use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

use tokio::{
    process::Command,
    time::{Duration, Instant, sleep},
};

use crate::{
    error::Error,
    password::prompt_password_once,
    ping::{ping_target_once, ping_targets},
    profile::{
        FileCleanup, Profile, ensure_default_profile_exists, parse_file_mode, resolve_profile_path,
    },
    secure_store::{clear_password, load_password as load_secure_password, store_password},
    vault::{VaultValue, load_vault_with_password},
};

const DEFAULT_PASS_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TMPDIR",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSH_AUTH_SOCK",
    "DOCKER_CONFIG",
];

#[derive(Debug)]
struct LoadedProfileEnv {
    envs: BTreeMap<String, String>,
    mounted_files: Vec<MountedFile>,
}

#[derive(Debug)]
struct MountedFile {
    path: PathBuf,
    created_dirs: Vec<PathBuf>,
    cleanup: FileCleanup,
}

pub async fn run_profile(profile_path: &Path) -> Result<(), Error> {
    run_profile_with_secure_store_key(profile_path, profile_path).await
}

pub async fn run_profile_with_secure_store_key(
    profile_path: &Path,
    secure_store_key: &Path,
) -> Result<(), Error> {
    ensure_default_profile_exists(profile_path)?;
    let profile_path = resolve_profile_path(profile_path);
    let profile = Profile::from_path(&profile_path)?;
    let envs = load_profile_env_prompt(&profile, &profile_path, secure_store_key)?;
    run_profile_with_loaded_env(&profile, envs).await
}

async fn run_profile_with_loaded_env(
    profile: &Profile,
    loaded: LoadedProfileEnv,
) -> Result<(), Error> {
    let LoadedProfileEnv {
        envs,
        mounted_files,
    } = loaded;
    let mut child = spawn_profile_command(profile, envs)?;

    let run_result = async {
        if !profile.pings.is_empty() {
            wait_for_pings(&mut child, &profile.pings).await?;
        }

        let status = child
            .wait()
            .await
            .map_err(|err| Error::CommandFailed(err.to_string()))?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::CommandFailed(status.to_string()))
        }
    }
    .await;

    if run_result.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    cleanup_mounted_files(mounted_files);
    run_result
}

fn spawn_profile_command(
    profile: &Profile,
    envs: BTreeMap<String, String>,
) -> Result<tokio::process::Child, Error> {
    let mut command = Command::new(&profile.run.cmd[0]);
    command.args(&profile.run.cmd[1..]);
    command.current_dir(resolve_workdir(profile));
    command.stdin(std::process::Stdio::inherit());
    command.stdout(std::process::Stdio::inherit());
    command.stderr(std::process::Stdio::inherit());

    if profile.run.clear_env {
        command.env_clear();
        for key in default_pass_env_keys(&profile.run.pass_env) {
            if let Ok(value) = env::var(&key) {
                command.env(&key, value);
            }
        }
    }

    for (key, value) in envs {
        command.env(key, value);
    }

    command
        .spawn()
        .map_err(|err| Error::CommandFailed(err.to_string()))
}

pub async fn ping_profile(profile_path: &Path) -> Result<(), Error> {
    ensure_default_profile_exists(profile_path)?;
    let profile_path = resolve_profile_path(profile_path);
    let profile = Profile::from_path(&profile_path)?;
    ping_targets(&profile.pings).await
}

fn load_profile_env_prompt(
    profile: &Profile,
    profile_path: &Path,
    secure_store_key: &Path,
) -> Result<LoadedProfileEnv, Error> {
    if let Some(password) = load_secure_password(secure_store_key)? {
        match load_profile_env_with_password(profile, profile_path, password.clone()) {
            Ok(loaded) => {
                store_password(secure_store_key, &password)?;
                return Ok(loaded);
            }
            Err(Error::Decryption(_)) => {
                clear_password(secure_store_key)?;
            }
            Err(err) => return Err(err),
        }
    }

    let password = prompt_password_once()?;
    let loaded = load_profile_env_with_password(profile, profile_path, password.clone())?;
    store_password(secure_store_key, &password)?;
    Ok(loaded)
}

fn load_profile_env_with_password(
    profile: &Profile,
    profile_path: &Path,
    password: age::secrecy::SecretString,
) -> Result<LoadedProfileEnv, Error> {
    let vault = load_vault_with_password(profile, profile_path, password)?;
    materialize_loaded_env(profile, vault.into_entries())
}

fn materialize_loaded_env(
    profile: &Profile,
    values: BTreeMap<String, VaultValue>,
) -> Result<LoadedProfileEnv, Error> {
    let workdir = resolve_workdir(profile);
    let mut envs = BTreeMap::new();
    let mut mounted_files = Vec::new();

    for (key, value) in values {
        match value {
            VaultValue::PlainText(value) => {
                envs.insert(key, value);
            }
            VaultValue::FileContent {
                path: legacy_path,
                content,
                mode: legacy_mode,
                cleanup: legacy_cleanup,
            } => {
                let (path, mode, cleanup) = if let Some(spec) = profile.file_spec(&key) {
                    (
                        spec.target_path.clone(),
                        parse_file_mode(&spec.mode)?,
                        spec.cleanup,
                    )
                } else {
                    (legacy_path, legacy_mode, legacy_cleanup)
                };
                let display_path = path.to_string_lossy().to_string();
                let resolved_path = if path.is_absolute() {
                    path.clone()
                } else {
                    workdir.join(&path)
                };
                let mount = write_runtime_file(&resolved_path, &content, mode, cleanup)?;
                envs.insert(key, display_path);
                mounted_files.push(mount);
            }
        }
    }

    Ok(LoadedProfileEnv {
        envs,
        mounted_files,
    })
}

fn write_runtime_file(
    path: &Path,
    content: &[u8],
    mode: u32,
    cleanup: FileCleanup,
) -> Result<MountedFile, Error> {
    if path.exists() {
        return Err(Error::RuntimeFilePathExists(path.to_path_buf()));
    }

    let mut created_dirs = Vec::new();
    if let Some(parent) = path.parent() {
        let mut missing = Vec::new();
        let mut current = Some(parent);
        while let Some(dir) = current {
            if dir.exists() {
                break;
            }
            missing.push(dir.to_path_buf());
            current = dir.parent();
        }
        for dir in missing.iter().rev() {
            fs::create_dir(dir).map_err(|source| Error::WriteFile {
                path: dir.clone(),
                source,
            })?;
            created_dirs.push(dir.clone());
        }
    }

    fs::write(path, content).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }

    Ok(MountedFile {
        path: path.to_path_buf(),
        created_dirs,
        cleanup,
    })
}

fn cleanup_mounted_files(mounted_files: Vec<MountedFile>) {
    for mounted_file in mounted_files {
        if mounted_file.cleanup == FileCleanup::Keep {
            continue;
        }
        let _ = fs::remove_file(&mounted_file.path);
        for dir in mounted_file.created_dirs.into_iter().rev() {
            match fs::remove_dir(&dir) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) if err.kind() == std::io::ErrorKind::DirectoryNotEmpty => break,
                Err(_) => break,
            }
        }
    }
}

fn resolve_workdir(profile: &Profile) -> PathBuf {
    profile
        .workdir
        .clone()
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf()))
}

fn default_pass_env_keys(profile_pass_env: &[String]) -> Vec<String> {
    let mut keys = DEFAULT_PASS_ENV
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    for key in profile_pass_env {
        if !keys.iter().any(|existing| existing == key) {
            keys.push(key.clone());
        }
    }
    keys
}

async fn wait_for_pings(
    child: &mut tokio::process::Child,
    targets: &[crate::profile::PingTarget],
) -> Result<(), Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| Error::HttpPing(err.to_string()))?;

    for target in targets {
        let deadline = Instant::now() + Duration::from_secs(target.timeout_seconds);
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => return Err(Error::ChildExitedEarly),
                Ok(None) => {}
                Err(err) => return Err(Error::CommandFailed(err.to_string())),
            }

            match ping_target_once(&client, target).await {
                Ok(()) => break,
                Err(err) => {
                    if Instant::now() >= deadline {
                        return Err(err);
                    }
                    sleep(Duration::from_millis(target.interval_millis)).await;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        LoadedProfileEnv, cleanup_mounted_files, default_pass_env_keys,
        load_profile_env_with_password, materialize_loaded_env, run_profile_with_loaded_env,
        wait_for_pings,
    };
    use crate::{
        error::Error,
        profile::{FileCleanup, FileSpec, PingTarget, Profile, RunConfig},
        vault::{VaultDocument, VaultValue, save_vault_with_password},
    };
    use age::secrecy::SecretString;
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::TcpListener,
        path::PathBuf,
        thread,
    };
    use tempfile::tempdir;
    use tokio::process::Command;

    fn test_profile(workdir: PathBuf) -> Profile {
        Profile {
            name: "test".to_string(),
            env_file: PathBuf::from("secret.env.enc"),
            workdir: Some(workdir),
            files: BTreeMap::new(),
            run: RunConfig {
                cmd: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "exit 0".to_string(),
                ],
                clear_env: true,
                pass_env: vec![],
            },
            pings: vec![],
            implicit_workdir: false,
        }
    }

    #[test]
    fn load_profile_env_with_password_reads_and_parses_encrypted_env() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("profile.yaml");
        std::fs::write(
            &profile_path,
            r#"
name: local
env_file: secret.env.enc
run:
  cmd: ["/bin/sh", "-c", "exit 0"]
"#,
        )
        .unwrap();

        let profile = Profile::from_path(&profile_path).unwrap();
        let mut vault = VaultDocument::default();
        vault
            .set_plain_text("API_URL", "https://example.com".to_string())
            .unwrap();
        vault
            .set_plain_text("GREETING", "hello world".to_string())
            .unwrap();
        save_vault_with_password(
            &profile,
            &profile_path,
            &vault,
            SecretString::from("test-password".to_string()),
        )
        .unwrap();

        let loaded = load_profile_env_with_password(
            &profile,
            &profile_path,
            SecretString::from("test-password".to_string()),
        )
        .unwrap();

        assert_eq!(loaded.envs.get("API_URL").unwrap(), "https://example.com");
        assert_eq!(loaded.envs.get("GREETING").unwrap(), "hello world");
        assert!(loaded.mounted_files.is_empty());
    }

    #[test]
    fn load_profile_env_with_password_rejects_wrong_password() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("profile.yaml");
        std::fs::write(
            &profile_path,
            r#"
name: local
env_file: secret.env.enc
run:
  cmd: ["/bin/sh", "-c", "exit 0"]
"#,
        )
        .unwrap();

        let profile = Profile::from_path(&profile_path).unwrap();
        let mut vault = VaultDocument::default();
        vault
            .set_plain_text("API_URL", "https://example.com".to_string())
            .unwrap();
        save_vault_with_password(
            &profile,
            &profile_path,
            &vault,
            SecretString::from("test-password".to_string()),
        )
        .unwrap();

        let err = load_profile_env_with_password(
            &profile,
            &profile_path,
            SecretString::from("wrong".to_string()),
        )
        .unwrap_err();

        assert!(matches!(err, Error::Decryption(_)));
    }

    #[test]
    fn default_pass_env_keys_deduplicates_requested_keys() {
        let keys = default_pass_env_keys(&["PATH".to_string(), "CARGO_HOME".to_string()]);
        assert_eq!(keys.iter().filter(|value| *value == "PATH").count(), 1);
        assert!(keys.iter().any(|value| value == "CARGO_HOME"));
    }

    #[tokio::test]
    async fn run_profile_with_loaded_env_injects_env_into_command() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("captured.txt");
        let mut profile = test_profile(dir.path().to_path_buf());
        profile.run.cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf '%s' \"$RUNVAULT_SECRET\" > captured.txt".to_string(),
        ];

        let mut envs = BTreeMap::new();
        envs.insert("RUNVAULT_SECRET".to_string(), "expected-value".to_string());
        run_profile_with_loaded_env(
            &profile,
            LoadedProfileEnv {
                envs,
                mounted_files: vec![],
            },
        )
        .await
        .unwrap();

        assert_eq!(std::fs::read_to_string(output).unwrap(), "expected-value");
    }

    #[tokio::test]
    async fn run_profile_with_loaded_env_materializes_and_cleans_up_file_backed_values() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("captured.txt");
        let runtime_secret = dir.path().join("runtime").join("gcp.json");
        let mut profile = test_profile(dir.path().to_path_buf());
        profile.run.cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            r#"printf '%s|' "$GOOGLE_APPLICATION_CREDENTIALS" > captured.txt && cat "$GOOGLE_APPLICATION_CREDENTIALS" >> captured.txt"#
                .to_string(),
        ];

        let mut values = BTreeMap::new();
        values.insert(
            "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
            VaultValue::FileContent {
                path: PathBuf::from("runtime/gcp.json"),
                content: br#"{"project":"demo"}"#.to_vec(),
                mode: 0o600,
                cleanup: FileCleanup::OnExit,
            },
        );

        let loaded = materialize_loaded_env(&profile, values).unwrap();
        assert!(runtime_secret.exists());

        run_profile_with_loaded_env(&profile, loaded).await.unwrap();

        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            format!("runtime/gcp.json|{}", r#"{"project":"demo"}"#)
        );
        assert!(!runtime_secret.exists());
        assert!(!runtime_secret.parent().unwrap().exists());
    }

    #[test]
    fn materialize_loaded_env_creates_missing_parent_directories() {
        let dir = tempdir().unwrap();
        let runtime_secret = dir
            .path()
            .join("nested")
            .join("tls")
            .join("client")
            .join("cert.pem");
        let profile = test_profile(dir.path().to_path_buf());

        let mut values = BTreeMap::new();
        values.insert(
            "SERVICE_CRT".to_string(),
            VaultValue::FileContent {
                path: PathBuf::from("nested/tls/client/cert.pem"),
                content: b"certificate".to_vec(),
                mode: 0o644,
                cleanup: FileCleanup::OnExit,
            },
        );

        let loaded = materialize_loaded_env(&profile, values).unwrap();
        assert!(runtime_secret.exists());
        assert_eq!(
            std::fs::read_to_string(&runtime_secret).unwrap(),
            "certificate"
        );
        assert!(runtime_secret.parent().unwrap().exists());

        cleanup_mounted_files(loaded.mounted_files);
        assert!(!runtime_secret.exists());
        assert!(!runtime_secret.parent().unwrap().exists());
    }

    #[tokio::test]
    async fn profile_file_specs_override_legacy_file_metadata() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("captured.txt");
        let runtime_secret = dir.path().join("pki").join("root.crt.pem");
        let mut profile = test_profile(dir.path().to_path_buf());
        profile.files.insert(
            "POSTGRES_TLS_CA_FILE".to_string(),
            FileSpec {
                target_path: PathBuf::from("pki/root.crt.pem"),
                mode: "0644".to_string(),
                cleanup: FileCleanup::Keep,
            },
        );
        profile.run.cmd = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            r#"printf '%s|' "$POSTGRES_TLS_CA_FILE" > captured.txt && cat "$POSTGRES_TLS_CA_FILE" >> captured.txt"#.to_string(),
        ];

        let mut values = BTreeMap::new();
        values.insert(
            "POSTGRES_TLS_CA_FILE".to_string(),
            VaultValue::FileContent {
                path: PathBuf::from("legacy/ignored.pem"),
                content: b"root-ca".to_vec(),
                mode: 0o600,
                cleanup: FileCleanup::OnExit,
            },
        );

        let loaded = materialize_loaded_env(&profile, values).unwrap();
        assert!(runtime_secret.exists());
        run_profile_with_loaded_env(&profile, loaded).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            "pki/root.crt.pem|root-ca"
        );
        assert!(runtime_secret.exists());
    }

    #[test]
    fn cleanup_mounted_files_keeps_file_when_requested() {
        let dir = tempdir().unwrap();
        let runtime_secret = dir.path().join("runtime").join("tls.key");
        let profile = test_profile(dir.path().to_path_buf());
        let mut values = BTreeMap::new();
        values.insert(
            "TLS_KEY_FILE".to_string(),
            VaultValue::FileContent {
                path: PathBuf::from("runtime/tls.key"),
                content: b"secret-key".to_vec(),
                mode: 0o600,
                cleanup: FileCleanup::Keep,
            },
        );

        let loaded = materialize_loaded_env(&profile, values).unwrap();
        assert!(runtime_secret.exists());
        cleanup_mounted_files(loaded.mounted_files);
        assert!(runtime_secret.exists());
    }

    #[tokio::test]
    async fn wait_for_pings_detects_early_child_exit() {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .unwrap();

        let targets = vec![PingTarget {
            name: "api".to_string(),
            url: "http://127.0.0.1:9/health".to_string(),
            timeout_seconds: 1,
            interval_millis: 25,
        }];

        let err = wait_for_pings(&mut child, &targets).await.unwrap_err();
        assert!(matches!(err, Error::ChildExitedEarly));
    }

    #[tokio::test]
    async fn wait_for_pings_succeeds_when_service_becomes_ready() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                );
            }
        });

        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 2")
            .spawn()
            .unwrap();

        let targets = vec![PingTarget {
            name: "api".to_string(),
            url: format!("http://{}/health", addr),
            timeout_seconds: 2,
            interval_millis: 50,
        }];

        wait_for_pings(&mut child, &targets).await.unwrap();
        let _ = child.kill().await;
        let _ = child.wait().await;
        server.join().unwrap();
    }
}

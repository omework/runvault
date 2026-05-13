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
    crypto::maybe_decrypt_file_payload,
    error::Error,
    password::prompt_password_once,
    ping::{ping_target_once, ping_targets},
    profile::{
        FileCleanup, Profile, ensure_default_profile_exists, parse_file_mode, resolve_profile_path,
        resolve_source_path,
    },
    secure_store::{
        clear_password, load_password as load_secure_password, store_password_if_possible,
    },
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

#[derive(Debug, Clone, Copy)]
struct RuntimeWriteContext<'a> {
    kind: &'a str,
    name: &'a str,
}

pub async fn run_profile(profile_path: &Path) -> Result<(), Error> {
    let execution_dir = env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
    run_profile_with_secure_store_key_in_dir(profile_path, profile_path, &execution_dir).await
}

pub async fn run_profile_with_secure_store_key(
    profile_path: &Path,
    secure_store_key: &Path,
) -> Result<(), Error> {
    let execution_dir = env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
    run_profile_with_secure_store_key_in_dir(profile_path, secure_store_key, &execution_dir).await
}

pub async fn run_profile_with_secure_store_key_in_dir(
    profile_path: &Path,
    secure_store_key: &Path,
    execution_dir: &Path,
) -> Result<(), Error> {
    ensure_default_profile_exists(profile_path)?;
    let profile_path = resolve_profile_path(profile_path);
    let profile = Profile::from_path(&profile_path)?;
    let envs = load_profile_env_prompt(&profile, &profile_path, secure_store_key, execution_dir)?;
    run_profile_with_loaded_env(&profile, envs, execution_dir).await
}

async fn run_profile_with_loaded_env(
    profile: &Profile,
    loaded: LoadedProfileEnv,
    execution_dir: &Path,
) -> Result<(), Error> {
    let LoadedProfileEnv {
        envs,
        mounted_files,
    } = loaded;
    let mut child = spawn_profile_command(profile, envs, execution_dir)?;

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
    execution_dir: &Path,
) -> Result<tokio::process::Child, Error> {
    let mut command = Command::new(&profile.run.cmd[0]);
    command.args(&profile.run.cmd[1..]);
    command.current_dir(resolve_workdir(profile, execution_dir));
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
    execution_dir: &Path,
) -> Result<LoadedProfileEnv, Error> {
    if let Some(password) = load_secure_password(&secure_store_key)? {
        match load_profile_env_with_password(profile, profile_path, password.clone(), execution_dir)
        {
            Ok(loaded) => {
                store_password_if_possible(&secure_store_key, &password)?;
                return Ok(loaded);
            }
            Err(Error::Decryption(_)) => {
                clear_password(&secure_store_key)?;
            }
            Err(err) => return Err(err),
        }
    }

    let password = prompt_password_once()?;
    let loaded =
        load_profile_env_with_password(profile, profile_path, password.clone(), execution_dir)?;
    store_password_if_possible(&secure_store_key, &password)?;
    Ok(loaded)
}

fn load_profile_env_with_password(
    profile: &Profile,
    profile_path: &Path,
    password: age::secrecy::SecretString,
    execution_dir: &Path,
) -> Result<LoadedProfileEnv, Error> {
    let vault = load_vault_with_password(profile, profile_path, password.clone())?;
    materialize_loaded_env(
        profile_path,
        profile,
        vault.into_entries(),
        password,
        execution_dir,
    )
}

fn materialize_loaded_env(
    profile_path: &Path,
    profile: &Profile,
    values: BTreeMap<String, VaultValue>,
    password: age::secrecy::SecretString,
    execution_dir: &Path,
) -> Result<LoadedProfileEnv, Error> {
    let workdir = resolve_workdir(profile, execution_dir);
    let mut envs = BTreeMap::new();
    let mut mounted_files = materialize_profile_assets(profile_path, profile, &workdir, &password)?;

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
                let mount = write_runtime_file(
                    &resolved_path,
                    &content,
                    mode,
                    cleanup,
                    Some(RuntimeWriteContext {
                        kind: "file-backed value",
                        name: &key,
                    }),
                )?;
                envs.insert(key, display_path);
                mounted_files.push(mount);
            }
            VaultValue::SealedVisible(_) => {
                return Err(Error::VaultFormat(format!(
                    "key '{key}' was not materialized before runtime"
                )));
            }
        }
    }

    Ok(LoadedProfileEnv {
        envs,
        mounted_files,
    })
}

fn materialize_profile_assets(
    profile_path: &Path,
    profile: &Profile,
    workdir: &Path,
    password: &age::secrecy::SecretString,
) -> Result<Vec<MountedFile>, Error> {
    let profile_dir = if profile_path.is_dir() {
        profile_path
    } else {
        profile_path.parent().unwrap_or_else(|| Path::new("."))
    };
    let mut mounted_files = Vec::new();

    for (key, spec) in profile.assets() {
        let resolved_source_path = resolve_source_path(&spec.source_path, profile_dir)?;
        let raw_content = fs::read(&resolved_source_path).map_err(|source| Error::ReadFile {
            path: resolved_source_path,
            source,
        })?;
        let content = maybe_decrypt_file_payload(&raw_content, password.clone())?;
        let resolved_target_path = if spec.target_path.is_absolute() {
            spec.target_path.clone()
        } else {
            workdir.join(&spec.target_path)
        };
        let mount = write_runtime_file(
            &resolved_target_path,
            &content,
            parse_file_mode(&spec.mode)?,
            spec.cleanup,
            Some(RuntimeWriteContext {
                kind: "resource",
                name: key,
            }),
        )?;
        mounted_files.push(mount);
    }

    Ok(mounted_files)
}

fn write_runtime_file(
    path: &Path,
    content: &[u8],
    mode: u32,
    cleanup: FileCleanup,
    context: Option<RuntimeWriteContext<'_>>,
) -> Result<MountedFile, Error> {
    if path.exists() {
        let metadata = fs::metadata(path).map_err(|source| {
            runtime_materialization_error(
                context,
                path,
                "inspect existing runtime file".to_string(),
                path.to_path_buf(),
                source,
            )
        })?;
        if !metadata.is_file() {
            return Err(Error::RuntimeFilePathExists(path.to_path_buf()));
        }

        let existing = fs::read(path).map_err(|source| {
            runtime_materialization_error(
                context,
                path,
                "read existing runtime file".to_string(),
                path.to_path_buf(),
                source,
            )
        })?;
        if existing == content {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
            }
            return Ok(MountedFile {
                path: path.to_path_buf(),
                created_dirs: Vec::new(),
                cleanup,
            });
        }

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
            fs::create_dir(dir).map_err(|source| {
                runtime_materialization_error(
                    context,
                    path,
                    format!("create parent directory {}", dir.display()),
                    dir.clone(),
                    source,
                )
            })?;
            created_dirs.push(dir.clone());
        }
    }

    fs::write(path, content).map_err(|source| {
        runtime_materialization_error(
            context,
            path,
            "write file contents".to_string(),
            path.to_path_buf(),
            source,
        )
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

fn runtime_materialization_error(
    context: Option<RuntimeWriteContext<'_>>,
    target_path: &Path,
    operation: String,
    path: PathBuf,
    source: std::io::Error,
) -> Error {
    if let Some(context) = context {
        Error::RuntimeMaterialization {
            kind: context.kind.to_string(),
            name: context.name.to_string(),
            target_path: target_path.to_path_buf(),
            operation,
            source,
        }
    } else {
        Error::WriteFile { path, source }
    }
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

fn resolve_workdir(profile: &Profile, execution_dir: &Path) -> PathBuf {
    match &profile.workdir {
        Some(workdir) if workdir.is_absolute() => workdir.clone(),
        Some(workdir) => execution_dir.join(workdir),
        None => execution_dir.to_path_buf(),
    }
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
        profile::{AssetSpec, FileCleanup, FileSpec, PingTarget, Profile, RunConfig},
        vault::{VaultDocument, VaultValue, save_vault_with_password},
    };
    use age::secrecy::{ExposeSecret, SecretString};
    use openssl::{pkey::PKey, rsa::Rsa, symm::Cipher};
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
            assets: BTreeMap::new(),
            resources: BTreeMap::new(),
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

    fn test_password() -> SecretString {
        SecretString::from("password".to_string())
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
            dir.path(),
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
            dir.path(),
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
            dir.path(),
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

        let loaded =
            materialize_loaded_env(dir.path(), &profile, values, test_password(), dir.path())
                .unwrap();
        assert!(runtime_secret.exists());

        run_profile_with_loaded_env(&profile, loaded, dir.path())
            .await
            .unwrap();

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

        let loaded =
            materialize_loaded_env(dir.path(), &profile, values, test_password(), dir.path())
                .unwrap();
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

    #[test]
    fn materialize_loaded_env_reports_key_and_target_path_on_runtime_write_failure() {
        let dir = tempdir().unwrap();
        let blocking_parent = dir.path().join("blocked");
        std::fs::write(&blocking_parent, "not a directory").unwrap();
        let profile = test_profile(dir.path().to_path_buf());

        let mut values = BTreeMap::new();
        values.insert(
            "SERVICE_TLS_KEY".to_string(),
            VaultValue::FileContent {
                path: PathBuf::from("blocked/server.key"),
                content: b"key".to_vec(),
                mode: 0o600,
                cleanup: FileCleanup::OnExit,
            },
        );

        let err = materialize_loaded_env(dir.path(), &profile, values, test_password(), dir.path())
            .unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, Error::RuntimeMaterialization { .. }));
        assert!(message.contains("file-backed value 'SERVICE_TLS_KEY'"));
        assert!(message.contains("blocked/server.key"));
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

        let loaded =
            materialize_loaded_env(dir.path(), &profile, values, test_password(), dir.path())
                .unwrap();
        assert!(runtime_secret.exists());
        run_profile_with_loaded_env(&profile, loaded, dir.path())
            .await
            .unwrap();
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

        let loaded =
            materialize_loaded_env(dir.path(), &profile, values, test_password(), dir.path())
                .unwrap();
        assert!(runtime_secret.exists());
        cleanup_mounted_files(loaded.mounted_files);
        assert!(runtime_secret.exists());
    }

    #[test]
    fn materialize_loaded_env_reuses_existing_runtime_file_with_identical_content() {
        let dir = tempdir().unwrap();
        let runtime_secret = dir.path().join("pki").join("root.chain.pem");
        std::fs::create_dir_all(runtime_secret.parent().unwrap()).unwrap();
        std::fs::write(&runtime_secret, "root-ca").unwrap();
        let profile = test_profile(dir.path().to_path_buf());

        let mut values = BTreeMap::new();
        values.insert(
            "POSTGRES_SERVER_CA_CRT".to_string(),
            VaultValue::FileContent {
                path: PathBuf::from("./pki/root.chain.pem"),
                content: b"root-ca".to_vec(),
                mode: 0o644,
                cleanup: FileCleanup::Keep,
            },
        );

        let loaded =
            materialize_loaded_env(dir.path(), &profile, values, test_password(), dir.path())
                .unwrap();
        assert_eq!(std::fs::read_to_string(&runtime_secret).unwrap(), "root-ca");
        cleanup_mounted_files(loaded.mounted_files);
        assert!(runtime_secret.exists());
    }

    #[test]
    fn materialize_loaded_env_rejects_existing_runtime_file_with_different_content() {
        let dir = tempdir().unwrap();
        let runtime_secret = dir.path().join("pki").join("root.chain.pem");
        std::fs::create_dir_all(runtime_secret.parent().unwrap()).unwrap();
        std::fs::write(&runtime_secret, "old-root-ca").unwrap();
        let profile = test_profile(dir.path().to_path_buf());

        let mut values = BTreeMap::new();
        values.insert(
            "POSTGRES_SERVER_CA_CRT".to_string(),
            VaultValue::FileContent {
                path: PathBuf::from("./pki/root.chain.pem"),
                content: b"new-root-ca".to_vec(),
                mode: 0o644,
                cleanup: FileCleanup::Keep,
            },
        );

        let err = materialize_loaded_env(dir.path(), &profile, values, test_password(), dir.path())
            .unwrap_err();
        assert!(matches!(err, Error::RuntimeFilePathExists(_)));
        assert_eq!(
            std::fs::read_to_string(&runtime_secret).unwrap(),
            "old-root-ca"
        );
    }

    #[test]
    fn materialize_loaded_env_materializes_profile_assets() {
        let dir = tempdir().unwrap();
        let asset_source = dir.path().join("docker-compose.yml");
        let runtime_compose = dir.path().join("runtime").join("docker-compose.yml");
        std::fs::write(&asset_source, "services: {}\n").unwrap();

        let mut profile = test_profile(dir.path().join("runtime"));
        profile.assets.insert(
            "BUNDLED_DOCKER_COMPOSE_FILE".to_string(),
            AssetSpec {
                source_path: PathBuf::from("./docker-compose.yml"),
                target_path: PathBuf::from("./docker-compose.yml"),
                mode: "0644".to_string(),
                cleanup: FileCleanup::Keep,
            },
        );

        let loaded = materialize_loaded_env(
            dir.path(),
            &profile,
            BTreeMap::new(),
            test_password(),
            dir.path(),
        )
        .unwrap();
        assert!(runtime_compose.exists());
        assert_eq!(
            std::fs::read_to_string(&runtime_compose).unwrap(),
            "services: {}\n"
        );
        cleanup_mounted_files(loaded.mounted_files);
        assert!(runtime_compose.exists());
    }

    #[test]
    fn materialize_loaded_env_decrypts_encrypted_profile_assets() {
        let dir = tempdir().unwrap();
        let asset_source = dir.path().join("server.key.pem");
        let runtime_key = dir.path().join("runtime").join("server.key.pem");
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let encrypted = key
            .private_key_to_pem_pkcs8_passphrase(
                Cipher::aes_256_cbc(),
                test_password().expose_secret().as_bytes(),
            )
            .unwrap();
        std::fs::write(&asset_source, encrypted).unwrap();

        let mut profile = test_profile(dir.path().join("runtime"));
        profile.assets.insert(
            "SERVER_KEY".to_string(),
            AssetSpec {
                source_path: PathBuf::from("./server.key.pem"),
                target_path: PathBuf::from("./server.key.pem"),
                mode: "0600".to_string(),
                cleanup: FileCleanup::Keep,
            },
        );

        let loaded = materialize_loaded_env(
            dir.path(),
            &profile,
            BTreeMap::new(),
            test_password(),
            dir.path(),
        )
        .unwrap();
        assert!(
            std::fs::read_to_string(&runtime_key)
                .unwrap()
                .contains("BEGIN PRIVATE KEY")
        );
        cleanup_mounted_files(loaded.mounted_files);
        assert!(runtime_key.exists());
    }

    #[test]
    fn implicit_workdir_materializes_runtime_targets_under_execution_dir() {
        let dir = tempdir().unwrap();
        let current = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let profile_dir = dir.path().join(".vault");
        std::fs::create_dir_all(&profile_dir).unwrap();
        let profile_path = profile_dir.join("runvault.yaml");
        std::fs::write(
            &profile_path,
            r#"
name: local
env_file: env.sec
run:
  cmd: ["/bin/sh", "-c", "exit 0"]
"#,
        )
        .unwrap();

        let profile = Profile::from_path(&profile_path).unwrap();
        let mut values = BTreeMap::new();
        values.insert(
            "CADDY_CONFIG_FILE".to_string(),
            VaultValue::FileContent {
                path: PathBuf::from("./caddy/Caddyfile"),
                content: b"example".to_vec(),
                mode: 0o644,
                cleanup: FileCleanup::OnExit,
            },
        );

        let loaded =
            materialize_loaded_env(&profile_path, &profile, values, test_password(), dir.path())
                .unwrap();
        assert!(dir.path().join("caddy/Caddyfile").exists());
        assert!(!profile_dir.join("caddy/Caddyfile").exists());

        cleanup_mounted_files(loaded.mounted_files);
        std::env::set_current_dir(current).unwrap();
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

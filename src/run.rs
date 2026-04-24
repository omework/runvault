use std::{collections::BTreeMap, env, path::Path};

use tokio::{
    process::Command,
    time::{Duration, Instant, sleep},
};

use crate::{
    crypto::decrypt_env,
    envfile::parse_env_bytes,
    error::Error,
    password::prompt_password_once,
    ping::{ping_target_once, ping_targets},
    profile::Profile,
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

pub async fn run_profile(profile_path: &Path) -> Result<(), Error> {
    let profile = Profile::from_path(profile_path)?;
    let envs = load_profile_env_prompt(&profile, profile_path)?;
    run_profile_with_env_map(&profile, envs).await
}

async fn run_profile_with_env_map(
    profile: &Profile,
    envs: BTreeMap<String, String>,
) -> Result<(), Error> {
    let mut child = spawn_profile_command(profile, envs)?;

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

fn spawn_profile_command(
    profile: &Profile,
    envs: BTreeMap<String, String>,
) -> Result<tokio::process::Child, Error> {
    let mut command = Command::new(&profile.run.cmd[0]);
    command.args(&profile.run.cmd[1..]);
    command.current_dir(
        profile
            .workdir
            .clone()
            .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf())),
    );
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
    let profile = Profile::from_path(profile_path)?;
    ping_targets(&profile.pings).await
}

fn load_profile_env_prompt(
    profile: &Profile,
    profile_path: &Path,
) -> Result<BTreeMap<String, String>, Error> {
    let password = prompt_password_once()?;
    load_profile_env_with_password(profile, profile_path, password)
}

fn load_profile_env_with_password(
    profile: &Profile,
    profile_path: &Path,
    password: age::secrecy::SecretString,
) -> Result<BTreeMap<String, String>, Error> {
    let env_path = profile.resolve_env_path(profile_path);
    let ciphertext = std::fs::read(&env_path).map_err(|source| Error::ReadFile {
        path: env_path.clone(),
        source,
    })?;
    let plaintext = decrypt_env(&ciphertext, password)?;
    parse_env_bytes(&plaintext)
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
        default_pass_env_keys, load_profile_env_with_password, run_profile_with_env_map,
        wait_for_pings,
    };
    use crate::{
        crypto::encrypt_env,
        error::Error,
        profile::{PingTarget, Profile, RunConfig},
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
        }
    }

    #[test]
    fn load_profile_env_with_password_reads_and_parses_encrypted_env() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("profile.yaml");
        let env_path = dir.path().join("secret.env.enc");
        let encrypted = encrypt_env(
            b"API_URL=https://example.com\nGREETING=\"hello world\"\n",
            SecretString::from("test-password".to_string()),
        )
        .unwrap();
        std::fs::write(&env_path, encrypted).unwrap();
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
        let envs = load_profile_env_with_password(
            &profile,
            &profile_path,
            SecretString::from("test-password".to_string()),
        )
        .unwrap();

        assert_eq!(envs.get("API_URL").unwrap(), "https://example.com");
        assert_eq!(envs.get("GREETING").unwrap(), "hello world");
    }

    #[test]
    fn load_profile_env_with_password_rejects_wrong_password() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("profile.yaml");
        let env_path = dir.path().join("secret.env.enc");
        let encrypted = encrypt_env(
            b"API_URL=https://example.com\n",
            SecretString::from("test-password".to_string()),
        )
        .unwrap();
        std::fs::write(&env_path, encrypted).unwrap();
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
    async fn run_profile_with_env_map_injects_env_into_command() {
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
        run_profile_with_env_map(&profile, envs).await.unwrap();

        assert_eq!(std::fs::read_to_string(output).unwrap(), "expected-value");
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
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        });

        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 1")
            .spawn()
            .unwrap();

        let targets = vec![PingTarget {
            name: "api".to_string(),
            url: format!("http://{}", addr),
            timeout_seconds: 1,
            interval_millis: 25,
        }];

        wait_for_pings(&mut child, &targets).await.unwrap();
        let _ = child.wait().await.unwrap();
        server.join().unwrap();
    }
}

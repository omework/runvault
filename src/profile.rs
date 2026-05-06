use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::error::Error;

pub const DEFAULT_PROFILE_FILE: &str = "runvault.yaml";
pub const DEFAULT_ENV_FILE: &str = "env.sec";

#[derive(Debug, Deserialize)]
pub struct Profile {
    pub name: String,
    #[serde(default = "default_env_file")]
    pub env_file: PathBuf,
    #[serde(default)]
    pub workdir: Option<PathBuf>,
    pub run: RunConfig,
    #[serde(default)]
    pub pings: Vec<PingTarget>,
}

#[derive(Debug, Deserialize)]
pub struct RunConfig {
    pub cmd: Vec<String>,
    #[serde(default = "default_clear_env")]
    pub clear_env: bool,
    #[serde(default)]
    pub pass_env: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PingTarget {
    pub name: String,
    pub url: String,
    #[serde(default = "default_ping_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_ping_interval_millis")]
    pub interval_millis: u64,
}

fn default_clear_env() -> bool {
    true
}

fn default_env_file() -> PathBuf {
    PathBuf::from(DEFAULT_ENV_FILE)
}

fn default_ping_timeout_seconds() -> u64 {
    30
}

fn default_ping_interval_millis() -> u64 {
    500
}

impl Profile {
    pub fn from_path(path: &Path) -> Result<Self, Error> {
        let content = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        let mut profile: Profile =
            serde_yaml::from_str(&content).map_err(|source| Error::ProfileParse {
                path: path.to_path_buf(),
                source,
            })?;
        profile.validate()?;
        if profile.workdir.is_none() {
            profile.workdir = path.parent().map(Path::to_path_buf);
        }
        Ok(profile)
    }

    pub fn resolve_env_path(&self, profile_path: &Path) -> PathBuf {
        if self.env_file.is_absolute() {
            return self.env_file.clone();
        }
        profile_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&self.env_file)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.name.trim().is_empty() {
            return Err(Error::InvalidProfile("name must not be empty".to_string()));
        }
        if self.run.cmd.is_empty() {
            return Err(Error::InvalidProfile(
                "run.cmd must include at least one command element".to_string(),
            ));
        }
        for ping in &self.pings {
            if ping.name.trim().is_empty() {
                return Err(Error::InvalidProfile(
                    "ping target name must not be empty".to_string(),
                ));
            }
            if ping.url.trim().is_empty() {
                return Err(Error::InvalidProfile(format!(
                    "ping target '{}' url must not be empty",
                    ping.name
                )));
            }
        }
        Ok(())
    }
}

pub fn resolve_profile_path(input: &Path) -> PathBuf {
    if input.is_dir() {
        input.join(DEFAULT_PROFILE_FILE)
    } else {
        input.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_ENV_FILE, DEFAULT_PROFILE_FILE, Profile, resolve_profile_path};
    use crate::error::Error;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn loads_profile_and_defaults_workdir_to_parent() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("local.yaml");
        std::fs::write(
            &profile_path,
            r#"
name: local
env_file: secrets.env.enc
run:
  cmd: ["cargo", "run"]
"#,
        )
        .unwrap();

        let profile = Profile::from_path(&profile_path).unwrap();
        assert_eq!(profile.name, "local");
        assert_eq!(profile.workdir.as_deref(), Some(dir.path()));
        assert_eq!(
            profile.resolve_env_path(&profile_path),
            dir.path().join("secrets.env.enc")
        );
        assert!(profile.run.clear_env);
    }

    #[test]
    fn defaults_env_file_to_env_sec_when_omitted() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join(DEFAULT_PROFILE_FILE);
        std::fs::write(
            &profile_path,
            r#"
name: local
run:
  cmd: ["cargo", "run"]
"#,
        )
        .unwrap();

        let profile = Profile::from_path(&profile_path).unwrap();
        assert_eq!(profile.env_file, PathBuf::from(DEFAULT_ENV_FILE));
        assert_eq!(
            profile.resolve_env_path(&profile_path),
            dir.path().join(DEFAULT_ENV_FILE)
        );
    }

    #[test]
    fn resolves_directory_input_to_default_profile_file() {
        let dir = tempdir().unwrap();
        assert_eq!(
            resolve_profile_path(dir.path()),
            dir.path().join(DEFAULT_PROFILE_FILE)
        );
    }

    #[test]
    fn rejects_empty_name() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("invalid.yaml");
        std::fs::write(
            &profile_path,
            r#"
name: "   "
env_file: secrets.env.enc
run:
  cmd: ["cargo", "run"]
"#,
        )
        .unwrap();

        let err = Profile::from_path(&profile_path).unwrap_err();
        assert!(matches!(err, Error::InvalidProfile(_)));
        assert!(err.to_string().contains("name must not be empty"));
    }

    #[test]
    fn rejects_empty_ping_url() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("invalid-ping.yaml");
        std::fs::write(
            &profile_path,
            r#"
name: local
env_file: secrets.env.enc
run:
  cmd: ["cargo", "run"]
pings:
  - name: api
    url: ""
"#,
        )
        .unwrap();

        let err = Profile::from_path(&profile_path).unwrap_err();
        assert!(matches!(err, Error::InvalidProfile(_)));
        assert!(err.to_string().contains("url must not be empty"));
    }
}

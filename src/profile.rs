use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::{envfile::validate_env_key, error::Error};

pub const DEFAULT_PROFILE_FILE: &str = "runvault.yaml";
pub const DEFAULT_ENV_FILE: &str = "env.sec";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FileCleanup {
    #[default]
    OnExit,
    Keep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSpec {
    pub target_path: PathBuf,
    #[serde(default = "default_file_mode")]
    pub mode: String,
    #[serde(default)]
    pub cleanup: FileCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileImportSpec {
    pub src: PathBuf,
    #[serde(
        default,
        rename = "to-file",
        alias = "to_file",
        alias = "target_path",
        skip_serializing_if = "Option::is_none"
    )]
    pub to_file: Option<PathBuf>,
    #[serde(default = "default_file_mode")]
    pub mode: String,
    #[serde(default)]
    pub cleanup: FileCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FileImportDocument {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, FileImportSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    #[serde(default = "default_env_file")]
    pub env_file: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, FileSpec>,
    pub run: RunConfig,
    #[serde(default)]
    pub pings: Vec<PingTarget>,
    #[serde(skip)]
    pub(crate) implicit_workdir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    pub cmd: Vec<String>,
    #[serde(default = "default_clear_env")]
    pub clear_env: bool,
    #[serde(default)]
    pub pass_env: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PingTarget {
    pub name: String,
    pub url: String,
    #[serde(default = "default_ping_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_ping_interval_millis")]
    pub interval_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateProfileOptions {
    pub name: Option<String>,
    pub env_file: PathBuf,
}

fn default_clear_env() -> bool {
    true
}

fn default_env_file() -> PathBuf {
    PathBuf::from(DEFAULT_ENV_FILE)
}

fn default_file_mode() -> String {
    "0600".to_string()
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
        profile.implicit_workdir = profile.workdir.is_none();
        profile.validate()?;
        if profile.implicit_workdir {
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

    pub fn file_spec(&self, key: &str) -> Option<&FileSpec> {
        self.files.get(key)
    }

    pub fn upsert_file_spec(&mut self, key: &str, spec: FileSpec) {
        self.files.insert(key.to_string(), spec);
    }

    pub fn remove_file_spec(&mut self, key: &str) {
        self.files.remove(key);
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
        for (key, spec) in &self.files {
            if !validate_env_key(key) {
                return Err(Error::InvalidProfile(format!(
                    "file spec key '{}' is not a valid env key",
                    key
                )));
            }
            if spec.target_path.as_os_str().is_empty() {
                return Err(Error::InvalidProfile(format!(
                    "file spec '{}' target_path must not be empty",
                    key
                )));
            }
            parse_file_mode(&spec.mode)?;
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

pub fn create_profile(path: &Path, options: &CreateProfileOptions) -> Result<PathBuf, Error> {
    let profile_dir = if path.extension().is_some_and(|value| value == "yaml") {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        path.to_path_buf()
    };

    std::fs::create_dir_all(&profile_dir).map_err(|source| Error::WriteFile {
        path: profile_dir.clone(),
        source,
    })?;

    let profile_path = profile_dir.join(DEFAULT_PROFILE_FILE);
    if profile_path.exists() {
        return Err(Error::AlreadyExists(profile_path));
    }

    let name = options
        .name
        .clone()
        .unwrap_or_else(|| infer_profile_name(&profile_dir));
    if name.trim().is_empty() {
        return Err(Error::InvalidProfile(
            "profile name must not be empty".to_string(),
        ));
    }

    let env_file = if options.env_file.as_os_str().is_empty() {
        PathBuf::from(DEFAULT_ENV_FILE)
    } else {
        options.env_file.clone()
    };

    let profile = Profile {
        name,
        env_file,
        workdir: None,
        files: BTreeMap::new(),
        run: RunConfig {
            cmd: vec![
                "echo".to_string(),
                "configure run.cmd in runvault.yaml".to_string(),
            ],
            clear_env: true,
            pass_env: Vec::new(),
        },
        pings: Vec::new(),
        implicit_workdir: true,
    };

    save_profile_to_path(&profile_path, &profile)?;

    Ok(profile_path)
}

fn infer_profile_name(dir: &Path) -> String {
    dir.file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("profile")
        .to_string()
}

pub fn save_profile_to_path(path: &Path, profile: &Profile) -> Result<(), Error> {
    let mut serializable = profile.clone();
    if serializable.implicit_workdir {
        serializable.workdir = None;
    }
    let yaml = serde_yaml::to_string(&serializable)
        .map_err(|source| Error::ProfileSerialize(source.to_string()))?;
    std::fs::write(path, yaml).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

pub fn parse_file_mode(value: &str) -> Result<u32, Error> {
    let trimmed = value.trim();
    u32::from_str_radix(trimmed, 8).map_err(|_| Error::InvalidFileMode {
        value: trimmed.to_string(),
    })
}

pub fn load_file_import_document(path: &Path) -> Result<FileImportDocument, Error> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut document: FileImportDocument =
        serde_yaml::from_str(&content).map_err(|source| Error::ImportSpecParse {
            path: path.to_path_buf(),
            source,
        })?;
    validate_file_import_document(&document)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    for spec in document.files.values_mut() {
        if spec.src.is_relative() {
            spec.src = base_dir.join(&spec.src);
        }
    }
    Ok(document)
}

fn validate_file_import_document(document: &FileImportDocument) -> Result<(), Error> {
    if document.files.is_empty() {
        return Err(Error::InvalidImportSpec(
            "files must contain at least one entry".to_string(),
        ));
    }
    for (key, spec) in &document.files {
        if !validate_env_key(key) {
            return Err(Error::InvalidImportSpec(format!(
                "file import key '{}' is not a valid env key",
                key
            )));
        }
        if spec.src.as_os_str().is_empty() {
            return Err(Error::InvalidImportSpec(format!(
                "file import '{}' src must not be empty",
                key
            )));
        }
        if let Some(path) = &spec.to_file {
            if path.as_os_str().is_empty() {
                return Err(Error::InvalidImportSpec(format!(
                    "file import '{}' to-file must not be empty",
                    key
                )));
            }
            parse_file_mode(&spec.mode)?;
        } else if spec.mode != default_file_mode() || spec.cleanup != FileCleanup::OnExit {
            return Err(Error::InvalidImportSpec(format!(
                "file import '{}' uses file options without to-file",
                key
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CreateProfileOptions, DEFAULT_ENV_FILE, DEFAULT_PROFILE_FILE, FileCleanup,
        FileImportDocument, FileSpec, Profile, create_profile, load_file_import_document,
        resolve_profile_path, save_profile_to_path,
    };
    use crate::error::Error;
    use std::{collections::BTreeMap, path::PathBuf};
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

    #[test]
    fn create_profile_bootstraps_folder_with_default_name() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("services");

        let created = create_profile(
            &target,
            &CreateProfileOptions {
                name: None,
                env_file: PathBuf::from(DEFAULT_ENV_FILE),
            },
        )
        .unwrap();

        assert_eq!(created, target.join(DEFAULT_PROFILE_FILE));
        let content = std::fs::read_to_string(created).unwrap();
        assert!(content.contains("name: services"));
        assert!(content.contains("env_file: env.sec"));
        assert!(content.contains("configure run.cmd in runvault.yaml"));
    }

    #[test]
    fn create_profile_rejects_existing_profile_file() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("services");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join(DEFAULT_PROFILE_FILE), "name: existing\n").unwrap();

        let err = create_profile(
            &target,
            &CreateProfileOptions {
                name: None,
                env_file: PathBuf::from(DEFAULT_ENV_FILE),
            },
        )
        .unwrap_err();

        assert!(matches!(err, Error::AlreadyExists(_)));
    }

    #[test]
    fn create_profile_uses_custom_name_and_env_file() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("workers");

        let created = create_profile(
            &target,
            &CreateProfileOptions {
                name: Some("ovh-workers".to_string()),
                env_file: PathBuf::from("secrets.sec"),
            },
        )
        .unwrap();

        let content = std::fs::read_to_string(created).unwrap();
        assert!(content.contains("name: ovh-workers"));
        assert!(content.contains("env_file: secrets.sec"));
    }

    #[test]
    fn save_profile_persists_file_specs() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join(DEFAULT_PROFILE_FILE);
        let mut profile = Profile {
            name: "local".to_string(),
            env_file: PathBuf::from(DEFAULT_ENV_FILE),
            workdir: Some(dir.path().to_path_buf()),
            files: BTreeMap::new(),
            run: super::RunConfig {
                cmd: vec!["echo".to_string(), "ok".to_string()],
                clear_env: true,
                pass_env: Vec::new(),
            },
            pings: Vec::new(),
            implicit_workdir: true,
        };
        profile.upsert_file_spec(
            "TLS_CA_FILE",
            FileSpec {
                target_path: PathBuf::from("/tmp/root.crt.pem"),
                mode: "0644".to_string(),
                cleanup: FileCleanup::Keep,
            },
        );

        save_profile_to_path(&profile_path, &profile).unwrap();
        let reloaded = Profile::from_path(&profile_path).unwrap();
        let spec = reloaded.file_spec("TLS_CA_FILE").unwrap();
        assert_eq!(spec.target_path, PathBuf::from("/tmp/root.crt.pem"));
        assert_eq!(spec.mode, "0644");
        assert_eq!(spec.cleanup, FileCleanup::Keep);
    }

    #[test]
    fn loads_file_import_document_and_resolves_relative_src_paths() {
        let dir = tempdir().unwrap();
        let spec_path = dir.path().join("files.yaml");
        std::fs::write(
            &spec_path,
            r#"
files:
  SERVICE_CA_CRT:
    src: ../pki/root.crt.pem
    to-file: /home/debian/mata35/pki/root.crt.pem
    mode: "0644"
    cleanup: keep
"#,
        )
        .unwrap();

        let document = load_file_import_document(&spec_path).unwrap();
        let spec = document.files.get("SERVICE_CA_CRT").unwrap();
        assert_eq!(spec.src, dir.path().join("../pki/root.crt.pem"));
        assert_eq!(
            spec.to_file.as_ref().unwrap(),
            &PathBuf::from("/home/debian/mata35/pki/root.crt.pem")
        );
        assert_eq!(spec.mode, "0644");
        assert_eq!(spec.cleanup, FileCleanup::Keep);
    }

    #[test]
    fn rejects_empty_file_import_document() {
        let dir = tempdir().unwrap();
        let spec_path = dir.path().join("files.yaml");
        std::fs::write(&spec_path, "files: {}\n").unwrap();

        let err = load_file_import_document(&spec_path).unwrap_err();
        assert!(matches!(err, Error::InvalidImportSpec(_)));
        assert!(
            err.to_string()
                .contains("files must contain at least one entry")
        );
    }

    #[test]
    fn file_import_document_defaults_mode_and_cleanup() {
        let document: FileImportDocument = serde_yaml::from_str(
            r#"
files:
  SERVICE_CRT:
    src: ./issued/service.crt.pem
    to-file: /tls/service.crt.pem
"#,
        )
        .unwrap();

        let spec = document.files.get("SERVICE_CRT").unwrap();
        assert_eq!(
            spec.to_file.as_ref().unwrap(),
            &PathBuf::from("/tls/service.crt.pem")
        );
        assert_eq!(spec.mode, "0600");
        assert_eq!(spec.cleanup, FileCleanup::OnExit);
    }

    #[test]
    fn file_import_document_allows_plain_env_import_from_src_only() {
        let document: FileImportDocument = serde_yaml::from_str(
            r#"
files:
  FIREBASE_JSON:
    src: ./firebase.json
"#,
        )
        .unwrap();

        let spec = document.files.get("FIREBASE_JSON").unwrap();
        assert_eq!(spec.src, PathBuf::from("./firebase.json"));
        assert_eq!(spec.to_file, None);
        assert_eq!(spec.mode, "0600");
        assert_eq!(spec.cleanup, FileCleanup::OnExit);
    }

    #[test]
    fn rejects_file_options_without_to_file() {
        let dir = tempdir().unwrap();
        let spec_path = dir.path().join("files.yaml");
        std::fs::write(
            &spec_path,
            r#"
files:
  SERVICE_CA_CRT:
    src: ../pki/root.crt.pem
    mode: "0644"
"#,
        )
        .unwrap();

        let err = load_file_import_document(&spec_path).unwrap_err();
        assert!(matches!(err, Error::InvalidImportSpec(_)));
        assert!(
            err.to_string()
                .contains("uses file options without to-file")
        );
    }

    #[test]
    fn file_import_document_accepts_legacy_target_path_alias() {
        let document: FileImportDocument = serde_yaml::from_str(
            r#"
files:
  SERVICE_CRT:
    src: ./issued/service.crt.pem
    target_path: /tls/service.crt.pem
"#,
        )
        .unwrap();

        let spec = document.files.get("SERVICE_CRT").unwrap();
        assert_eq!(
            spec.to_file.as_ref().unwrap(),
            &PathBuf::from("/tls/service.crt.pem")
        );
    }
}

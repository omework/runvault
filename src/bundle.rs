use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::{
    error::Error,
    profile::{
        DEFAULT_PROFILE_FILE, Profile, parse_file_mode, resolve_profile_path, save_profile_to_path,
    },
    vault::StoredFileCleanup,
};

const BUNDLE_SCHEMA_VERSION: u8 = 1;
const VISIBLE_VAULT_VERSION: u8 = 2;
const BUNDLE_DEFAULT_FILE_MODE: &str = "0600";
const VISIBLE_VAULT_DEFAULT_FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleDocument {
    #[serde(default = "default_bundle_schema_version")]
    pub schema_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub profile: Profile,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, BundledEnvEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, BundledFileEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledEnvEntry {
    pub enc_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledFileEntry {
    pub path: PathBuf,
    pub enc_base64: String,
    #[serde(default = "default_bundle_file_mode")]
    pub mode: String,
    #[serde(default)]
    pub cleanup: StoredFileCleanup,
}

#[derive(Debug, Clone)]
pub struct BundleExportOptions {
    pub version: Option<String>,
    pub description: Option<String>,
}

fn default_bundle_schema_version() -> u8 {
    BUNDLE_SCHEMA_VERSION
}

fn default_visible_vault_file_mode() -> u32 {
    VISIBLE_VAULT_DEFAULT_FILE_MODE
}

fn default_bundle_file_mode() -> String {
    BUNDLE_DEFAULT_FILE_MODE.to_string()
}

pub fn export_bundle(
    profile_input: &Path,
    output_path: &Path,
    options: &BundleExportOptions,
) -> Result<(), Error> {
    if output_path.exists() {
        return Err(Error::AlreadyExists(output_path.to_path_buf()));
    }

    let profile_path = resolve_profile_path(profile_input);
    let mut profile = Profile::from_path(&profile_path)?;
    let env_path = profile.resolve_env_path(&profile_path);
    let env_payload = fs::read(&env_path).map_err(|source| Error::ReadFile {
        path: env_path.clone(),
        source,
    })?;

    if profile.env_file.is_absolute() {
        let file_name = profile
            .env_file
            .file_name()
            .map(PathBuf::from)
            .filter(|value| !value.as_os_str().is_empty())
            .ok_or_else(|| {
                Error::InvalidBundle(
                    "absolute env_file path must end with a file name to be bundled".to_string(),
                )
            })?;
        profile.env_file = file_name;
    }

    let visible_vault = parse_visible_vault_payload(&env_payload)?;
    let (env, files) = split_visible_vault_entries(visible_vault)?;

    let bundle = BundleDocument {
        schema_version: default_bundle_schema_version(),
        version: options.version.clone(),
        description: options.description.clone(),
        profile,
        env,
        files,
    };

    let yaml =
        serde_yaml::to_string(&bundle).map_err(|err| Error::BundleSerialize(err.to_string()))?;
    fs::write(output_path, yaml).map_err(|source| Error::WriteFile {
        path: output_path.to_path_buf(),
        source,
    })
}

pub fn load_bundle(path: &Path) -> Result<BundleDocument, Error> {
    let content = fs::read_to_string(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let bundle: BundleDocument =
        serde_yaml::from_str(&content).map_err(|source| Error::BundleParse {
            path: path.to_path_buf(),
            source,
        })?;
    validate_bundle(&bundle)?;
    Ok(bundle)
}

pub fn materialize_bundle(bundle: &BundleDocument) -> Result<(TempDir, PathBuf), Error> {
    validate_bundle(bundle)?;
    let dir = tempfile::tempdir().map_err(|source| Error::WriteFile {
        path: std::env::temp_dir(),
        source,
    })?;
    let profile_path = dir.path().join(DEFAULT_PROFILE_FILE);

    let profile = bundle.profile.clone();
    if profile.env_file.is_absolute() {
        return Err(Error::InvalidBundle(
            "bundled profile env_file must be relative".to_string(),
        ));
    }

    save_profile_to_path(&profile_path, &profile)?;
    let env_path = profile.resolve_env_path(&profile_path);
    if let Some(parent) = env_path.parent() {
        fs::create_dir_all(parent).map_err(|source| Error::WriteFile {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let env_payload = bundle_env_payload_bytes(bundle)?;
    fs::write(&env_path, env_payload).map_err(|source| Error::WriteFile {
        path: env_path,
        source,
    })?;
    Ok((dir, profile_path))
}

fn validate_bundle(bundle: &BundleDocument) -> Result<(), Error> {
    if bundle.schema_version != BUNDLE_SCHEMA_VERSION {
        return Err(Error::InvalidBundle(format!(
            "unsupported bundle schema version {}",
            bundle.schema_version
        )));
    }
    if bundle.profile.name.trim().is_empty() {
        return Err(Error::InvalidBundle(
            "bundled profile name must not be empty".to_string(),
        ));
    }
    if bundle.profile.run.cmd.is_empty() {
        return Err(Error::InvalidBundle(
            "bundled profile run.cmd must not be empty".to_string(),
        ));
    }
    if bundle.profile.env_file.as_os_str().is_empty() {
        return Err(Error::InvalidBundle(
            "bundled profile env_file must not be empty".to_string(),
        ));
    }
    if bundle.profile.env_file.is_absolute() {
        return Err(Error::InvalidBundle(
            "bundled profile env_file must be relative".to_string(),
        ));
    }
    if bundle.env.is_empty() && bundle.files.is_empty() {
        return Err(Error::InvalidBundle(
            "bundle must contain env/files payload".to_string(),
        ));
    }
    let _ = bundle_env_payload_bytes(bundle)?;
    Ok(())
}

fn bundle_env_payload_bytes(bundle: &BundleDocument) -> Result<Vec<u8>, Error> {
    serialize_visible_vault_payload_from_bundle(bundle)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VisibleVaultDocument {
    #[serde(default = "default_visible_vault_version")]
    version: u8,
    #[serde(default)]
    entries: BTreeMap<String, VisibleVaultValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum VisibleVaultValue {
    PlainText {
        enc_base64: String,
    },
    FileContent {
        path: PathBuf,
        enc_base64: String,
        #[serde(default = "default_visible_vault_file_mode")]
        mode: u32,
        #[serde(default)]
        cleanup: StoredFileCleanup,
    },
}

fn default_visible_vault_version() -> u8 {
    VISIBLE_VAULT_VERSION
}

fn parse_visible_vault_payload(input: &[u8]) -> Result<VisibleVaultDocument, Error> {
    let visible: VisibleVaultDocument =
        serde_yaml::from_slice(input).map_err(|_| {
            Error::InvalidBundle(
                "bundle export requires a visible per-entry env payload; rewrite env.sec with a current runvault command first".to_string(),
            )
        })?;

    if visible.version != VISIBLE_VAULT_VERSION {
        return Err(Error::InvalidBundle(format!(
            "unsupported visible vault version {} for bundle export",
            visible.version
        )));
    }

    Ok(visible)
}

fn split_visible_vault_entries(
    visible: VisibleVaultDocument,
) -> Result<
    (
        BTreeMap<String, BundledEnvEntry>,
        BTreeMap<String, BundledFileEntry>,
    ),
    Error,
> {
    let mut env = BTreeMap::new();
    let mut files = BTreeMap::new();

    for (key, value) in visible.entries {
        match value {
            VisibleVaultValue::PlainText { enc_base64 } => {
                if files.contains_key(&key) {
                    return Err(Error::InvalidBundle(format!(
                        "duplicate bundled key '{key}'"
                    )));
                }
                env.insert(key, BundledEnvEntry { enc_base64 });
            }
            VisibleVaultValue::FileContent {
                path,
                enc_base64,
                mode,
                cleanup,
            } => {
                if env.contains_key(&key) {
                    return Err(Error::InvalidBundle(format!(
                        "duplicate bundled key '{key}'"
                    )));
                }
                files.insert(
                    key,
                    BundledFileEntry {
                        path,
                        enc_base64,
                        mode: format!("{mode:04o}"),
                        cleanup,
                    },
                );
            }
        }
    }

    Ok((env, files))
}

fn serialize_visible_vault_payload_from_bundle(bundle: &BundleDocument) -> Result<Vec<u8>, Error> {
    let mut entries = BTreeMap::new();

    for (key, value) in &bundle.env {
        entries.insert(
            key.clone(),
            VisibleVaultValue::PlainText {
                enc_base64: value.enc_base64.clone(),
            },
        );
    }

    for (key, value) in &bundle.files {
        if entries.contains_key(key) {
            return Err(Error::InvalidBundle(format!(
                "bundle key '{key}' is present in both env and files"
            )));
        }
        entries.insert(
            key.clone(),
            VisibleVaultValue::FileContent {
                path: value.path.clone(),
                enc_base64: value.enc_base64.clone(),
                mode: parse_file_mode(&value.mode)?,
                cleanup: value.cleanup,
            },
        );
    }

    serde_yaml::to_string(&VisibleVaultDocument {
        version: default_visible_vault_version(),
        entries,
    })
    .map(|yaml| yaml.into_bytes())
    .map_err(|err| Error::BundleSerialize(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{BundleExportOptions, export_bundle, load_bundle, materialize_bundle};
    use crate::{
        profile::Profile,
        vault::{StoredFileCleanup, VaultDocument, save_vault_with_password},
    };
    use age::secrecy::SecretString;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn exports_and_materializes_bundle() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("runvault.yaml");
        let bundle_path = dir.path().join("profile.bundle.yaml");
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
        let mut vault = VaultDocument::default();
        vault
            .set_plain_text("API_KEY", "secret".to_string())
            .unwrap();
        vault
            .set_file_content(
                "GOOGLE_APPLICATION_CREDENTIALS",
                PathBuf::from(".runvault/gcp.json"),
                br#"{"project":"demo"}"#.to_vec(),
                0o600,
                StoredFileCleanup::Keep.into(),
            )
            .unwrap();
        save_vault_with_password(
            &profile,
            &profile_path,
            &vault,
            SecretString::from("bundle-password".to_string()),
        )
        .unwrap();

        export_bundle(
            dir.path(),
            &bundle_path,
            &BundleExportOptions {
                version: Some("1.2.3".to_string()),
                description: Some("test bundle".to_string()),
            },
        )
        .unwrap();

        let bundle = load_bundle(&bundle_path).unwrap();
        let bundle_yaml = std::fs::read_to_string(&bundle_path).unwrap();
        assert!(bundle_yaml.contains("env:"));
        assert!(bundle_yaml.contains("files:"));
        assert!(bundle.env.contains_key("API_KEY"));
        assert!(bundle.files.contains_key("GOOGLE_APPLICATION_CREDENTIALS"));
        assert_eq!(
            bundle
                .files
                .get("GOOGLE_APPLICATION_CREDENTIALS")
                .unwrap()
                .mode,
            "0600"
        );
        assert_eq!(bundle.version.as_deref(), Some("1.2.3"));
        assert_eq!(bundle.description.as_deref(), Some("test bundle"));

        let (_temp_dir, extracted_profile_path) = materialize_bundle(&bundle).unwrap();
        let extracted_profile = Profile::from_path(&extracted_profile_path).unwrap();
        assert_eq!(extracted_profile.name, "local");
        assert_eq!(extracted_profile.env_file, PathBuf::from("env.sec"));
        assert!(
            extracted_profile
                .resolve_env_path(&extracted_profile_path)
                .exists()
        );
    }

    #[test]
    fn export_normalizes_absolute_env_file_path() {
        let dir = tempdir().unwrap();
        let env_path = dir.path().join("secrets").join("bundle.sec");
        std::fs::create_dir_all(env_path.parent().unwrap()).unwrap();
        let profile_path = dir.path().join("runvault.yaml");
        std::fs::write(
            &profile_path,
            format!(
                r#"
name: local
env_file: {}
run:
  cmd: ["/bin/sh", "-c", "exit 0"]
"#,
                env_path.display()
            ),
        )
        .unwrap();

        let profile = Profile::from_path(&profile_path).unwrap();
        let mut vault = VaultDocument::default();
        vault
            .set_plain_text("API_KEY", "secret".to_string())
            .unwrap();
        save_vault_with_password(
            &profile,
            &profile_path,
            &vault,
            SecretString::from("bundle-password".to_string()),
        )
        .unwrap();

        let bundle_path = dir.path().join("profile.bundle.yaml");
        export_bundle(
            dir.path(),
            &bundle_path,
            &BundleExportOptions {
                version: None,
                description: None,
            },
        )
        .unwrap();

        let bundle = load_bundle(&bundle_path).unwrap();
        assert_eq!(bundle.profile.env_file, PathBuf::from("bundle.sec"));
    }
}

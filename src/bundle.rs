use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::{
    error::Error,
    profile::{
        DEFAULT_PROFILE_FILE, FileCleanup, Profile, ResourceSpec, parse_file_mode,
        resolve_profile_path, save_profile_to_path,
    },
    vault::StoredFileCleanup,
};

const BUNDLE_SCHEMA_VERSION: u8 = 1;
const VISIBLE_VAULT_VERSION: u8 = 3;
const BUNDLE_DEFAULT_FILE_MODE: &str = "0600";
const VISIBLE_VAULT_DEFAULT_FILE_MODE: u32 = 0o600;
const VISIBLE_VAULT_DEFAULT_CIPHER: &str = "aes_256_gcm";
const VISIBLE_VAULT_DEFAULT_PBKDF2_ROUNDS: u32 = crate::crypto::DEFAULT_VAULT_PBKDF2_ROUNDS;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleDocument {
    #[serde(default = "default_bundle_schema_version")]
    pub schema_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub profile: Profile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_vault_crypto: Option<VisibleVaultCryptoMetadata>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, BundledEnvEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, BundledFileEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, BundledResourceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledEnvEntry {
    pub enc_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_base64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledFileEntry {
    pub path: PathBuf,
    pub enc_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_base64: Option<String>,
    #[serde(default = "default_bundle_file_mode")]
    pub mode: String,
    #[serde(default)]
    pub cleanup: StoredFileCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledResourceEntry {
    pub target_path: PathBuf,
    pub content_base64: String,
    #[serde(default = "default_bundle_file_mode")]
    pub mode: String,
    #[serde(default)]
    pub cleanup: FileCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibleVaultCryptoMetadata {
    #[serde(default = "default_visible_vault_cipher")]
    pub cipher: String,
    pub salt_base64: String,
    #[serde(default = "default_visible_vault_pbkdf2_rounds")]
    pub pbkdf2_rounds: u32,
}

#[derive(Debug, Clone)]
pub struct BundleExportOptions {
    pub version: Option<String>,
    pub description: Option<String>,
    pub force: bool,
}

fn default_bundle_schema_version() -> u8 {
    BUNDLE_SCHEMA_VERSION
}

fn default_visible_vault_cipher() -> String {
    VISIBLE_VAULT_DEFAULT_CIPHER.to_string()
}

fn default_visible_vault_pbkdf2_rounds() -> u32 {
    VISIBLE_VAULT_DEFAULT_PBKDF2_ROUNDS
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
    if output_path.exists() && !options.force {
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
    if profile.implicit_workdir {
        profile.workdir = None;
    }
    normalize_profile_bundle_paths(&mut profile);

    let visible_vault = parse_visible_vault_payload(&env_payload)?;
    let (visible_vault_crypto, env, files) = split_visible_vault_entries(visible_vault)?;
    let resources = bundle_profile_resources(&mut profile, &profile_path)?;

    let bundle = BundleDocument {
        schema_version: default_bundle_schema_version(),
        version: options.version.clone(),
        description: options.description.clone(),
        profile,
        visible_vault_crypto,
        env,
        files,
        resources,
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
    let profile_path = materialize_bundle_into(dir.path(), bundle)?;
    Ok((dir, profile_path))
}

pub fn materialize_bundle_into(base_dir: &Path, bundle: &BundleDocument) -> Result<PathBuf, Error> {
    validate_bundle(bundle)?;
    fs::create_dir_all(base_dir).map_err(|source| Error::WriteFile {
        path: base_dir.to_path_buf(),
        source,
    })?;
    let profile_path = base_dir.join(DEFAULT_PROFILE_FILE);
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
    materialize_bundle_resources(base_dir, bundle)?;
    Ok(profile_path)
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
    reject_relative_parent_components(&bundle.profile.env_file, "bundled profile env_file")?;
    if bundle.env.is_empty() && bundle.files.is_empty() && bundle.resources.is_empty() {
        return Err(Error::InvalidBundle(
            "bundle must contain env/files/resources payload".to_string(),
        ));
    }
    for (key, value) in &bundle.resources {
        reject_relative_parent_components(
            &value.target_path,
            &format!("bundled resource '{}' target_path", key),
        )?;
        if value.target_path.as_os_str().is_empty() {
            return Err(Error::InvalidBundle(format!(
                "bundled resource '{}' target_path must not be empty",
                key
            )));
        }
        parse_file_mode(&value.mode)?;
        let _ = STANDARD.decode(&value.content_base64).map_err(|err| {
            Error::InvalidBundle(format!(
                "bundled resource '{}' content_base64 is invalid: {}",
                key, err
            ))
        })?;
    }
    let _ = bundle_env_payload_bytes(bundle)?;
    for (key, value) in &bundle.files {
        reject_relative_parent_components(&value.path, &format!("bundled file '{}' path", key))?;
    }
    for (key, spec) in bundle.profile.resources() {
        reject_relative_parent_components(
            &spec.source_path,
            &format!("bundled resource '{}' source_path", key),
        )?;
        reject_relative_parent_components(
            &spec.target_path,
            &format!("bundled resource '{}' target_path", key),
        )?;
    }
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
    crypto: Option<VisibleVaultCryptoMetadata>,
    #[serde(default)]
    entries: BTreeMap<String, VisibleVaultValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum VisibleVaultValue {
    PlainText {
        enc_base64: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce_base64: Option<String>,
    },
    FileContent {
        path: PathBuf,
        enc_base64: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce_base64: Option<String>,
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

    if !is_supported_visible_vault_version(visible.version) {
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
        Option<VisibleVaultCryptoMetadata>,
        BTreeMap<String, BundledEnvEntry>,
        BTreeMap<String, BundledFileEntry>,
    ),
    Error,
> {
    let mut env = BTreeMap::new();
    let mut files = BTreeMap::new();

    for (key, value) in visible.entries {
        match value {
            VisibleVaultValue::PlainText {
                enc_base64,
                nonce_base64,
            } => {
                if files.contains_key(&key) {
                    return Err(Error::InvalidBundle(format!(
                        "duplicate bundled key '{key}'"
                    )));
                }
                env.insert(
                    key,
                    BundledEnvEntry {
                        enc_base64,
                        nonce_base64,
                    },
                );
            }
            VisibleVaultValue::FileContent {
                path,
                enc_base64,
                nonce_base64,
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
                        path: normalize_bundle_relative_path(&path),
                        enc_base64,
                        nonce_base64,
                        mode: format!("{mode:04o}"),
                        cleanup,
                    },
                );
            }
        }
    }

    Ok((visible.crypto, env, files))
}

fn bundle_profile_resources(
    profile: &mut Profile,
    profile_path: &Path,
) -> Result<BTreeMap<String, BundledResourceEntry>, Error> {
    let workdir = resolve_profile_workdir(profile, profile_path);
    let mut resources = BTreeMap::new();

    for (key, spec) in profile.resources().clone() {
        let source_path = if spec.source_path.is_absolute() {
            spec.source_path.clone()
        } else {
            workdir.join(&spec.source_path)
        };
        let content = fs::read(&source_path).map_err(|source| Error::ReadFile {
            path: source_path,
            source,
        })?;
        resources.insert(
            key.clone(),
            BundledResourceEntry {
                target_path: normalize_bundle_relative_path(&spec.target_path),
                content_base64: STANDARD.encode(content),
                mode: spec.mode.clone(),
                cleanup: spec.cleanup,
            },
        );
        profile.resources.insert(
            key.clone(),
            ResourceSpec {
                source_path: bundled_resource_source_path(&key, &spec),
                target_path: normalize_bundle_relative_path(&spec.target_path),
                mode: spec.mode,
                cleanup: spec.cleanup,
            },
        );
    }

    Ok(resources)
}

fn bundled_resource_source_path(key: &str, spec: &ResourceSpec) -> PathBuf {
    let file_name = spec
        .source_path
        .file_name()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("resource"));
    PathBuf::from(".runvault")
        .join("resources")
        .join(key)
        .join(file_name)
}

fn normalize_bundle_relative_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    match path.components().next() {
        Some(Component::CurDir | Component::ParentDir) | None => path.to_path_buf(),
        _ => PathBuf::from(".").join(path),
    }
}

fn normalize_profile_bundle_paths(profile: &mut Profile) {
    for spec in profile.files.values_mut() {
        spec.target_path = normalize_bundle_relative_path(&spec.target_path);
    }
    for spec in profile.resources.values_mut() {
        spec.target_path = normalize_bundle_relative_path(&spec.target_path);
    }
}

fn materialize_bundle_resources(base_dir: &Path, bundle: &BundleDocument) -> Result<(), Error> {
    for (key, value) in &bundle.resources {
        let spec = bundle.profile.resources().get(key).ok_or_else(|| {
            Error::InvalidBundle(format!(
                "bundled profile is missing resource spec for '{}'",
                key
            ))
        })?;
        let source_path = if spec.source_path.is_absolute() {
            return Err(Error::InvalidBundle(format!(
                "bundled resource '{}' source_path must be relative",
                key
            )));
        } else {
            base_dir.join(&spec.source_path)
        };
        if let Some(parent) = source_path.parent() {
            fs::create_dir_all(parent).map_err(|source| Error::WriteFile {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let content = STANDARD.decode(&value.content_base64).map_err(|err| {
            Error::InvalidBundle(format!(
                "bundled resource '{}' content_base64 is invalid: {}",
                key, err
            ))
        })?;
        fs::write(&source_path, content).map_err(|source| Error::WriteFile {
            path: source_path.clone(),
            source,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = parse_file_mode(&value.mode)?;
            let _ = fs::set_permissions(&source_path, fs::Permissions::from_mode(mode));
        }
    }
    Ok(())
}

fn reject_relative_parent_components(path: &Path, label: &str) -> Result<(), Error> {
    if path.is_absolute() {
        return Ok(());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::InvalidBundle(format!(
            "{} must not contain '..' in a relative path",
            label
        )));
    }
    Ok(())
}

fn resolve_profile_workdir(profile: &Profile, profile_path: &Path) -> PathBuf {
    let current_dir = std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf());
    if profile.implicit_workdir {
        return current_dir;
    }
    if let Some(workdir) = &profile.workdir {
        if workdir.is_absolute() {
            return workdir.clone();
        }
        return current_dir.join(workdir);
    }
    let _ = profile_path;
    current_dir
}

fn serialize_visible_vault_payload_from_bundle(bundle: &BundleDocument) -> Result<Vec<u8>, Error> {
    let mut entries = BTreeMap::new();
    let has_nonce = bundle
        .env
        .values()
        .any(|value| value.nonce_base64.is_some())
        || bundle
            .files
            .values()
            .any(|value| value.nonce_base64.is_some());

    if has_nonce && bundle.visible_vault_crypto.is_none() {
        return Err(Error::InvalidBundle(
            "bundle contains AES-GCM visible vault entries but is missing visible_vault_crypto"
                .to_string(),
        ));
    }

    for (key, value) in &bundle.env {
        entries.insert(
            key.clone(),
            VisibleVaultValue::PlainText {
                enc_base64: value.enc_base64.clone(),
                nonce_base64: value.nonce_base64.clone(),
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
                nonce_base64: value.nonce_base64.clone(),
                mode: parse_file_mode(&value.mode)?,
                cleanup: value.cleanup,
            },
        );
    }

    serde_yaml::to_string(&VisibleVaultDocument {
        version: if bundle.visible_vault_crypto.is_some() {
            default_visible_vault_version()
        } else {
            2
        },
        crypto: bundle.visible_vault_crypto.clone(),
        entries,
    })
    .map(|yaml| yaml.into_bytes())
    .map_err(|err| Error::BundleSerialize(err.to_string()))
}

fn is_supported_visible_vault_version(version: u8) -> bool {
    matches!(version, 2 | 3)
}

#[cfg(test)]
mod tests {
    use super::{BundleExportOptions, export_bundle, load_bundle, materialize_bundle};
    use crate::{
        error::Error,
        profile::Profile,
        vault::{StoredFileCleanup, VaultDocument, save_vault_with_password},
    };
    use age::secrecy::SecretString;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn exports_and_materializes_bundle() {
        let dir = tempdir().unwrap();

        let profile_dir = dir.path().join(".vault");
        std::fs::create_dir_all(&profile_dir).unwrap();
        let profile_path = profile_dir.join("runvault.yaml");
        let bundle_path = dir.path().join("profile.bundle.yaml");
        std::fs::write(dir.path().join("docker-compose.yml"), "services: {}\n").unwrap();
        std::fs::write(
            &profile_path,
            format!(
                r#"
name: local
env_file: env.sec
workdir: {}
resources:
  BUNDLED_DOCKER_COMPOSE_FILE:
    source_path: ./docker-compose.yml
    target_path: docker-compose.yml
    mode: "0644"
    cleanup: keep
run:
  cmd: ["/bin/sh", "-c", "exit 0"]
"#,
                dir.path().display()
            ),
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
                PathBuf::from("account-keys/gcp.json"),
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
            &profile_dir,
            &bundle_path,
            &BundleExportOptions {
                version: Some("1.2.3".to_string()),
                description: Some("test bundle".to_string()),
                force: false,
            },
        )
        .unwrap();

        let bundle = load_bundle(&bundle_path).unwrap();
        let bundle_yaml = std::fs::read_to_string(&bundle_path).unwrap();
        assert!(bundle_yaml.contains("env:"));
        assert!(bundle_yaml.contains("files:"));
        assert!(bundle_yaml.contains("resources:"));
        assert!(bundle.env.contains_key("API_KEY"));
        assert!(bundle.files.contains_key("GOOGLE_APPLICATION_CREDENTIALS"));
        assert!(bundle.resources.contains_key("BUNDLED_DOCKER_COMPOSE_FILE"));
        assert_eq!(
            bundle
                .files
                .get("GOOGLE_APPLICATION_CREDENTIALS")
                .unwrap()
                .path,
            PathBuf::from("./account-keys/gcp.json")
        );
        assert_eq!(
            bundle
                .resources
                .get("BUNDLED_DOCKER_COMPOSE_FILE")
                .unwrap()
                .target_path,
            PathBuf::from("./docker-compose.yml")
        );
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
        let resource = extracted_profile
            .resources()
            .get("BUNDLED_DOCKER_COMPOSE_FILE")
            .unwrap();
        assert_eq!(resource.target_path, PathBuf::from("./docker-compose.yml"));
        assert!(
            extracted_profile_path
                .parent()
                .unwrap()
                .join(&resource.source_path)
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
                force: false,
            },
        )
        .unwrap();

        let bundle = load_bundle(&bundle_path).unwrap();
        assert_eq!(bundle.profile.env_file, PathBuf::from("bundle.sec"));
    }

    #[test]
    fn export_bundle_overwrites_existing_target_when_forced() {
        let dir = tempdir().unwrap();
        let current = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let profile_dir = dir.path().join(".vault");
        std::fs::create_dir_all(&profile_dir).unwrap();
        let profile_path = profile_dir.join("runvault.yaml");
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
        save_vault_with_password(
            &profile,
            &profile_path,
            &vault,
            SecretString::from("bundle-password".to_string()),
        )
        .unwrap();

        std::fs::write(&bundle_path, "stale bundle\n").unwrap();

        let err = export_bundle(
            &profile_dir,
            &bundle_path,
            &BundleExportOptions {
                version: None,
                description: None,
                force: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::AlreadyExists(_)));
        assert_eq!(
            std::fs::read_to_string(&bundle_path).unwrap(),
            "stale bundle\n"
        );

        export_bundle(
            &profile_dir,
            &bundle_path,
            &BundleExportOptions {
                version: Some("2.0.0".to_string()),
                description: Some("forced bundle".to_string()),
                force: true,
            },
        )
        .unwrap();

        let bundle = load_bundle(&bundle_path).unwrap();
        assert_eq!(bundle.version.as_deref(), Some("2.0.0"));
        assert_eq!(bundle.description.as_deref(), Some("forced bundle"));
        assert!(bundle.env.contains_key("API_KEY"));

        std::env::set_current_dir(current).unwrap();
    }
}

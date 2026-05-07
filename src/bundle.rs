use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::{
    error::Error,
    profile::{DEFAULT_PROFILE_FILE, Profile, resolve_profile_path, save_profile_to_path},
};

const BUNDLE_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleDocument {
    #[serde(default = "default_bundle_schema_version")]
    pub schema_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub profile: Profile,
    pub env_payload_base64: String,
}

#[derive(Debug, Clone)]
pub struct BundleExportOptions {
    pub version: Option<String>,
    pub description: Option<String>,
}

fn default_bundle_schema_version() -> u8 {
    BUNDLE_SCHEMA_VERSION
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

    let bundle = BundleDocument {
        schema_version: default_bundle_schema_version(),
        version: options.version.clone(),
        description: options.description.clone(),
        profile,
        env_payload_base64: STANDARD.encode(env_payload),
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
    let env_payload = STANDARD
        .decode(&bundle.env_payload_base64)
        .map_err(|err| Error::InvalidBundle(format!("invalid env payload encoding: {err}")))?;
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
    let _ = STANDARD
        .decode(&bundle.env_payload_base64)
        .map_err(|err| Error::InvalidBundle(format!("invalid env payload encoding: {err}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BundleExportOptions, export_bundle, load_bundle, materialize_bundle};
    use crate::{
        profile::Profile,
        vault::{VaultDocument, save_vault_with_password},
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
        std::fs::write(&env_path, b"ciphertext").unwrap();

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

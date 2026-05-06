use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use age::secrecy::SecretString;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{decrypt_env, encrypt_env},
    envfile::{parse_env_bytes, validate_env_key},
    error::Error,
    profile::Profile,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultValue {
    PlainText(String),
    FileContent {
        path: PathBuf,
        content: Vec<u8>,
        mode: u32,
        cleanup: FileCleanup,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCleanup {
    OnExit,
    Keep,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultDocument {
    entries: BTreeMap<String, VaultValue>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredVaultDocument {
    #[serde(default = "default_vault_version")]
    version: u8,
    #[serde(default)]
    entries: BTreeMap<String, StoredVaultValue>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredVaultValue {
    PlainText {
        value: String,
    },
    FileContent {
        path: PathBuf,
        content_base64: String,
        #[serde(default = "default_file_mode")]
        mode: u32,
        #[serde(default)]
        cleanup: StoredFileCleanup,
    },
}

fn default_vault_version() -> u8 {
    1
}

fn default_file_mode() -> u32 {
    0o600
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum StoredFileCleanup {
    #[default]
    OnExit,
    Keep,
}

impl From<StoredFileCleanup> for FileCleanup {
    fn from(value: StoredFileCleanup) -> Self {
        match value {
            StoredFileCleanup::OnExit => FileCleanup::OnExit,
            StoredFileCleanup::Keep => FileCleanup::Keep,
        }
    }
}

impl From<FileCleanup> for StoredFileCleanup {
    fn from(value: FileCleanup) -> Self {
        match value {
            FileCleanup::OnExit => StoredFileCleanup::OnExit,
            FileCleanup::Keep => StoredFileCleanup::Keep,
        }
    }
}

impl VaultDocument {
    pub fn set_plain_text(&mut self, key: &str, value: String) -> Result<(), Error> {
        validate_key(key)?;
        self.entries
            .insert(key.to_string(), VaultValue::PlainText(value));
        Ok(())
    }

    pub fn set_file_content(
        &mut self,
        key: &str,
        runtime_path: PathBuf,
        content: Vec<u8>,
        mode: u32,
        cleanup: FileCleanup,
    ) -> Result<(), Error> {
        validate_key(key)?;
        if runtime_path.as_os_str().is_empty() {
            return Err(Error::VaultFormat(
                "file-backed values require a non-empty runtime path".to_string(),
            ));
        }
        self.entries.insert(
            key.to_string(),
            VaultValue::FileContent {
                path: runtime_path,
                content,
                mode,
                cleanup,
            },
        );
        Ok(())
    }

    pub fn delete(&mut self, key: &str) -> Result<(), Error> {
        if self.entries.remove(key).is_some() {
            Ok(())
        } else {
            Err(Error::MissingConfigKey(key.to_string()))
        }
    }

    pub fn entries(&self) -> &BTreeMap<String, VaultValue> {
        &self.entries
    }

    pub fn into_entries(self) -> BTreeMap<String, VaultValue> {
        self.entries
    }
}

pub fn load_vault_with_password(
    profile: &Profile,
    profile_path: &Path,
    password: SecretString,
) -> Result<VaultDocument, Error> {
    let env_path = profile.resolve_env_path(profile_path);
    let ciphertext = std::fs::read(&env_path).map_err(|source| Error::ReadFile {
        path: env_path.clone(),
        source,
    })?;
    let plaintext = decrypt_env(&ciphertext, password)?;
    parse_vault_bytes(&plaintext)
}

pub fn save_vault_with_password(
    profile: &Profile,
    profile_path: &Path,
    vault: &VaultDocument,
    password: SecretString,
) -> Result<(), Error> {
    let env_path = profile.resolve_env_path(profile_path);
    let plaintext = serialize_vault_bytes(vault)?;
    let ciphertext = encrypt_env(&plaintext, password)?;
    std::fs::write(&env_path, ciphertext).map_err(|source| Error::WriteFile {
        path: env_path,
        source,
    })
}

pub fn parse_vault_bytes(input: &[u8]) -> Result<VaultDocument, Error> {
    if input.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(VaultDocument::default());
    }

    match serde_yaml::from_slice::<StoredVaultDocument>(input) {
        Ok(stored) => from_stored_vault(stored),
        Err(_) => {
            let envs = parse_env_bytes(input)?;
            Ok(VaultDocument {
                entries: envs
                    .into_iter()
                    .map(|(key, value)| (key, VaultValue::PlainText(value)))
                    .collect(),
            })
        }
    }
}

fn serialize_vault_bytes(vault: &VaultDocument) -> Result<Vec<u8>, Error> {
    let stored = StoredVaultDocument {
        version: default_vault_version(),
        entries: vault
            .entries
            .iter()
            .map(|(key, value)| {
                let stored_value = match value {
                    VaultValue::PlainText(value) => StoredVaultValue::PlainText {
                        value: value.clone(),
                    },
                    VaultValue::FileContent {
                        path,
                        content,
                        mode,
                        cleanup,
                    } => StoredVaultValue::FileContent {
                        path: path.clone(),
                        content_base64: STANDARD.encode(content),
                        mode: *mode,
                        cleanup: (*cleanup).into(),
                    },
                };
                (key.clone(), stored_value)
            })
            .collect(),
    };

    serde_yaml::to_string(&stored)
        .map(|yaml| yaml.into_bytes())
        .map_err(|err| Error::VaultSerialize(err.to_string()))
}

fn from_stored_vault(stored: StoredVaultDocument) -> Result<VaultDocument, Error> {
    if stored.version != default_vault_version() {
        return Err(Error::VaultFormat(format!(
            "unsupported vault version {}",
            stored.version
        )));
    }

    let mut entries = BTreeMap::new();
    for (key, value) in stored.entries {
        validate_key(&key)?;
        let decoded = match value {
            StoredVaultValue::PlainText { value } => VaultValue::PlainText(value),
            StoredVaultValue::FileContent {
                path,
                content_base64,
                mode,
                cleanup,
            } => VaultValue::FileContent {
                path,
                content: STANDARD.decode(content_base64).map_err(|source| {
                    Error::FileContentDecode {
                        key: key.clone(),
                        source,
                    }
                })?,
                mode,
                cleanup: cleanup.into(),
            },
        };
        entries.insert(key, decoded);
    }

    Ok(VaultDocument { entries })
}

fn validate_key(key: &str) -> Result<(), Error> {
    if validate_env_key(key) {
        Ok(())
    } else {
        Err(Error::InvalidConfigKey(key.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FileCleanup, VaultDocument, VaultValue, load_vault_with_password, parse_vault_bytes,
        save_vault_with_password,
    };
    use crate::profile::Profile;
    use age::secrecy::SecretString;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn parses_legacy_env_payload_as_plain_text_entries() {
        let vault = parse_vault_bytes(b"API_KEY=test\nNAME=hello\n").unwrap();
        assert_eq!(
            vault.entries().get("API_KEY"),
            Some(&VaultValue::PlainText("test".to_string()))
        );
        assert_eq!(
            vault.entries().get("NAME"),
            Some(&VaultValue::PlainText("hello".to_string()))
        );
    }

    #[test]
    fn round_trips_plain_and_file_values() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("profile.yaml");
        let env_path = dir.path().join("secret.env.enc");
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
        vault.set_plain_text("API_KEY", "test".to_string()).unwrap();
        vault
            .set_file_content(
                "GOOGLE_APPLICATION_CREDENTIALS",
                PathBuf::from(".runvault/gcp.json"),
                br#"{"project":"demo"}"#.to_vec(),
                0o640,
                FileCleanup::Keep,
            )
            .unwrap();

        save_vault_with_password(
            &profile,
            &profile_path,
            &vault,
            SecretString::from("test-password".to_string()),
        )
        .unwrap();
        assert!(env_path.exists());

        let loaded = load_vault_with_password(
            &profile,
            &profile_path,
            SecretString::from("test-password".to_string()),
        )
        .unwrap();

        assert_eq!(
            loaded.entries().get("API_KEY"),
            Some(&VaultValue::PlainText("test".to_string()))
        );
        assert_eq!(
            loaded.entries().get("GOOGLE_APPLICATION_CREDENTIALS"),
            Some(&VaultValue::FileContent {
                path: PathBuf::from(".runvault/gcp.json"),
                content: br#"{"project":"demo"}"#.to_vec(),
                mode: 0o640,
                cleanup: FileCleanup::Keep,
            })
        );
    }

    #[test]
    fn parses_legacy_file_entry_without_mode_or_cleanup() {
        let input = br#"
version: 1
entries:
  GOOGLE_APPLICATION_CREDENTIALS:
    kind: file_content
    path: .runvault/gcp.json
    content_base64: eyJwcm9qZWN0IjoiZGVtbyJ9
"#;

        let vault = parse_vault_bytes(input).unwrap();
        assert_eq!(
            vault.entries().get("GOOGLE_APPLICATION_CREDENTIALS"),
            Some(&VaultValue::FileContent {
                path: PathBuf::from(".runvault/gcp.json"),
                content: br#"{"project":"demo"}"#.to_vec(),
                mode: 0o600,
                cleanup: FileCleanup::OnExit,
            })
        );
    }

    #[test]
    fn delete_requires_existing_key() {
        let mut vault = VaultDocument::default();
        let err = vault.delete("MISSING").unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }
}

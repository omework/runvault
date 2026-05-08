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
    profile::{FileCleanup, Profile},
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
    SealedVisible(VisibleVaultValue),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultDocument {
    entries: BTreeMap<String, VaultValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VisibleVaultDocument {
    #[serde(default = "default_visible_vault_version")]
    version: u8,
    #[serde(default)]
    entries: BTreeMap<String, VisibleVaultValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VisibleVaultValue {
    PlainText {
        enc_base64: String,
    },
    FileContent {
        path: PathBuf,
        enc_base64: String,
        #[serde(default = "default_file_mode")]
        mode: u32,
        #[serde(default)]
        cleanup: StoredFileCleanup,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyStoredVaultDocument {
    #[serde(default = "default_legacy_vault_version")]
    version: u8,
    #[serde(default)]
    entries: BTreeMap<String, LegacyStoredVaultValue>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum LegacyStoredVaultValue {
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

fn default_visible_vault_version() -> u8 {
    2
}

fn default_legacy_vault_version() -> u8 {
    1
}

fn default_file_mode() -> u32 {
    0o600
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum StoredFileCleanup {
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
    let input = std::fs::read(&env_path).map_err(|source| Error::ReadFile {
        path: env_path.clone(),
        source,
    })?;

    if input.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(VaultDocument::default());
    }

    if let Some(visible) = try_parse_visible_vault_document(&input)? {
        return from_visible_vault(visible, password);
    }

    let plaintext = decrypt_env(&input, password)?;
    parse_legacy_vault_bytes(&plaintext)
}

pub fn load_vault_for_update_with_password(
    profile: &Profile,
    profile_path: &Path,
    password: SecretString,
) -> Result<VaultDocument, Error> {
    let env_path = profile.resolve_env_path(profile_path);
    let input = std::fs::read(&env_path).map_err(|source| Error::ReadFile {
        path: env_path.clone(),
        source,
    })?;

    if input.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(VaultDocument::default());
    }

    if let Some(visible) = try_parse_visible_vault_document(&input)? {
        return from_visible_vault_for_update(visible, password);
    }

    let plaintext = decrypt_env(&input, password)?;
    parse_legacy_vault_bytes(&plaintext)
}

pub fn save_vault_with_password(
    profile: &Profile,
    profile_path: &Path,
    vault: &VaultDocument,
    password: SecretString,
) -> Result<(), Error> {
    let env_path = profile.resolve_env_path(profile_path);
    let plaintext = serialize_visible_vault_bytes(vault, password)?;
    std::fs::write(&env_path, plaintext).map_err(|source| Error::WriteFile {
        path: env_path,
        source,
    })
}

pub fn parse_vault_bytes(input: &[u8]) -> Result<VaultDocument, Error> {
    parse_legacy_vault_bytes(input)
}

fn parse_legacy_vault_bytes(input: &[u8]) -> Result<VaultDocument, Error> {
    if input.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(VaultDocument::default());
    }

    match serde_yaml::from_slice::<LegacyStoredVaultDocument>(input) {
        Ok(stored) => from_legacy_vault(stored),
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

fn try_parse_visible_vault_document(input: &[u8]) -> Result<Option<VisibleVaultDocument>, Error> {
    match serde_yaml::from_slice::<VisibleVaultDocument>(input) {
        Ok(document) => Ok(Some(document)),
        Err(_) => Ok(None),
    }
}

fn serialize_visible_vault_bytes(
    vault: &VaultDocument,
    password: SecretString,
) -> Result<Vec<u8>, Error> {
    let entries = vault
        .entries
        .iter()
        .map(|(key, value)| {
            let stored_value = match value {
                VaultValue::PlainText(value) => VisibleVaultValue::PlainText {
                    enc_base64: STANDARD.encode(encrypt_env(value.as_bytes(), password.clone())?),
                },
                VaultValue::FileContent {
                    path,
                    content,
                    mode,
                    cleanup,
                } => VisibleVaultValue::FileContent {
                    path: path.clone(),
                    enc_base64: STANDARD.encode(encrypt_env(content, password.clone())?),
                    mode: *mode,
                    cleanup: (*cleanup).into(),
                },
                VaultValue::SealedVisible(value) => value.clone(),
            };
            Ok((key.clone(), stored_value))
        })
        .collect::<Result<BTreeMap<_, _>, Error>>()?;

    let stored = VisibleVaultDocument {
        version: default_visible_vault_version(),
        entries,
    };

    serde_yaml::to_string(&stored)
        .map(|yaml| yaml.into_bytes())
        .map_err(|err| Error::VaultSerialize(err.to_string()))
}

fn from_visible_vault(
    stored: VisibleVaultDocument,
    password: SecretString,
) -> Result<VaultDocument, Error> {
    if stored.version != default_visible_vault_version() {
        return Err(Error::VaultFormat(format!(
            "unsupported visible vault version {}",
            stored.version
        )));
    }

    let mut entries = BTreeMap::new();
    for (key, value) in stored.entries {
        validate_key(&key)?;
        let decoded = decrypt_visible_value(&key, value, password.clone())?;
        entries.insert(key, decoded);
    }

    Ok(VaultDocument { entries })
}

fn from_visible_vault_for_update(
    stored: VisibleVaultDocument,
    password: SecretString,
) -> Result<VaultDocument, Error> {
    if stored.version != default_visible_vault_version() {
        return Err(Error::VaultFormat(format!(
            "unsupported visible vault version {}",
            stored.version
        )));
    }

    let mut entries = BTreeMap::new();
    let mut validated_password = stored.entries.is_empty();

    for (key, value) in stored.entries {
        validate_key(&key)?;
        if !validated_password {
            validate_visible_entry_password(&key, &value, password.clone())?;
            validated_password = true;
        }
        entries.insert(key, VaultValue::SealedVisible(value));
    }

    Ok(VaultDocument { entries })
}

fn decrypt_visible_value(
    key: &str,
    value: VisibleVaultValue,
    password: SecretString,
) -> Result<VaultValue, Error> {
    match value {
        VisibleVaultValue::PlainText { enc_base64 } => {
            let ciphertext =
                STANDARD
                    .decode(enc_base64)
                    .map_err(|source| Error::EntryCiphertextDecode {
                        key: key.to_string(),
                        source,
                    })?;
            let plaintext = decrypt_env(&ciphertext, password)?;
            let value = String::from_utf8(plaintext.to_vec())
                .map_err(|_| Error::VaultFormat(format!("key '{key}' is not valid utf-8")))?;
            Ok(VaultValue::PlainText(value))
        }
        VisibleVaultValue::FileContent {
            path,
            enc_base64,
            mode,
            cleanup,
        } => {
            let ciphertext =
                STANDARD
                    .decode(enc_base64)
                    .map_err(|source| Error::EntryCiphertextDecode {
                        key: key.to_string(),
                        source,
                    })?;
            let content = decrypt_env(&ciphertext, password)?.to_vec();
            Ok(VaultValue::FileContent {
                path,
                content,
                mode,
                cleanup: cleanup.into(),
            })
        }
    }
}

fn validate_visible_entry_password(
    key: &str,
    value: &VisibleVaultValue,
    password: SecretString,
) -> Result<(), Error> {
    match value {
        VisibleVaultValue::PlainText { enc_base64 } => {
            let ciphertext =
                STANDARD
                    .decode(enc_base64)
                    .map_err(|source| Error::EntryCiphertextDecode {
                        key: key.to_string(),
                        source,
                    })?;
            let _ = decrypt_env(&ciphertext, password)?;
        }
        VisibleVaultValue::FileContent { enc_base64, .. } => {
            let ciphertext =
                STANDARD
                    .decode(enc_base64)
                    .map_err(|source| Error::EntryCiphertextDecode {
                        key: key.to_string(),
                        source,
                    })?;
            let _ = decrypt_env(&ciphertext, password)?;
        }
    }
    Ok(())
}

fn from_legacy_vault(stored: LegacyStoredVaultDocument) -> Result<VaultDocument, Error> {
    if stored.version != default_legacy_vault_version() {
        return Err(Error::VaultFormat(format!(
            "unsupported vault version {}",
            stored.version
        )));
    }

    let mut entries = BTreeMap::new();
    for (key, value) in stored.entries {
        validate_key(&key)?;
        let decoded = match value {
            LegacyStoredVaultValue::PlainText { value } => VaultValue::PlainText(value),
            LegacyStoredVaultValue::FileContent {
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
        FileCleanup, LegacyStoredVaultDocument, LegacyStoredVaultValue, VaultDocument, VaultValue,
        VisibleVaultDocument, VisibleVaultValue, load_vault_for_update_with_password,
        load_vault_with_password, parse_vault_bytes, save_vault_with_password,
    };
    use crate::{crypto::encrypt_env, profile::Profile};
    use age::secrecy::SecretString;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::{collections::BTreeMap, path::PathBuf};
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
    fn round_trips_plain_and_file_values_in_visible_format() {
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

        let visible = std::fs::read_to_string(&env_path).unwrap();
        assert!(visible.contains("version: 2"));
        assert!(visible.contains("API_KEY:"));
        assert!(visible.contains("GOOGLE_APPLICATION_CREDENTIALS:"));
        assert!(!visible.contains("value: test"));
        assert!(!visible.contains(r#"{"project":"demo"}"#));

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
    fn loads_legacy_whole_file_encrypted_vault() {
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

        let legacy = LegacyStoredVaultDocument {
            version: 1,
            entries: BTreeMap::from([
                (
                    "API_KEY".to_string(),
                    LegacyStoredVaultValue::PlainText {
                        value: "test".to_string(),
                    },
                ),
                (
                    "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
                    LegacyStoredVaultValue::FileContent {
                        path: PathBuf::from(".runvault/gcp.json"),
                        content_base64: STANDARD.encode(br#"{"project":"demo"}"#),
                        mode: 0o600,
                        cleanup: super::StoredFileCleanup::OnExit,
                    },
                ),
            ]),
        };
        let plaintext = serde_yaml::to_string(&legacy).unwrap();
        let ciphertext = encrypt_env(
            plaintext.as_bytes(),
            SecretString::from("test-password".to_string()),
        )
        .unwrap();
        std::fs::write(&env_path, ciphertext).unwrap();

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
                mode: 0o600,
                cleanup: FileCleanup::OnExit,
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
    fn visible_vault_document_is_password_protected_per_entry() {
        let ciphertext = encrypt_env(
            b"top-secret",
            SecretString::from("test-password".to_string()),
        )
        .unwrap();
        let visible = VisibleVaultDocument {
            version: 2,
            entries: BTreeMap::from([(
                "SECRET".to_string(),
                VisibleVaultValue::PlainText {
                    enc_base64: STANDARD.encode(ciphertext),
                },
            )]),
        };
        let encoded = serde_yaml::to_string(&visible).unwrap();
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
        std::fs::write(&env_path, encoded).unwrap();
        let profile = Profile::from_path(&profile_path).unwrap();

        let err = load_vault_with_password(
            &profile,
            &profile_path,
            SecretString::from("wrong".to_string()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }

    #[test]
    fn update_loader_preserves_untouched_visible_ciphertext() {
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
        let password = SecretString::from("test-password".to_string());

        let original_secret_ciphertext =
            STANDARD.encode(encrypt_env(b"keep-me", password.clone()).unwrap());
        let visible = VisibleVaultDocument {
            version: 2,
            entries: BTreeMap::from([
                (
                    "SECRET".to_string(),
                    VisibleVaultValue::PlainText {
                        enc_base64: original_secret_ciphertext.clone(),
                    },
                ),
                (
                    "CONFIG".to_string(),
                    VisibleVaultValue::PlainText {
                        enc_base64: STANDARD.encode(encrypt_env(b"old", password.clone()).unwrap()),
                    },
                ),
            ]),
        };
        std::fs::write(&env_path, serde_yaml::to_string(&visible).unwrap()).unwrap();

        let mut vault =
            load_vault_for_update_with_password(&profile, &profile_path, password.clone()).unwrap();
        assert!(matches!(
            vault.entries().get("SECRET"),
            Some(VaultValue::SealedVisible(_))
        ));

        vault.set_plain_text("CONFIG", "new".to_string()).unwrap();
        save_vault_with_password(&profile, &profile_path, &vault, password.clone()).unwrap();

        let saved: VisibleVaultDocument =
            serde_yaml::from_str(&std::fs::read_to_string(&env_path).unwrap()).unwrap();
        assert_eq!(
            saved.entries.get("SECRET"),
            Some(&VisibleVaultValue::PlainText {
                enc_base64: original_secret_ciphertext,
            })
        );

        let loaded = load_vault_with_password(&profile, &profile_path, password).unwrap();
        assert_eq!(
            loaded.entries().get("SECRET"),
            Some(&VaultValue::PlainText("keep-me".to_string()))
        );
        assert_eq!(
            loaded.entries().get("CONFIG"),
            Some(&VaultValue::PlainText("new".to_string()))
        );
    }

    #[test]
    fn delete_requires_existing_key() {
        let mut vault = VaultDocument::default();
        let err = vault.delete("MISSING").unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }
}

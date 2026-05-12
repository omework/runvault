use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use age::secrecy::SecretString;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        EncryptedPayload, VaultCipher, VaultCryptoConfig, decrypt_env, generate_profile_key,
        unwrap_profile_key, wrap_profile_key,
    },
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
    visible_crypto: Option<VisibleVaultCryptoMetadata>,
    visible_wrapped_key: Option<VisibleVaultWrappedKeyMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VisibleVaultDocument {
    #[serde(default = "default_visible_vault_version")]
    version: u8,
    #[serde(default)]
    crypto: Option<VisibleVaultCryptoMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrapped_profile_key: Option<VisibleVaultWrappedKeyMetadata>,
    #[serde(default)]
    entries: BTreeMap<String, VisibleVaultValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VisibleVaultValue {
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
        #[serde(default = "default_file_mode")]
        mode: u32,
        #[serde(default)]
        cleanup: StoredFileCleanup,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VisibleVaultCryptoMetadata {
    #[serde(default = "default_visible_vault_cipher")]
    cipher: String,
    salt_base64: String,
    #[serde(default = "default_visible_vault_pbkdf2_rounds")]
    pbkdf2_rounds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VisibleVaultWrappedKeyMetadata {
    enc_base64: String,
    nonce_base64: String,
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
    4
}

fn default_legacy_vault_version() -> u8 {
    1
}

fn default_visible_vault_cipher() -> String {
    "aes_256_gcm".to_string()
}

fn default_visible_vault_pbkdf2_rounds() -> u32 {
    crate::crypto::DEFAULT_VAULT_PBKDF2_ROUNDS
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

impl StoredFileCleanup {
    fn as_str(self) -> &'static str {
        match self {
            StoredFileCleanup::OnExit => "on_exit",
            StoredFileCleanup::Keep => "keep",
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

    fn visible_crypto(&self) -> Option<&VisibleVaultCryptoMetadata> {
        self.visible_crypto.as_ref()
    }

    fn visible_wrapped_key(&self) -> Option<&VisibleVaultWrappedKeyMetadata> {
        self.visible_wrapped_key.as_ref()
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
                visible_crypto: None,
                visible_wrapped_key: None,
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
    let needs_aead = vault
        .entries
        .values()
        .any(|value| !matches!(value, VaultValue::SealedVisible(_)));
    let uses_wrapped_profile_key = needs_aead;
    let crypto = if uses_wrapped_profile_key {
        Some(
            vault
                .visible_crypto()
                .cloned()
                .unwrap_or_else(|| visible_vault_crypto_metadata(&VaultCryptoConfig::generate())),
        )
    } else {
        vault.visible_crypto().cloned()
    };
    let profile_key = if uses_wrapped_profile_key {
        if let (Some(crypto), Some(wrapped)) = (crypto.as_ref(), vault.visible_wrapped_key()) {
            unwrap_visible_profile_key(crypto, wrapped, &password)?.to_vec()
        } else {
            generate_profile_key().to_vec()
        }
    } else {
        Vec::new()
    };
    let cipher = if uses_wrapped_profile_key {
        Some(VaultCipher::from_key_bytes(&profile_key)?)
    } else {
        None
    };
    let wrapped_profile_key = if uses_wrapped_profile_key {
        Some(visible_vault_wrapped_key_metadata(&wrap_profile_key(
            &password,
            &visible_vault_crypto_config(crypto.as_ref().ok_or_else(|| {
                Error::VaultFormat("missing visible vault crypto config".to_string())
            })?)?,
            &profile_key,
        )?))
    } else {
        vault.visible_wrapped_key().cloned()
    };

    let entries = vault
        .entries
        .iter()
        .map(|(key, value)| {
            let stored_value = match value {
                VaultValue::PlainText(value) => {
                    let encrypted = cipher
                        .as_ref()
                        .ok_or_else(|| {
                            Error::VaultFormat(
                                "missing AES-256-GCM cipher for visible vault entry".to_string(),
                            )
                        })?
                        .encrypt(value.as_bytes(), plain_text_aad(key).as_bytes())?;
                    VisibleVaultValue::PlainText {
                        enc_base64: STANDARD.encode(encrypted.ciphertext),
                        nonce_base64: Some(STANDARD.encode(encrypted.nonce)),
                    }
                }
                VaultValue::FileContent {
                    path,
                    content,
                    mode,
                    cleanup,
                } => {
                    let cleanup: StoredFileCleanup = (*cleanup).into();
                    let encrypted = cipher
                        .as_ref()
                        .ok_or_else(|| {
                            Error::VaultFormat(
                                "missing AES-256-GCM cipher for visible vault entry".to_string(),
                            )
                        })?
                        .encrypt(
                            content,
                            file_content_aad(key, path, *mode, cleanup).as_bytes(),
                        )?;
                    VisibleVaultValue::FileContent {
                        path: path.clone(),
                        enc_base64: STANDARD.encode(encrypted.ciphertext),
                        nonce_base64: Some(STANDARD.encode(encrypted.nonce)),
                        mode: *mode,
                        cleanup,
                    }
                }
                VaultValue::SealedVisible(value) => value.clone(),
            };
            Ok((key.clone(), stored_value))
        })
        .collect::<Result<BTreeMap<_, _>, Error>>()?;

    let stored = VisibleVaultDocument {
        version: if wrapped_profile_key.is_some() {
            default_visible_vault_version()
        } else if crypto.is_some() {
            3
        } else {
            2
        },
        crypto,
        wrapped_profile_key,
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
    if !is_supported_visible_vault_version(stored.version) {
        return Err(Error::VaultFormat(format!(
            "unsupported visible vault version {}",
            stored.version
        )));
    }

    let wrapped_profile_key = stored.wrapped_profile_key.clone();
    let cipher = visible_vault_cipher(
        stored.version,
        stored.crypto.as_ref(),
        wrapped_profile_key.as_ref(),
        &password,
    )?;
    let mut entries = BTreeMap::new();
    for (key, value) in stored.entries {
        validate_key(&key)?;
        let decoded = decrypt_visible_value(&key, value, password.clone(), cipher.as_ref())?;
        entries.insert(key, decoded);
    }

    Ok(VaultDocument {
        entries,
        visible_crypto: stored.crypto,
        visible_wrapped_key: wrapped_profile_key,
    })
}

fn from_visible_vault_for_update(
    stored: VisibleVaultDocument,
    password: SecretString,
) -> Result<VaultDocument, Error> {
    if !is_supported_visible_vault_version(stored.version) {
        return Err(Error::VaultFormat(format!(
            "unsupported visible vault version {}",
            stored.version
        )));
    }

    let wrapped_profile_key = stored.wrapped_profile_key.clone();
    let cipher = visible_vault_cipher(
        stored.version,
        stored.crypto.as_ref(),
        wrapped_profile_key.as_ref(),
        &password,
    )?;
    let mut entries = BTreeMap::new();
    let mut validated_password = stored.entries.is_empty();

    for (key, value) in stored.entries {
        validate_key(&key)?;
        if !validated_password {
            validate_visible_entry_password(&key, &value, password.clone(), cipher.as_ref())?;
            validated_password = true;
        }
        entries.insert(key, VaultValue::SealedVisible(value));
    }

    Ok(VaultDocument {
        entries,
        visible_crypto: stored.crypto,
        visible_wrapped_key: wrapped_profile_key,
    })
}

fn decrypt_visible_value(
    key: &str,
    value: VisibleVaultValue,
    password: SecretString,
    cipher: Option<&VaultCipher>,
) -> Result<VaultValue, Error> {
    match value {
        VisibleVaultValue::PlainText {
            enc_base64,
            nonce_base64,
        } => {
            let plaintext = if let Some(nonce_base64) = nonce_base64 {
                let payload = encrypted_payload_from_fields(key, enc_base64, &nonce_base64)?;
                cipher
                    .ok_or_else(|| {
                        Error::VaultFormat(format!(
                            "key '{key}' requires visible vault crypto metadata"
                        ))
                    })?
                    .decrypt(&payload, plain_text_aad(key).as_bytes())?
            } else {
                let ciphertext =
                    STANDARD
                        .decode(enc_base64)
                        .map_err(|source| Error::EntryCiphertextDecode {
                            key: key.to_string(),
                            source,
                        })?;
                decrypt_env(&ciphertext, password)?
            };
            let value = String::from_utf8(plaintext.to_vec())
                .map_err(|_| Error::VaultFormat(format!("key '{key}' is not valid utf-8")))?;
            Ok(VaultValue::PlainText(value))
        }
        VisibleVaultValue::FileContent {
            path,
            enc_base64,
            nonce_base64,
            mode,
            cleanup,
        } => {
            let content = if let Some(nonce_base64) = nonce_base64 {
                let payload = encrypted_payload_from_fields(key, enc_base64, &nonce_base64)?;
                cipher
                    .ok_or_else(|| {
                        Error::VaultFormat(format!(
                            "key '{key}' requires visible vault crypto metadata"
                        ))
                    })?
                    .decrypt(
                        &payload,
                        file_content_aad(key, &path, mode, cleanup).as_bytes(),
                    )?
                    .to_vec()
            } else {
                let ciphertext =
                    STANDARD
                        .decode(enc_base64)
                        .map_err(|source| Error::EntryCiphertextDecode {
                            key: key.to_string(),
                            source,
                        })?;
                decrypt_env(&ciphertext, password)?.to_vec()
            };
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
    cipher: Option<&VaultCipher>,
) -> Result<(), Error> {
    match value {
        VisibleVaultValue::PlainText {
            enc_base64,
            nonce_base64,
        } => match nonce_base64 {
            Some(nonce_base64) => {
                let payload = encrypted_payload_from_fields(key, enc_base64.clone(), nonce_base64)?;
                let _ = cipher
                    .ok_or_else(|| {
                        Error::VaultFormat(format!(
                            "key '{key}' requires visible vault crypto metadata"
                        ))
                    })?
                    .decrypt(&payload, plain_text_aad(key).as_bytes())?;
            }
            None => {
                let ciphertext =
                    STANDARD
                        .decode(enc_base64)
                        .map_err(|source| Error::EntryCiphertextDecode {
                            key: key.to_string(),
                            source,
                        })?;
                let _ = decrypt_env(&ciphertext, password)?;
            }
        },
        VisibleVaultValue::FileContent {
            path,
            enc_base64,
            nonce_base64,
            mode,
            cleanup,
        } => match nonce_base64 {
            Some(nonce_base64) => {
                let payload = encrypted_payload_from_fields(key, enc_base64.clone(), nonce_base64)?;
                let _ = cipher
                    .ok_or_else(|| {
                        Error::VaultFormat(format!(
                            "key '{key}' requires visible vault crypto metadata"
                        ))
                    })?
                    .decrypt(
                        &payload,
                        file_content_aad(key, path, *mode, *cleanup).as_bytes(),
                    )?;
            }
            None => {
                let ciphertext =
                    STANDARD
                        .decode(enc_base64)
                        .map_err(|source| Error::EntryCiphertextDecode {
                            key: key.to_string(),
                            source,
                        })?;
                let _ = decrypt_env(&ciphertext, password)?;
            }
        },
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

    Ok(VaultDocument {
        entries,
        visible_crypto: None,
        visible_wrapped_key: None,
    })
}

fn validate_key(key: &str) -> Result<(), Error> {
    if validate_env_key(key) {
        Ok(())
    } else {
        Err(Error::InvalidConfigKey(key.to_string()))
    }
}

fn is_supported_visible_vault_version(version: u8) -> bool {
    matches!(version, 2 | 3 | 4)
}

fn visible_vault_crypto_metadata(config: &VaultCryptoConfig) -> VisibleVaultCryptoMetadata {
    VisibleVaultCryptoMetadata {
        cipher: default_visible_vault_cipher(),
        salt_base64: STANDARD.encode(config.salt),
        pbkdf2_rounds: config.pbkdf2_rounds,
    }
}

fn visible_vault_crypto_config(
    metadata: &VisibleVaultCryptoMetadata,
) -> Result<VaultCryptoConfig, Error> {
    if metadata.cipher != default_visible_vault_cipher() {
        return Err(Error::VaultFormat(format!(
            "unsupported visible vault cipher {}",
            metadata.cipher
        )));
    }

    let salt = STANDARD
        .decode(&metadata.salt_base64)
        .map_err(|err| Error::VaultFormat(format!("invalid visible vault salt: {err}")))?;
    let salt: [u8; crate::crypto::VAULT_KDF_SALT_LEN] = salt.try_into().map_err(|_| {
        Error::VaultFormat("visible vault salt must be exactly 16 bytes".to_string())
    })?;

    Ok(VaultCryptoConfig {
        salt,
        pbkdf2_rounds: metadata.pbkdf2_rounds,
    })
}

fn visible_vault_cipher(
    version: u8,
    metadata: Option<&VisibleVaultCryptoMetadata>,
    wrapped_key: Option<&VisibleVaultWrappedKeyMetadata>,
    password: &SecretString,
) -> Result<Option<VaultCipher>, Error> {
    match version {
        4 => {
            let metadata = metadata.ok_or_else(|| {
                Error::VaultFormat("visible vault version 4 requires crypto metadata".to_string())
            })?;
            let wrapped_key = wrapped_key.ok_or_else(|| {
                Error::VaultFormat(
                    "visible vault version 4 requires wrapped profile key metadata".to_string(),
                )
            })?;
            let profile_key = unwrap_visible_profile_key(metadata, wrapped_key, password)?;
            Ok(Some(VaultCipher::from_key_bytes(&profile_key)?))
        }
        _ => metadata
            .map(|metadata| VaultCipher::derive(password, &visible_vault_crypto_config(metadata)?))
            .transpose(),
    }
}

fn visible_vault_wrapped_key_metadata(
    payload: &EncryptedPayload,
) -> VisibleVaultWrappedKeyMetadata {
    VisibleVaultWrappedKeyMetadata {
        enc_base64: STANDARD.encode(&payload.ciphertext),
        nonce_base64: STANDARD.encode(payload.nonce),
    }
}

fn unwrap_visible_profile_key(
    crypto: &VisibleVaultCryptoMetadata,
    wrapped_key: &VisibleVaultWrappedKeyMetadata,
    password: &SecretString,
) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let payload = encrypted_payload_from_fields(
        "wrapped_profile_key",
        wrapped_key.enc_base64.clone(),
        &wrapped_key.nonce_base64,
    )?;
    unwrap_profile_key(password, &visible_vault_crypto_config(crypto)?, &payload)
}

fn encrypted_payload_from_fields(
    key: &str,
    enc_base64: String,
    nonce_base64: &str,
) -> Result<EncryptedPayload, Error> {
    let ciphertext =
        STANDARD
            .decode(enc_base64)
            .map_err(|source| Error::EntryCiphertextDecode {
                key: key.to_string(),
                source,
            })?;
    let nonce = STANDARD
        .decode(nonce_base64)
        .map_err(|err| Error::VaultFormat(format!("invalid nonce for key '{key}': {err}")))?;
    let nonce: [u8; crate::crypto::VAULT_NONCE_LEN] = nonce.try_into().map_err(|_| {
        Error::VaultFormat(format!("nonce for key '{key}' must be exactly 12 bytes"))
    })?;
    Ok(EncryptedPayload { nonce, ciphertext })
}

fn plain_text_aad(key: &str) -> String {
    format!("kind=plain_text\nkey={key}\n")
}

fn file_content_aad(key: &str, path: &Path, mode: u32, cleanup: StoredFileCleanup) -> String {
    format!(
        "kind=file_content\nkey={key}\npath={}\nmode={mode:04o}\ncleanup={}\n",
        path.to_string_lossy(),
        cleanup.as_str(),
    )
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
        assert!(visible.contains("version: 4"));
        assert!(visible.contains("crypto:"));
        assert!(visible.contains("wrapped_profile_key:"));
        assert!(visible.contains("salt_base64:"));
        assert!(visible.contains("nonce_base64:"));
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
            crypto: None,
            wrapped_profile_key: None,
            entries: BTreeMap::from([(
                "SECRET".to_string(),
                VisibleVaultValue::PlainText {
                    enc_base64: STANDARD.encode(ciphertext),
                    nonce_base64: None,
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
            crypto: None,
            wrapped_profile_key: None,
            entries: BTreeMap::from([
                (
                    "SECRET".to_string(),
                    VisibleVaultValue::PlainText {
                        enc_base64: original_secret_ciphertext.clone(),
                        nonce_base64: None,
                    },
                ),
                (
                    "CONFIG".to_string(),
                    VisibleVaultValue::PlainText {
                        enc_base64: STANDARD.encode(encrypt_env(b"old", password.clone()).unwrap()),
                        nonce_base64: None,
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
                nonce_base64: None,
            })
        );
        assert_eq!(saved.version, 4);
        assert!(saved.crypto.is_some());
        assert!(saved.wrapped_profile_key.is_some());

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
    fn visible_aes_entries_authenticate_file_metadata() {
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

        let mut vault = VaultDocument::default();
        vault
            .set_file_content(
                "TLS_KEY",
                PathBuf::from(".runvault/tls/key.pem"),
                b"top-secret".to_vec(),
                0o600,
                FileCleanup::Keep,
            )
            .unwrap();
        save_vault_with_password(&profile, &profile_path, &vault, password.clone()).unwrap();

        let mut saved: VisibleVaultDocument =
            serde_yaml::from_str(&std::fs::read_to_string(&env_path).unwrap()).unwrap();
        match saved.entries.get_mut("TLS_KEY").unwrap() {
            VisibleVaultValue::FileContent { path, .. } => {
                *path = PathBuf::from(".runvault/tls/other.pem");
            }
            _ => panic!("expected file-backed visible value"),
        }
        std::fs::write(&env_path, serde_yaml::to_string(&saved).unwrap()).unwrap();

        let err = load_vault_with_password(&profile, &profile_path, password).unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }

    #[test]
    fn delete_requires_existing_key() {
        let mut vault = VaultDocument::default();
        let err = vault.delete("MISSING").unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }
}

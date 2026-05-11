use age::{
    Decryptor, Encryptor,
    armor::{ArmoredReader, ArmoredWriter, Format},
    scrypt,
    secrecy::{ExposeSecret, SecretString},
};
use openssl::pkey::PKey;
use pbkdf2::pbkdf2_hmac_array;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::Sha256;
use std::{
    io::{Cursor, Read, Write},
    iter,
};
use zeroize::Zeroizing;

use crate::error::Error;

pub const DEFAULT_VAULT_PBKDF2_ROUNDS: u32 = 100_000;
pub const VAULT_KDF_SALT_LEN: usize = 16;
pub const VAULT_NONCE_LEN: usize = 12;
const ENCRYPTED_FILE_MAGIC: &[u8] = b"RUNVAULT-ENC-FILE\n";
const ENCRYPTED_PRIVATE_KEY_PEM_MAGIC: &[u8] = b"-----BEGIN ENCRYPTED PRIVATE KEY-----";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultCryptoConfig {
    pub salt: [u8; VAULT_KDF_SALT_LEN],
    pub pbkdf2_rounds: u32,
}

#[derive(Debug)]
pub struct VaultCipher {
    key: LessSafeKey,
}

impl VaultCryptoConfig {
    pub fn generate() -> Self {
        Self {
            salt: rand::random(),
            pbkdf2_rounds: DEFAULT_VAULT_PBKDF2_ROUNDS,
        }
    }
}

impl VaultCipher {
    pub fn derive(password: &SecretString, config: &VaultCryptoConfig) -> Result<Self, Error> {
        let key_bytes = pbkdf2_hmac_array::<Sha256, 32>(
            password.expose_secret().as_bytes(),
            &config.salt,
            config.pbkdf2_rounds,
        );
        let key = UnboundKey::new(&AES_256_GCM, &key_bytes)
            .map_err(|_| Error::Encryption("failed to initialize AES-256-GCM key".to_string()))?;
        Ok(Self {
            key: LessSafeKey::new(key),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedPayload, Error> {
        let nonce_bytes: [u8; VAULT_NONCE_LEN] = rand::random();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| Error::Encryption("AES-256-GCM seal failed".to_string()))?;
        in_out.extend_from_slice(tag.as_ref());
        Ok(EncryptedPayload {
            nonce: nonce_bytes,
            ciphertext: in_out,
        })
    }

    pub fn decrypt(
        &self,
        payload: &EncryptedPayload,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let nonce = Nonce::assume_unique_for_key(payload.nonce);
        let mut in_out = payload.ciphertext.clone();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| Error::Decryption("AES-256-GCM open failed".to_string()))?;
        Ok(Zeroizing::new(plaintext.to_vec()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub nonce: [u8; VAULT_NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_env(plaintext: &[u8], password: SecretString) -> Result<Vec<u8>, Error> {
    let encryptor = Encryptor::with_user_passphrase(password);
    let mut output = Vec::new();
    let armor = ArmoredWriter::wrap_output(&mut output, Format::AsciiArmor)
        .map_err(|err| Error::Encryption(err.to_string()))?;
    let mut writer = encryptor
        .wrap_output(armor)
        .map_err(|err| Error::Encryption(err.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|err| Error::Encryption(err.to_string()))?;
    writer
        .finish()
        .map_err(|err| Error::Encryption(err.to_string()))?
        .finish()
        .map_err(|err| Error::Encryption(err.to_string()))?;
    Ok(output)
}

pub fn decrypt_env(ciphertext: &[u8], password: SecretString) -> Result<Zeroizing<Vec<u8>>, Error> {
    let input = ArmoredReader::new(Cursor::new(ciphertext));
    let decryptor = Decryptor::new(input).map_err(|err| Error::Decryption(err.to_string()))?;
    let identity = scrypt::Identity::new(password);
    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .map_err(|err| Error::Decryption(err.to_string()))?;

    let mut output = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut output)
        .map_err(|err| Error::Decryption(err.to_string()))?;
    Ok(output)
}

pub fn encrypt_file_payload(plaintext: &[u8], password: SecretString) -> Result<Vec<u8>, Error> {
    let encrypted = encrypt_env(plaintext, password)?;
    let mut output = Vec::with_capacity(ENCRYPTED_FILE_MAGIC.len() + encrypted.len());
    output.extend_from_slice(ENCRYPTED_FILE_MAGIC);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

pub fn is_encrypted_file_payload(input: &[u8]) -> bool {
    input.starts_with(ENCRYPTED_FILE_MAGIC)
}

pub fn is_encrypted_private_key_pem(input: &[u8]) -> bool {
    input.starts_with(ENCRYPTED_PRIVATE_KEY_PEM_MAGIC)
}

pub fn decrypt_file_payload(
    ciphertext: &[u8],
    password: SecretString,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !is_encrypted_file_payload(ciphertext) {
        return Err(Error::Decryption(
            "missing runvault encrypted file header".to_string(),
        ));
    }
    decrypt_env(&ciphertext[ENCRYPTED_FILE_MAGIC.len()..], password)
}

pub fn maybe_decrypt_file_payload(
    input: &[u8],
    password: SecretString,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if is_encrypted_file_payload(input) {
        decrypt_file_payload(input, password)
    } else if is_encrypted_private_key_pem(input) {
        let key = PKey::private_key_from_pem_passphrase(input, password.expose_secret().as_bytes())
            .map_err(|err| Error::Decryption(err.to_string()))?;
        let pem = key
            .private_key_to_pem_pkcs8()
            .map_err(|err| Error::Decryption(err.to_string()))?;
        Ok(Zeroizing::new(pem))
    } else {
        Ok(Zeroizing::new(input.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_VAULT_PBKDF2_ROUNDS, EncryptedPayload, VAULT_KDF_SALT_LEN, VaultCipher,
        VaultCryptoConfig, decrypt_env, decrypt_file_payload, encrypt_env, encrypt_file_payload,
        is_encrypted_file_payload, is_encrypted_private_key_pem, maybe_decrypt_file_payload,
    };
    use age::secrecy::{ExposeSecret, SecretString};
    use openssl::{pkey::PKey, rsa::Rsa, symm::Cipher};

    #[test]
    fn round_trips_plaintext() {
        let plaintext = b"API_KEY=test\nNAME=\"hello\"";
        let password = SecretString::from("correct horse battery staple".to_string());
        let encrypted = encrypt_env(plaintext, password.clone()).unwrap();
        let decrypted = decrypt_env(&encrypted, password).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn rejects_wrong_password() {
        let encrypted = encrypt_env(
            b"API_KEY=test",
            SecretString::from("correct horse battery staple".to_string()),
        )
        .unwrap();

        let err = decrypt_env(&encrypted, SecretString::from("wrong".to_string())).unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }

    #[test]
    fn rejects_invalid_ciphertext() {
        let err = decrypt_env(
            b"not an age file",
            SecretString::from("correct horse battery staple".to_string()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }

    #[test]
    fn encrypted_file_payload_round_trips() {
        let plaintext = b"secret";
        let password = SecretString::from("correct horse battery staple".to_string());
        let encrypted = encrypt_file_payload(plaintext, password.clone()).unwrap();
        assert!(is_encrypted_file_payload(&encrypted));
        let decrypted = decrypt_file_payload(&encrypted, password).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn maybe_decrypt_file_payload_passes_through_plain_bytes() {
        let plaintext = b"plain";
        let password = SecretString::from("correct horse battery staple".to_string());
        let decrypted = maybe_decrypt_file_payload(plaintext, password).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn maybe_decrypt_file_payload_decrypts_standard_private_key_pem() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let password = SecretString::from("correct horse battery staple".to_string());
        let encrypted = key
            .private_key_to_pem_pkcs8_passphrase(
                Cipher::aes_256_cbc(),
                password.expose_secret().as_bytes(),
            )
            .unwrap();
        assert!(is_encrypted_private_key_pem(&encrypted));
        let decrypted = maybe_decrypt_file_payload(&encrypted, password).unwrap();
        assert!(String::from_utf8_lossy(&decrypted).contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn vault_cipher_round_trips_with_aad() {
        let config = VaultCryptoConfig {
            salt: [7; VAULT_KDF_SALT_LEN],
            pbkdf2_rounds: DEFAULT_VAULT_PBKDF2_ROUNDS,
        };
        let cipher = VaultCipher::derive(
            &SecretString::from("correct horse battery staple".to_string()),
            &config,
        )
        .unwrap();

        let encrypted = cipher
            .encrypt(b"top-secret", b"kind=plain_text\nkey=SECRET\n")
            .unwrap();
        let decrypted = cipher
            .decrypt(&encrypted, b"kind=plain_text\nkey=SECRET\n")
            .unwrap();
        assert_eq!(&*decrypted, b"top-secret");
    }

    #[test]
    fn vault_cipher_rejects_modified_aad() {
        let config = VaultCryptoConfig {
            salt: [9; VAULT_KDF_SALT_LEN],
            pbkdf2_rounds: DEFAULT_VAULT_PBKDF2_ROUNDS,
        };
        let cipher =
            VaultCipher::derive(&SecretString::from("password".to_string()), &config).unwrap();
        let encrypted = cipher
            .encrypt(b"top-secret", b"kind=plain_text\nkey=SECRET\n")
            .unwrap();

        let err = cipher
            .decrypt(
                &EncryptedPayload {
                    nonce: encrypted.nonce,
                    ciphertext: encrypted.ciphertext,
                },
                b"kind=plain_text\nkey=OTHER\n",
            )
            .unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }
}

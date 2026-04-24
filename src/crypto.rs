use age::{
    Decryptor, Encryptor,
    armor::{ArmoredReader, ArmoredWriter, Format},
    scrypt,
    secrecy::SecretString,
};
use std::{
    io::{Cursor, Read, Write},
    iter,
};
use zeroize::Zeroizing;

use crate::error::Error;

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

#[cfg(test)]
mod tests {
    use super::{decrypt_env, encrypt_env};
    use age::secrecy::SecretString;

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
}

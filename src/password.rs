use age::secrecy::SecretString;
use rpassword::prompt_password;

use crate::error::Error;

pub fn prompt_password_confirm() -> Result<SecretString, Error> {
    let password = prompt_password("Password: ").map_err(Error::PasswordPrompt)?;
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    let confirm = prompt_password("Confirm password: ").map_err(Error::PasswordPrompt)?;
    if password != confirm {
        return Err(Error::PasswordMismatch);
    }
    Ok(SecretString::from(password))
}

pub fn prompt_password_once() -> Result<SecretString, Error> {
    let password = prompt_password("Password: ").map_err(Error::PasswordPrompt)?;
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    Ok(SecretString::from(password))
}

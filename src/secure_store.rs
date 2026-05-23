use std::path::Path;
#[cfg(any(test, target_os = "macos"))]
use std::path::{Component, PathBuf};
#[cfg(target_os = "macos")]
use std::{env, process::Command};

#[cfg(target_os = "macos")]
use age::secrecy::ExposeSecret;
use age::secrecy::SecretString;

use crate::error::Error;

#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "runvault";

pub fn load_password(profile_path: &Path) -> Result<Option<SecretString>, Error> {
    #[cfg(target_os = "macos")]
    {
        let account = store_key(profile_path)?;
        let output = Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                &account,
                "-w",
            ])
            .output()
            .map_err(|err| Error::SecureStore(err.to_string()))?;
        if output.status.success() {
            let password = String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_string();
            if password.is_empty() {
                return Ok(None);
            }
            return Ok(Some(SecretString::from(password)));
        }
        return Ok(None);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = profile_path;
        Ok(None)
    }
}

pub fn store_password(profile_path: &Path, password: &SecretString) -> Result<(), Error> {
    #[cfg(target_os = "macos")]
    {
        let account = store_key(profile_path)?;
        let output = Command::new("security")
            .args([
                "add-generic-password",
                "-U",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                &account,
                "-w",
                password.expose_secret(),
            ])
            .output()
            .map_err(|err| Error::SecureStore(err.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let details = if stderr.is_empty() {
                format!("status {}", output.status)
            } else {
                format!("status {}; {}", output.status, stderr)
            };
            return Err(Error::SecureStore(format!(
                "security add-generic-password failed with {details}"
            )));
        }
        return Ok(());
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (profile_path, password);
        Ok(())
    }
}

pub fn store_password_if_possible(
    profile_path: &Path,
    password: &SecretString,
) -> Result<(), Error> {
    match store_password(profile_path, password) {
        Ok(()) => Ok(()),
        Err(Error::SecureStore(message)) if is_noninteractive_keychain_error(&message) => Ok(()),
        Err(err) => Err(err),
    }
}

pub fn clear_password(profile_path: &Path) -> Result<(), Error> {
    #[cfg(target_os = "macos")]
    {
        let account = store_key(profile_path)?;
        let status = Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                &account,
            ])
            .status()
            .map_err(|err| Error::SecureStore(err.to_string()))?;
        if status.success() {
            return Ok(());
        }
        return Ok(());
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = profile_path;
        Ok(())
    }
}

pub fn clear_all_passwords() -> Result<(), Error> {
    #[cfg(target_os = "macos")]
    {
        return Err(Error::SecureStore(
            "clearing all keychain-backed runvault entries at once is not supported; specify a profile".to_string(),
        ));
    }

    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

#[cfg(any(test, target_os = "macos"))]
fn store_key(profile_path: &Path) -> Result<String, Error> {
    let absolute = if profile_path.exists() {
        profile_path.canonicalize().map_err(Error::PasswordPrompt)?
    } else if profile_path.is_absolute() {
        normalize_pathbuf(profile_path.to_path_buf())
    } else {
        normalize_pathbuf(
            env::current_dir()
                .map_err(Error::PasswordPrompt)?
                .join(profile_path),
        )
    };
    Ok(format!("profile:{}", normalize_path(&absolute)))
}

#[cfg(any(test, target_os = "macos"))]
fn normalize_path(path: &PathBuf) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(any(test, target_os = "macos"))]
fn normalize_pathbuf(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn is_noninteractive_keychain_error(message: &str) -> bool {
    message.contains("User interaction is not allowed") || message.contains("exit status: 36")
}

#[cfg(test)]
mod tests {
    use super::store_key;
    use std::env;

    #[test]
    fn store_key_is_stable() {
        let key = store_key(std::path::Path::new("/tmp/demo/runvault.yaml")).unwrap();
        assert_eq!(key, "profile:/tmp/demo/runvault.yaml");
    }

    #[test]
    fn store_key_normalizes_relative_profile_paths() {
        let cwd = env::current_dir().unwrap();
        let expected = cwd.join(".vault/runvault.yaml");
        let key = store_key(std::path::Path::new("./service/../.vault/./runvault.yaml")).unwrap();
        assert_eq!(key, format!("profile:{}", expected.to_string_lossy()));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_secure_store_is_noop() {
        let path = std::path::Path::new("/tmp/demo/runvault.yaml");
        let password = age::secrecy::SecretString::from("secret".to_string());
        super::store_password(path, &password).unwrap();
        assert!(super::load_password(path).unwrap().is_none());
        super::clear_password(path).unwrap();
        super::clear_all_passwords().unwrap();
    }
}

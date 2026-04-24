use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse profile {path}: {source}")]
    ProfileParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("failed to read password: {0}")]
    PasswordPrompt(#[source] std::io::Error),
    #[error("password confirmation does not match")]
    PasswordMismatch,
    #[error("password must not be empty")]
    EmptyPassword,
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("invalid env file: {0}")]
    EnvParse(String),
    #[error("profile is invalid: {0}")]
    InvalidProfile(String),
    #[error("http ping failed: {0}")]
    HttpPing(String),
    #[error("command exited before health checks passed")]
    ChildExitedEarly,
    #[error("command failed with status {0}")]
    CommandFailed(String),
}

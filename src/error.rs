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
    #[error("refusing to overwrite existing path {0}")]
    AlreadyExists(PathBuf),
    #[error("failed to parse profile {path}: {source}")]
    ProfileParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("failed to parse file import spec {path}: {source}")]
    ImportSpecParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("failed to parse bundle {path}: {source}")]
    BundleParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("failed to serialize profile: {0}")]
    ProfileSerialize(String),
    #[error("failed to serialize bundle: {0}")]
    BundleSerialize(String),
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
    #[error("file import spec is invalid: {0}")]
    InvalidImportSpec(String),
    #[error("invalid config key '{0}'")]
    InvalidConfigKey(String),
    #[error("config key '{0}' does not exist")]
    MissingConfigKey(String),
    #[error("vault payload is invalid: {0}")]
    VaultFormat(String),
    #[error("failed to serialize vault payload: {0}")]
    VaultSerialize(String),
    #[error("failed to decode stored file payload for key '{key}': {source}")]
    FileContentDecode {
        key: String,
        #[source]
        source: base64::DecodeError,
    },
    #[error("failed to decode stored encrypted payload for key '{key}': {source}")]
    EntryCiphertextDecode {
        key: String,
        #[source]
        source: base64::DecodeError,
    },
    #[error("file-backed values require --to-file")]
    MissingValuePath,
    #[error("file source {path} is not valid utf-8 and cannot be stored as a plain env value")]
    FileSourceNotUtf8 { path: PathBuf },
    #[error("invalid file mode '{value}', expected octal like 0600")]
    InvalidFileMode { value: String },
    #[error("invalid duration '{value}', expected a number with optional suffix s, m, h, or d")]
    InvalidDuration { value: String },
    #[error("invalid JWT claim '{value}', expected KEY=VALUE")]
    InvalidJwtClaim { value: String },
    #[error("custom JWT claim '{key}' conflicts with a reserved claim")]
    ReservedJwtClaim { key: String },
    #[error("config key '{key}' must be a plain-text value for JWT generation")]
    JwtSecretMustBePlainText { key: String },
    #[error("failed to generate JWT signing secret: {0}")]
    JwtSecretGeneration(String),
    #[error("JWT generation failed: {0}")]
    Jwt(String),
    #[error("secure store error: {0}")]
    SecureStore(String),
    #[error("http ping failed: {0}")]
    HttpPing(String),
    #[error("command exited before health checks passed")]
    ChildExitedEarly,
    #[error("runtime file path already exists: {0}")]
    RuntimeFilePathExists(PathBuf),
    #[error("bundle is invalid: {0}")]
    InvalidBundle(String),
    #[error("command failed with status {0}")]
    CommandFailed(String),
}

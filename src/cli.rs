use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::profile::DEFAULT_PROFILE_DIR;

#[derive(Debug, Parser)]
#[command(name = "runvault", version, about = "Encrypted env launcher")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    CreateProfile(CreateProfileArgs),
    Cache(CacheCommand),
    Encrypt(EncryptArgs),
    Jwt(JwtArgs),
    Set(SetArgs),
    Import(ImportArgs),
    ImportFiles(ImportFilesArgs),
    Delete(DeleteArgs),
    Reveal(RevealArgs),
    Run(ProfileArgs),
    Ping(PingCommand),
}

#[derive(Debug, Args)]
pub struct CacheCommand {
    #[command(subcommand)]
    pub command: CacheSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum CacheSubcommand {
    Clear(CacheClearArgs),
}

#[derive(Debug, Args)]
pub struct CacheClearArgs {
    pub profile: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct CreateProfileArgs {
    pub profile: Option<PathBuf>,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long = "env-file", default_value = "env.sec")]
    pub env_file: PathBuf,
}

#[derive(Debug, Args)]
pub struct EncryptArgs {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct JwtArgs {
    #[arg(value_name = "PROFILE_OR_KEY", num_args = 1..=2)]
    pub targets: Vec<String>,
    #[arg(long = "signing-key", value_name = "KEY")]
    pub signing_key: Option<String>,
    #[arg(long)]
    pub issuer: Option<String>,
    #[arg(long)]
    pub audience: Option<String>,
    #[arg(long)]
    pub subject: Option<String>,
    #[arg(long, default_value = "1h")]
    pub ttl: String,
    #[arg(long = "claim", value_name = "KEY=VALUE")]
    pub claims: Vec<String>,
    #[arg(long = "file", alias = "output", value_name = "PATH")]
    pub file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SetArgs {
    #[arg(value_name = "PROFILE_OR_KEY", num_args = 1..=2)]
    pub targets: Vec<String>,
    #[arg(
        long,
        conflicts_with = "from_file",
        required_unless_present = "from_file"
    )]
    pub value: Option<String>,
    #[arg(
        long = "from-file",
        value_name = "PATH",
        conflicts_with = "value",
        required_unless_present = "value"
    )]
    pub from_file: Option<PathBuf>,
    #[arg(long = "to-file", alias = "value-path", value_name = "PATH")]
    pub to_file: Option<PathBuf>,
    #[arg(long, value_name = "MODE", requires = "to_file")]
    pub mode: Option<String>,
    #[arg(long, requires = "to_file")]
    pub keep: bool,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    #[arg(value_name = "PROFILE_OR_INPUT", num_args = 1..)]
    pub targets: Vec<PathBuf>,
    #[arg(long)]
    pub prefix: Option<String>,
}

#[derive(Debug, Args)]
pub struct ImportFilesArgs {
    #[arg(value_name = "PROFILE_OR_INPUT", num_args = 1..)]
    pub targets: Vec<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    #[arg(value_name = "PROFILE_OR_KEY", num_args = 1..=2)]
    pub targets: Vec<String>,
}

#[derive(Debug, Args)]
pub struct RevealArgs {
    #[arg(value_name = "PROFILE_OR_KEY", num_args = 1..=2)]
    pub targets: Vec<String>,
    #[arg(long)]
    pub raw: bool,
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ProfileArgs {
    pub profile: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct PingCommand {
    #[command(subcommand)]
    pub command: Option<PingSubcommand>,
    pub profile: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum PingSubcommand {
    Add(PingAddArgs),
}

#[derive(Debug, Args)]
pub struct PingAddArgs {
    #[arg(value_name = "PROFILE_OR_NAME_OR_URL", num_args = 2..=3)]
    pub targets: Vec<String>,
    #[arg(long, default_value_t = 30)]
    pub timeout_seconds: u64,
    #[arg(long, default_value_t = 500)]
    pub interval_millis: u64,
}

impl CacheClearArgs {
    pub fn profile_or_default(&self) -> PathBuf {
        self.profile
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR))
    }
}

impl CreateProfileArgs {
    pub fn profile_or_default(&self) -> PathBuf {
        self.profile
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR))
    }
}

impl SetArgs {
    pub fn resolve(&self) -> (PathBuf, String) {
        match self.targets.as_slice() {
            [key] => (PathBuf::from(DEFAULT_PROFILE_DIR), key.clone()),
            [profile, key] => (PathBuf::from(profile), key.clone()),
            _ => unreachable!("clap enforces set target arity"),
        }
    }
}

impl JwtArgs {
    pub fn resolve(&self) -> (PathBuf, String) {
        match self.targets.as_slice() {
            [key] => (PathBuf::from(DEFAULT_PROFILE_DIR), key.clone()),
            [profile, key] => (PathBuf::from(profile), key.clone()),
            _ => unreachable!("clap enforces jwt target arity"),
        }
    }
}

impl ImportArgs {
    pub fn resolve(&self) -> (PathBuf, Vec<PathBuf>) {
        match self.targets.as_slice() {
            [input] => (PathBuf::from(DEFAULT_PROFILE_DIR), vec![input.clone()]),
            [first, rest @ ..] if looks_like_profile_path(first) => (first.clone(), rest.to_vec()),
            inputs => (PathBuf::from(DEFAULT_PROFILE_DIR), inputs.to_vec()),
        }
    }
}

impl ImportFilesArgs {
    pub fn resolve(&self) -> (PathBuf, Vec<PathBuf>) {
        match self.targets.as_slice() {
            [input] => (PathBuf::from(DEFAULT_PROFILE_DIR), vec![input.clone()]),
            [first, rest @ ..] if looks_like_profile_path(first) => (first.clone(), rest.to_vec()),
            inputs => (PathBuf::from(DEFAULT_PROFILE_DIR), inputs.to_vec()),
        }
    }
}

impl DeleteArgs {
    pub fn resolve(&self) -> (PathBuf, String) {
        match self.targets.as_slice() {
            [key] => (PathBuf::from(DEFAULT_PROFILE_DIR), key.clone()),
            [profile, key] => (PathBuf::from(profile), key.clone()),
            _ => unreachable!("clap enforces delete target arity"),
        }
    }
}

impl RevealArgs {
    pub fn resolve(&self) -> (PathBuf, String) {
        match self.targets.as_slice() {
            [key] => (PathBuf::from(DEFAULT_PROFILE_DIR), key.clone()),
            [profile, key] => (PathBuf::from(profile), key.clone()),
            _ => unreachable!("clap enforces reveal target arity"),
        }
    }
}

impl ProfileArgs {
    pub fn profile_or_default(&self) -> PathBuf {
        self.profile
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR))
    }
}

impl PingCommand {
    pub fn profile_or_default(&self) -> PathBuf {
        self.profile
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR))
    }
}

impl PingAddArgs {
    pub fn resolve(&self) -> (PathBuf, String, String) {
        match self.targets.as_slice() {
            [name, url] => (
                PathBuf::from(DEFAULT_PROFILE_DIR),
                name.clone(),
                url.clone(),
            ),
            [profile, name, url] => (PathBuf::from(profile), name.clone(), url.clone()),
            _ => unreachable!("clap enforces ping add target arity"),
        }
    }
}

fn looks_like_profile_path(path: &PathBuf) -> bool {
    if path.file_name().is_some_and(|name| name == "runvault.yaml") {
        return true;
    }

    path.join("runvault.yaml").exists()
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command, DEFAULT_PROFILE_DIR, PingSubcommand};
    use clap::Parser;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn import_defaults_to_dot_vault_for_multiple_inputs() {
        let cli = Cli::try_parse_from(["runvault", "import", ".env", ".env.local"]).unwrap();

        let Command::Import(args) = cli.command else {
            panic!("expected import command");
        };

        let (profile, inputs) = args.resolve();
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(
            inputs,
            vec![PathBuf::from(".env"), PathBuf::from(".env.local")]
        );
    }

    #[test]
    fn jwt_defaults_to_dot_vault_for_output_key() {
        let cli = Cli::try_parse_from(["runvault", "jwt", "TEMPO_INGEST_TOKEN"]).unwrap();

        let Command::Jwt(args) = cli.command else {
            panic!("expected jwt command");
        };

        let (profile, key) = args.resolve();
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(key, "TEMPO_INGEST_TOKEN");
    }

    #[test]
    fn ping_add_defaults_to_dot_vault_for_name_and_url() {
        let cli = Cli::try_parse_from([
            "runvault",
            "ping",
            "add",
            "api",
            "http://127.0.0.1:8080/health",
        ])
        .unwrap();

        let Command::Ping(args) = cli.command else {
            panic!("expected ping command");
        };
        let Some(PingSubcommand::Add(add)) = args.command else {
            panic!("expected ping add subcommand");
        };

        let (profile, name, url) = add.resolve();
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(name, "api");
        assert_eq!(url, "http://127.0.0.1:8080/health");
        assert_eq!(add.timeout_seconds, 30);
        assert_eq!(add.interval_millis, 500);
    }

    #[test]
    fn import_uses_explicit_profile_when_runvault_yaml_exists() {
        let profile_dir = unique_temp_dir("runvault-cli-import-profile");
        fs::create_dir_all(&profile_dir).unwrap();
        fs::write(
            profile_dir.join("runvault.yaml"),
            "name: test\nrun:\n  cmd: [\"true\"]\n",
        )
        .unwrap();

        let cli = Cli::try_parse_from([
            "runvault",
            "import",
            profile_dir.to_str().unwrap(),
            ".env",
            ".env.local",
        ])
        .unwrap();

        let Command::Import(args) = cli.command else {
            panic!("expected import command");
        };

        let (profile, inputs) = args.resolve();
        assert_eq!(profile, profile_dir);
        assert_eq!(
            inputs,
            vec![PathBuf::from(".env"), PathBuf::from(".env.local")]
        );
    }

    #[test]
    fn import_files_defaults_to_dot_vault_for_multiple_specs() {
        let cli = Cli::try_parse_from(["runvault", "import-files", "files-a.yaml", "files-b.yaml"])
            .unwrap();

        let Command::ImportFiles(args) = cli.command else {
            panic!("expected import-files command");
        };

        let (profile, inputs) = args.resolve();
        assert_eq!(profile, PathBuf::from(DEFAULT_PROFILE_DIR));
        assert_eq!(
            inputs,
            vec![PathBuf::from("files-a.yaml"), PathBuf::from("files-b.yaml")]
        );
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("{prefix}-{nanos}"));
        path
    }
}

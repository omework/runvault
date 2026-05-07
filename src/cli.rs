use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

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
    Set(SetArgs),
    Import(ImportArgs),
    ImportFiles(ImportFilesArgs),
    Delete(DeleteArgs),
    Reveal(RevealArgs),
    Run(ProfileArgs),
    Ping(ProfileArgs),
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
    pub profile: PathBuf,
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
pub struct SetArgs {
    pub profile: PathBuf,
    pub key: String,
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
    pub profile: PathBuf,
    pub input: PathBuf,
    #[arg(long)]
    pub prefix: Option<String>,
}

#[derive(Debug, Args)]
pub struct ImportFilesArgs {
    pub profile: PathBuf,
    pub input: PathBuf,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    pub profile: PathBuf,
    pub key: String,
}

#[derive(Debug, Args)]
pub struct RevealArgs {
    pub profile: PathBuf,
    pub key: String,
    #[arg(long)]
    pub raw: bool,
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ProfileArgs {
    pub profile: PathBuf,
}

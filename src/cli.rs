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
    Encrypt(EncryptArgs),
    Set(SetArgs),
    Import(ImportArgs),
    Delete(DeleteArgs),
    Run(ProfileArgs),
    Ping(ProfileArgs),
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
    #[arg(long = "value-path", value_name = "PATH", requires = "from_file")]
    pub value_path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    pub profile: PathBuf,
    pub input: PathBuf,
    #[arg(long)]
    pub prefix: Option<String>,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    pub profile: PathBuf,
    pub key: String,
}

#[derive(Debug, Args)]
pub struct ProfileArgs {
    pub profile: PathBuf,
}

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
    Run(ProfileArgs),
    Ping(ProfileArgs),
}

#[derive(Debug, Args)]
pub struct EncryptArgs {
    #[arg(long)]
    pub input: PathBuf,
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ProfileArgs {
    #[arg(long)]
    pub profile: PathBuf,
}

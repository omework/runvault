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
    #[arg(value_name = "PROFILE_OR_INPUT", num_args = 1..=2)]
    pub targets: Vec<PathBuf>,
    #[arg(long)]
    pub prefix: Option<String>,
}

#[derive(Debug, Args)]
pub struct ImportFilesArgs {
    #[arg(value_name = "PROFILE_OR_INPUT", num_args = 1..=2)]
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

impl ImportArgs {
    pub fn resolve(&self) -> (PathBuf, PathBuf) {
        match self.targets.as_slice() {
            [input] => (PathBuf::from(DEFAULT_PROFILE_DIR), input.clone()),
            [profile, input] => (profile.clone(), input.clone()),
            _ => unreachable!("clap enforces import target arity"),
        }
    }
}

impl ImportFilesArgs {
    pub fn resolve(&self) -> (PathBuf, PathBuf) {
        match self.targets.as_slice() {
            [input] => (PathBuf::from(DEFAULT_PROFILE_DIR), input.clone()),
            [profile, input] => (profile.clone(), input.clone()),
            _ => unreachable!("clap enforces import-files target arity"),
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

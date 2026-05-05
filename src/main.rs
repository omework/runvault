use clap::Parser;
use runvault::{
    cli::{Cli, Command},
    crypto::encrypt_env,
    error::Error,
    password::{prompt_password_confirm, prompt_password_once},
    profile::Profile,
    run::{ping_profile, run_profile},
    vault::{VaultDocument, load_vault_with_password, save_vault_with_password},
};
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Error> {
    let cli = Cli::parse();
    match cli.command {
        Command::Encrypt(args) => {
            let input = std::fs::read(&args.input).map_err(|source| Error::ReadFile {
                path: args.input.clone(),
                source,
            })?;
            let output_path = args
                .output
                .unwrap_or_else(|| default_encrypted_path(&args.input));
            let password = prompt_password_confirm()?;
            let encrypted = encrypt_env(&input, password)?;
            std::fs::write(&output_path, encrypted).map_err(|source| Error::WriteFile {
                path: output_path,
                source,
            })?;
            Ok(())
        }
        Command::Set(args) => {
            let profile = Profile::from_path(&args.profile)?;
            let env_path = profile.resolve_env_path(&args.profile);
            let (mut vault, password) = if env_path.exists() {
                let password = prompt_password_once()?;
                let vault = load_vault_with_password(&profile, &args.profile, password.clone())?;
                (vault, password)
            } else {
                (VaultDocument::default(), prompt_password_confirm()?)
            };

            match (args.value, args.from_file, args.value_path) {
                (Some(value), None, None) => vault.set_plain_text(&args.key, value)?,
                (None, Some(source_path), Some(runtime_path)) => {
                    let content =
                        std::fs::read(&source_path).map_err(|source| Error::ReadFile {
                            path: source_path,
                            source,
                        })?;
                    vault.set_file_content(&args.key, runtime_path, content)?;
                }
                (None, Some(_), None) => return Err(Error::MissingValuePath),
                _ => unreachable!("clap enforces set arguments"),
            }

            save_vault_with_password(&profile, &args.profile, &vault, password)
        }
        Command::Delete(args) => {
            let profile = Profile::from_path(&args.profile)?;
            let password = prompt_password_once()?;
            let mut vault = load_vault_with_password(&profile, &args.profile, password.clone())?;
            vault.delete(&args.key)?;
            save_vault_with_password(&profile, &args.profile, &vault, password)
        }
        Command::Run(args) => run_profile(&args.profile).await,
        Command::Ping(args) => ping_profile(&args.profile).await,
    }
}

fn default_encrypted_path(input: &PathBuf) -> PathBuf {
    if let Some(file_name) = input.file_name().and_then(|value| value.to_str()) {
        return input.with_file_name(format!("{}.enc", file_name));
    }
    input.with_extension("enc")
}

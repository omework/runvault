use clap::Parser;
use runvault::{
    cli::{Cli, Command},
    crypto::encrypt_env,
    envfile::{apply_prefix, parse_env_bytes},
    error::Error,
    password::{prompt_password_confirm, prompt_password_once},
    profile::{CreateProfileOptions, Profile, create_profile, resolve_profile_path},
    run::{ping_profile, run_profile},
    vault::{
        FileCleanup, VaultDocument, VaultValue, load_vault_with_password, save_vault_with_password,
    },
};
use std::{io::Write, path::PathBuf};

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
        Command::CreateProfile(args) => {
            let created = create_profile(
                &args.profile,
                &CreateProfileOptions {
                    name: args.name,
                    env_file: args.env_file,
                },
            )?;
            println!("{}", created.display());
            Ok(())
        }
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
            let profile_path = resolve_profile_path(&args.profile);
            let profile = Profile::from_path(&profile_path)?;
            let env_path = profile.resolve_env_path(&profile_path);
            let (mut vault, password) = if env_path.exists() {
                let password = prompt_password_once()?;
                let vault = load_vault_with_password(&profile, &profile_path, password.clone())?;
                (vault, password)
            } else {
                (VaultDocument::default(), prompt_password_confirm()?)
            };

            let mode = args
                .mode
                .as_deref()
                .map(parse_file_mode)
                .transpose()?
                .unwrap_or(0o600);
            let cleanup = if args.keep {
                FileCleanup::Keep
            } else {
                FileCleanup::OnExit
            };

            match (args.value, args.from_file, args.to_file) {
                (Some(value), None, None) => vault.set_plain_text(&args.key, value)?,
                (Some(value), None, Some(runtime_path)) => vault.set_file_content(
                    &args.key,
                    runtime_path,
                    value.into_bytes(),
                    mode,
                    cleanup,
                )?,
                (None, Some(source_path), None) => {
                    let content =
                        std::fs::read(&source_path).map_err(|source| Error::ReadFile {
                            path: source_path.clone(),
                            source,
                        })?;
                    let value = String::from_utf8(content)
                        .map_err(|_| Error::FileSourceNotUtf8 { path: source_path })?;
                    vault.set_plain_text(&args.key, value)?;
                }
                (None, Some(source_path), Some(runtime_path)) => {
                    let content =
                        std::fs::read(&source_path).map_err(|source| Error::ReadFile {
                            path: source_path,
                            source,
                        })?;
                    vault.set_file_content(&args.key, runtime_path, content, mode, cleanup)?;
                }
                _ => unreachable!("clap enforces set arguments"),
            }

            save_vault_with_password(&profile, &profile_path, &vault, password)
        }
        Command::Import(args) => {
            let profile_path = resolve_profile_path(&args.profile);
            let profile = Profile::from_path(&profile_path)?;
            let env_path = profile.resolve_env_path(&profile_path);
            let (mut vault, password) = if env_path.exists() {
                let password = prompt_password_once()?;
                let vault = load_vault_with_password(&profile, &profile_path, password.clone())?;
                (vault, password)
            } else {
                (VaultDocument::default(), prompt_password_confirm()?)
            };

            let input = std::fs::read(&args.input).map_err(|source| Error::ReadFile {
                path: args.input.clone(),
                source,
            })?;
            let vars = parse_env_bytes(&input)?;
            let vars = apply_prefix(vars, args.prefix.as_deref().unwrap_or(""))?;
            for (key, value) in vars {
                vault.set_plain_text(&key, value)?;
            }

            save_vault_with_password(&profile, &profile_path, &vault, password)
        }
        Command::Delete(args) => {
            let profile_path = resolve_profile_path(&args.profile);
            let profile = Profile::from_path(&profile_path)?;
            let password = prompt_password_once()?;
            let mut vault = load_vault_with_password(&profile, &profile_path, password.clone())?;
            vault.delete(&args.key)?;
            save_vault_with_password(&profile, &profile_path, &vault, password)
        }
        Command::Reveal(args) => {
            let profile_path = resolve_profile_path(&args.profile);
            let profile = Profile::from_path(&profile_path)?;
            let password = prompt_password_once()?;
            let vault = load_vault_with_password(&profile, &profile_path, password)?;
            let value = vault
                .entries()
                .get(&args.key)
                .ok_or_else(|| Error::MissingConfigKey(args.key.clone()))?;
            reveal_value(&args.key, value, args.raw, args.output.as_ref())
        }
        Command::Run(args) => run_profile(&args.profile).await,
        Command::Ping(args) => ping_profile(&args.profile).await,
    }
}

fn parse_file_mode(value: &str) -> Result<u32, Error> {
    let trimmed = value.trim();
    u32::from_str_radix(trimmed, 8).map_err(|_| Error::InvalidFileMode {
        value: trimmed.to_string(),
    })
}

fn reveal_value(
    key: &str,
    value: &VaultValue,
    raw: bool,
    output: Option<&PathBuf>,
) -> Result<(), Error> {
    match value {
        VaultValue::PlainText(text) => {
            if let Some(path) = output {
                std::fs::write(path, text.as_bytes()).map_err(|source| Error::WriteFile {
                    path: path.clone(),
                    source,
                })?;
            } else {
                println!("{}", text);
            }
        }
        VaultValue::FileContent {
            path,
            content,
            mode,
            cleanup,
        } => {
            if let Some(output_path) = output {
                std::fs::write(output_path, content).map_err(|source| Error::WriteFile {
                    path: output_path.clone(),
                    source,
                })?;
            } else if raw {
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(content).map_err(Error::PasswordPrompt)?;
                stdout.flush().map_err(Error::PasswordPrompt)?;
            } else {
                println!("key: {}", key);
                println!("kind: file");
                println!("target_path: {}", path.display());
                println!("size_bytes: {}", content.len());
                println!("mode: {:04o}", mode);
                println!(
                    "cleanup: {}",
                    match cleanup {
                        FileCleanup::OnExit => "on_exit",
                        FileCleanup::Keep => "keep",
                    }
                );
            }
        }
    }
    Ok(())
}

fn default_encrypted_path(input: &PathBuf) -> PathBuf {
    if let Some(file_name) = input.file_name().and_then(|value| value.to_str()) {
        if matches!(file_name, ".env" | "env") {
            return input.with_file_name("env.sec");
        }
        return input.with_file_name(format!("{}.enc", file_name));
    }
    input.with_extension("enc")
}

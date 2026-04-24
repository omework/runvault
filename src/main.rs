use clap::Parser;
use runvault::{
    cli::{Cli, Command},
    crypto::encrypt_env,
    error::Error,
    password::prompt_password_confirm,
    run::{ping_profile, run_profile},
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

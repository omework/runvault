use clap::Parser;
use runvault::{
    bundle::{BundleExportOptions, export_bundle, load_bundle, materialize_bundle},
    cli::{CacheSubcommand, Cli, CmdSubcommand, Command},
    crypto::encrypt_env,
    envfile::{apply_prefix, parse_env_bytes, parse_reference_value},
    error::Error,
    jwt::{JwtOptions, generate_hs256, generate_signing_secret, parse_ttl_seconds},
    password::{prompt_password_confirm, prompt_password_once},
    profile::{
        CreateProfileOptions, FileCleanup, FileImportSpec, FileSpec, PingTarget, Profile,
        create_profile, ensure_default_profile_exists, expand_user_home, load_file_import_document,
        parse_file_mode, resolve_profile_path, save_profile_to_path,
    },
    run::{ping_profile, run_profile, run_profile_with_secure_store_key},
    secure_store::{
        clear_all_passwords, clear_password, load_password as load_secure_password, store_password,
    },
    vault::{
        VaultDocument, VaultValue, load_vault_for_update_with_password, load_vault_with_password,
        save_vault_with_password,
    },
};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
};

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
        Command::Cmd(args) => match args.command {
            CmdSubcommand::Set(set) => {
                let (profile_input, cmd) = set.resolve();
                ensure_default_profile_exists(&profile_input)?;
                let profile_path = resolve_profile_path(&profile_input);
                let mut profile = Profile::from_path(&profile_path)?;
                profile.run.cmd = cmd;
                save_profile_to_path(&profile_path, &profile)
            }
        },
        Command::CreateProfile(args) => {
            let created = create_profile(
                &args.profile_or_default(),
                &CreateProfileOptions {
                    name: args.name,
                    env_file: args.env_file,
                },
            )?;
            println!("{}", created.display());
            Ok(())
        }
        Command::Bundle(args) => {
            let (profile_input, output_path) = args.resolve();
            ensure_default_profile_exists(&profile_input)?;
            export_bundle(
                &profile_input,
                &output_path,
                &BundleExportOptions {
                    version: args.version,
                    description: args.description,
                },
            )
        }
        Command::Cache(args) => match args.command {
            CacheSubcommand::Clear(args) => {
                if let Some(profile) = args.profile {
                    clear_password(&resolve_profile_path(&profile))
                } else {
                    clear_all_passwords()
                }
            }
        },
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
        Command::Jwt(args) => {
            let (profile_input, key) = args.resolve();
            ensure_default_profile_exists(&profile_input)?;
            let profile_path = resolve_profile_path(&profile_input);
            let mut profile = Profile::from_path(&profile_path)?;
            let env_path = profile.resolve_env_path(&profile_path);
            let (mut vault, password) = if env_path.exists() {
                let (vault, password) = load_vault_with_lazy_password(&profile, &profile_path)?;
                (vault, password)
            } else {
                (
                    VaultDocument::default(),
                    password_for_new_vault(&profile_path)?,
                )
            };
            let signing_secret = if let Some(signing_key) = args.signing_key.as_ref() {
                match vault.entries().get(signing_key) {
                    Some(VaultValue::PlainText(value)) => value.clone(),
                    Some(VaultValue::FileContent { .. }) => {
                        return Err(Error::JwtSecretMustBePlainText {
                            key: signing_key.clone(),
                        });
                    }
                    Some(VaultValue::SealedVisible(_)) => {
                        unreachable!("JWT command uses the fully materialized vault loader")
                    }
                    None => return Err(Error::MissingConfigKey(signing_key.clone())),
                }
            } else {
                generate_signing_secret()?
            };
            let token = generate_hs256(
                &signing_secret,
                &JwtOptions {
                    issuer: args.issuer,
                    audience: args.audience,
                    subject: args.subject,
                    ttl_seconds: parse_ttl_seconds(&args.ttl)?,
                    claims: args.claims,
                },
            )?;
            vault.set_plain_text(&key, token.clone())?;
            profile.remove_file_spec(&key);
            save_profile_to_path(&profile_path, &profile)?;
            save_vault_with_password(&profile, &profile_path, &vault, password)?;

            if let Some(output_path) = args.file {
                std::fs::write(&output_path, token).map_err(|source| Error::WriteFile {
                    path: output_path,
                    source,
                })?;
            } else {
                println!("{}", token);
            }
            Ok(())
        }
        Command::Set(args) => {
            let (profile_input, key) = args.resolve();
            ensure_default_profile_exists(&profile_input)?;
            let profile_path = resolve_profile_path(&profile_input);
            let mut profile = Profile::from_path(&profile_path)?;
            let env_path = profile.resolve_env_path(&profile_path);
            let (mut vault, password) = if env_path.exists() {
                let (vault, password) =
                    load_vault_with_lazy_password_for_update(&profile, &profile_path)?;
                (vault, password)
            } else {
                (
                    VaultDocument::default(),
                    password_for_new_vault(&profile_path)?,
                )
            };

            let mode = args
                .mode
                .as_deref()
                .map(parse_file_mode)
                .transpose()?
                .unwrap_or(0o600);
            let cleanup = if args.to_file.is_some() {
                if args.on_exit {
                    FileCleanup::OnExit
                } else {
                    FileCleanup::Keep
                }
            } else {
                FileCleanup::OnExit
            };

            match (args.value, args.from_file, args.to_file) {
                (Some(value), None, None) => {
                    vault.set_plain_text(&key, value)?;
                    profile.remove_file_spec(&key);
                }
                (Some(value), None, Some(runtime_path)) => {
                    vault.set_file_content(
                        &key,
                        runtime_path.clone(),
                        value.into_bytes(),
                        mode,
                        cleanup,
                    )?;
                    profile.upsert_file_spec(
                        &key,
                        FileSpec {
                            target_path: runtime_path,
                            mode: format!("{mode:04o}"),
                            cleanup,
                        },
                    );
                }
                (None, Some(source_path), None) => {
                    let content =
                        std::fs::read(&source_path).map_err(|source| Error::ReadFile {
                            path: source_path.clone(),
                            source,
                        })?;
                    let value = String::from_utf8(content)
                        .map_err(|_| Error::FileSourceNotUtf8 { path: source_path })?;
                    vault.set_plain_text(&key, value)?;
                    profile.remove_file_spec(&key);
                }
                (None, Some(source_path), Some(runtime_path)) => {
                    let content =
                        std::fs::read(&source_path).map_err(|source| Error::ReadFile {
                            path: source_path,
                            source,
                        })?;
                    vault.set_file_content(&key, runtime_path.clone(), content, mode, cleanup)?;
                    profile.upsert_file_spec(
                        &key,
                        FileSpec {
                            target_path: runtime_path,
                            mode: format!("{mode:04o}"),
                            cleanup,
                        },
                    );
                }
                _ => unreachable!("clap enforces set arguments"),
            }

            save_profile_to_path(&profile_path, &profile)?;
            save_vault_with_password(&profile, &profile_path, &vault, password)
        }
        Command::Import(args) => {
            let (profile_input, input_paths) = args.resolve();
            ensure_default_profile_exists(&profile_input)?;
            let profile_path = resolve_profile_path(&profile_input);
            let mut profile = Profile::from_path(&profile_path)?;
            let env_path = profile.resolve_env_path(&profile_path);
            let (mut vault, password) = if env_path.exists() {
                let (vault, password) =
                    load_vault_with_lazy_password_for_update(&profile, &profile_path)?;
                (vault, password)
            } else {
                (
                    VaultDocument::default(),
                    password_for_new_vault(&profile_path)?,
                )
            };

            let mut referenced_specs: BTreeMap<(PathBuf, String), FileImportSpec> = BTreeMap::new();
            for input_path in input_paths {
                let input = std::fs::read(&input_path).map_err(|source| Error::ReadFile {
                    path: input_path.clone(),
                    source,
                })?;
                let input_dir = input_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf();
                let vars = parse_env_bytes(&input)?;
                let vars = apply_prefix(vars, args.prefix.as_deref().unwrap_or(""))?;
                for (key, value) in vars {
                    if let Some(reference) = parse_reference_value(&value) {
                        let mut reference_path = expand_user_home(Path::new(&reference));
                        if reference_path.is_relative() {
                            reference_path = input_dir.join(reference_path);
                        }
                        let spec = if let Some(spec) =
                            referenced_specs.get(&(reference_path.clone(), key.clone()))
                        {
                            spec.clone()
                        } else {
                            let document = load_file_import_document(&reference_path)?;
                            let spec = document.files.get(&key).cloned().ok_or_else(|| {
                                Error::InvalidImportSpec(format!(
                                    "reference file '{}' does not define key '{}'",
                                    reference_path.display(),
                                    key
                                ))
                            })?;
                            referenced_specs
                                .insert((reference_path.clone(), key.clone()), spec.clone());
                            spec
                        };
                        apply_file_import_spec(&mut profile, &mut vault, &key, spec)?;
                    } else {
                        vault.set_plain_text(&key, value)?;
                        profile.remove_file_spec(&key);
                    }
                }
            }

            save_profile_to_path(&profile_path, &profile)?;
            save_vault_with_password(&profile, &profile_path, &vault, password)
        }
        Command::ImportFiles(args) => {
            let (profile_input, input_paths) = args.resolve();
            ensure_default_profile_exists(&profile_input)?;
            let profile_path = resolve_profile_path(&profile_input);
            let mut profile = Profile::from_path(&profile_path)?;
            let env_path = profile.resolve_env_path(&profile_path);
            let (mut vault, password) = if env_path.exists() {
                let (vault, password) =
                    load_vault_with_lazy_password_for_update(&profile, &profile_path)?;
                (vault, password)
            } else {
                (
                    VaultDocument::default(),
                    password_for_new_vault(&profile_path)?,
                )
            };

            for input_path in input_paths {
                let document = load_file_import_document(&input_path)?;
                for (key, spec) in document.files {
                    apply_file_import_spec(&mut profile, &mut vault, &key, spec)?;
                }
            }

            save_profile_to_path(&profile_path, &profile)?;
            save_vault_with_password(&profile, &profile_path, &vault, password)
        }
        Command::Delete(args) => {
            let (profile_input, key) = args.resolve();
            ensure_default_profile_exists(&profile_input)?;
            let profile_path = resolve_profile_path(&profile_input);
            let mut profile = Profile::from_path(&profile_path)?;
            let (mut vault, password) =
                load_vault_with_lazy_password_for_update(&profile, &profile_path)?;
            vault.delete(&key)?;
            profile.remove_file_spec(&key);
            save_profile_to_path(&profile_path, &profile)?;
            save_vault_with_password(&profile, &profile_path, &vault, password)
        }
        Command::Reveal(args) => {
            let (profile_input, key) = args.resolve();
            ensure_default_profile_exists(&profile_input)?;
            let profile_path = resolve_profile_path(&profile_input);
            let profile = Profile::from_path(&profile_path)?;
            let (vault, _) = load_vault_with_lazy_password(&profile, &profile_path)?;
            let value = vault
                .entries()
                .get(&key)
                .ok_or_else(|| Error::MissingConfigKey(key.clone()))?;
            reveal_value(
                &key,
                value,
                profile.file_spec(&key),
                args.raw,
                args.output.as_ref(),
            )
        }
        Command::Run(args) => {
            let target = args.profile_or_default();
            if looks_like_profile_input(&target) {
                run_profile(&target).await
            } else {
                let bundle = load_bundle(&target)?;
                let (_temp_dir, profile_path) = materialize_bundle(&bundle)?;
                run_profile_with_secure_store_key(&profile_path, &target).await
            }
        }
        Command::Ping(args) => match args.command {
            Some(runvault::cli::PingSubcommand::Add(add)) => {
                let (profile_input, name, url) = add.resolve();
                ensure_default_profile_exists(&profile_input)?;
                let profile_path = resolve_profile_path(&profile_input);
                let mut profile = Profile::from_path(&profile_path)?;
                profile.upsert_ping_target(PingTarget {
                    name,
                    url,
                    timeout_seconds: add.timeout_seconds,
                    interval_millis: add.interval_millis,
                });
                save_profile_to_path(&profile_path, &profile)
            }
            None => ping_profile(&args.profile_or_default()).await,
        },
    }
}

fn looks_like_profile_input(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "runvault.yaml")
        || path.is_dir()
        || path.join("runvault.yaml").exists()
}

fn apply_file_import_spec(
    profile: &mut Profile,
    vault: &mut VaultDocument,
    key: &str,
    spec: FileImportSpec,
) -> Result<(), Error> {
    let content = std::fs::read(&spec.src).map_err(|source| Error::ReadFile {
        path: spec.src.clone(),
        source,
    })?;
    if let Some(target_path) = spec.to_file {
        let mode = parse_file_mode(&spec.mode)?;
        let cleanup = spec.cleanup.unwrap_or(FileCleanup::Keep);
        vault.set_file_content(key, target_path.clone(), content, mode, cleanup)?;
        profile.upsert_file_spec(
            key,
            FileSpec {
                target_path,
                mode: spec.mode,
                cleanup,
            },
        );
    } else {
        let value =
            String::from_utf8(content).map_err(|_| Error::FileSourceNotUtf8 { path: spec.src })?;
        vault.set_plain_text(key, value)?;
        profile.remove_file_spec(key);
    }
    Ok(())
}

fn load_vault_with_lazy_password(
    profile: &Profile,
    profile_path: &PathBuf,
) -> Result<(VaultDocument, age::secrecy::SecretString), Error> {
    if let Some(password) = load_secure_password(profile_path)? {
        match load_vault_with_password(profile, profile_path, password.clone()) {
            Ok(vault) => {
                store_password(profile_path, &password)?;
                return Ok((vault, password));
            }
            Err(Error::Decryption(_)) => {
                clear_password(profile_path)?;
            }
            Err(err) => return Err(err),
        }
    }

    let password = prompt_password_once()?;
    let vault = load_vault_with_password(profile, profile_path, password.clone())?;
    store_password(profile_path, &password)?;
    Ok((vault, password))
}

fn load_vault_with_lazy_password_for_update(
    profile: &Profile,
    profile_path: &PathBuf,
) -> Result<(VaultDocument, age::secrecy::SecretString), Error> {
    if let Some(password) = load_secure_password(profile_path)? {
        match load_vault_for_update_with_password(profile, profile_path, password.clone()) {
            Ok(vault) => {
                store_password(profile_path, &password)?;
                return Ok((vault, password));
            }
            Err(Error::Decryption(_)) => {
                clear_password(profile_path)?;
            }
            Err(err) => return Err(err),
        }
    }

    let password = prompt_password_once()?;
    let vault = load_vault_for_update_with_password(profile, profile_path, password.clone())?;
    store_password(profile_path, &password)?;
    Ok((vault, password))
}

fn password_for_new_vault(profile_path: &PathBuf) -> Result<age::secrecy::SecretString, Error> {
    if let Some(password) = load_secure_password(profile_path)? {
        store_password(profile_path, &password)?;
        return Ok(password);
    }
    let password = prompt_password_confirm()?;
    store_password(profile_path, &password)?;
    Ok(password)
}

fn reveal_value(
    key: &str,
    value: &VaultValue,
    file_spec: Option<&FileSpec>,
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
                let target_path = file_spec
                    .map(|spec| spec.target_path.as_path())
                    .unwrap_or(path.as_path());
                let mode = file_spec
                    .map(|spec| parse_file_mode(&spec.mode))
                    .transpose()?
                    .unwrap_or(*mode);
                let cleanup = file_spec.map(|spec| spec.cleanup).unwrap_or(*cleanup);
                println!("key: {}", key);
                println!("kind: file");
                println!("target_path: {}", target_path.display());
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
        VaultValue::SealedVisible(_) => {
            return Err(Error::VaultFormat(format!(
                "key '{key}' was not materialized before reveal"
            )));
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

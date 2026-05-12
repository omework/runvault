use clap::Parser;
use runvault::{
    bundle::{
        BundleDocument, BundleExportOptions, export_bundle, load_bundle, materialize_bundle_into,
    },
    cli::{CacheSubcommand, Cli, CmdSubcommand, Command, ImportSubcommand, PkiSubcommand},
    crypto::{encrypt_file_payload, maybe_decrypt_file_payload},
    envfile::{apply_prefix, parse_env_bytes, parse_reference_value},
    error::Error,
    jwt::{JwtOptions, generate_hs256, generate_signing_secret, parse_ttl_seconds},
    password::{prompt_password_confirm, prompt_password_once},
    pki::{
        PkiInitOptions, PkiIssueOptions, init_infra_pki, issue_infra_certificate,
        rotate_infra_certificates,
    },
    profile::{
        CreateProfileOptions, FileCleanup, FileImportSpec, FileSpec, PingTarget, Profile,
        ResourceImportSpec, ResourceSpec, create_profile, ensure_default_profile_exists,
        expand_user_home, load_file_import_document, load_resource_import_document,
        parse_file_mode, resolve_profile_path, save_profile_to_path,
    },
    registry::{
        RegistryEntryStatus, append_history_entry, current_bundle_path, current_version,
        global_passphrase_store_key, load_registry, mark_history_entry,
        previous_successful_bundle_path, save_registry, track_bundle_dir,
    },
    run::{ping_profile, run_profile, run_profile_with_secure_store_key_in_dir},
    secure_store::{
        clear_password, load_password as load_secure_password, store_password_if_possible,
    },
    vault::{
        VaultDocument, VaultValue, load_vault_for_update_with_password, load_vault_with_password,
        save_vault_with_password,
    },
};
use std::{
    collections::BTreeMap,
    io::Write,
    net::IpAddr,
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
    let Cli { profile, command } = Cli::parse();
    let global_profile = profile.as_ref();
    match command {
        Command::Cmd(args) => match args.command {
            CmdSubcommand::Set(set) => {
                let (profile_input, cmd) = set.resolve(global_profile);
                ensure_default_profile_exists(&profile_input)?;
                let profile_path = resolve_profile_path(&profile_input);
                let mut profile = Profile::from_path(&profile_path)?;
                profile.run.cmd = cmd;
                save_profile_to_path(&profile_path, &profile)
            }
        },
        Command::Init(args) => {
            let created = create_profile(
                &args.profile_or_default(global_profile),
                &CreateProfileOptions {
                    name: args.name,
                    env_file: args.env_file,
                },
            )?;
            println!("{}", created.display());
            Ok(())
        }
        Command::Bundle(args) => {
            let (profile_input, output_path) = args.resolve(global_profile);
            ensure_default_profile_exists(&profile_input)?;
            export_bundle(
                &profile_input,
                &output_path,
                &BundleExportOptions {
                    version: args.version,
                    description: args.description,
                    force: args.force,
                },
            )
        }
        Command::Cache(args) => match args.command {
            CacheSubcommand::Clear(args) => {
                let _ = args.profile;
                let _ = global_profile;
                clear_password(&global_passphrase_store_key()?)
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
            let encrypted = encrypt_file_payload(&input, password)?;
            std::fs::write(&output_path, encrypted).map_err(|source| Error::WriteFile {
                path: output_path,
                source,
            })?;
            Ok(())
        }
        Command::Jwt(args) => {
            let profile_input = args.resolve(global_profile);
            ensure_default_profile_exists(&profile_input)?;
            let profile_path = resolve_profile_path(&profile_input);
            let profile = Profile::from_path(&profile_path)?;
            let signing_secret = if let Some(signing_key) = args.signing_key.as_ref() {
                let env_path = profile.resolve_env_path(&profile_path);
                if !env_path.exists() {
                    return Err(Error::MissingConfigKey(signing_key.clone()));
                }
                let (vault, _) = load_vault_with_lazy_password(&profile, &profile_path)?;
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
                    audience: Some(args.audience.clone()),
                    subject: args.subject,
                    ttl_seconds: parse_ttl_seconds(&args.ttl)?,
                    claims: args.claims,
                },
            )?;
            println!("{}", token);
            Ok(())
        }
        Command::Set(args) => {
            let (profile_input, key) = args.resolve(global_profile);
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
                    let content = read_profile_source_bytes(&source_path, &password)?;
                    let value = String::from_utf8(content)
                        .map_err(|_| Error::FileSourceNotUtf8 { path: source_path })?;
                    vault.set_plain_text(&key, value)?;
                    profile.remove_file_spec(&key);
                }
                (None, Some(source_path), Some(runtime_path)) => {
                    let content = read_profile_source_bytes(&source_path, &password)?;
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
        Command::Pki(args) => match args.command {
            PkiSubcommand::Init(args) => {
                let password = load_pki_secret_password(true)?;
                let created = init_infra_pki(
                    password,
                    &PkiInitOptions {
                        common_name: args.common_name,
                        days: args.days,
                    },
                )?;
                println!("{}", created.display());
                Ok(())
            }
            PkiSubcommand::Issue(args) => {
                let password = load_pki_secret_password(false)?;
                let ip_addrs = args
                    .ip_addrs
                    .into_iter()
                    .map(|value| {
                        value
                            .parse::<IpAddr>()
                            .map_err(|_| Error::Pki(format!("invalid IP address '{}'", value)))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let created = issue_infra_certificate(
                    password,
                    &args.name,
                    &PkiIssueOptions {
                        common_name: args.common_name,
                        dns_names: args.dns_names,
                        ip_addrs,
                        client: args.client,
                        server: args.server,
                        days: args.days,
                    },
                )?;
                println!("{}", created.display());
                Ok(())
            }
            PkiSubcommand::Rotate(_) => {
                let password = load_pki_secret_password(false)?;
                rotate_infra_certificates(password)?;
                println!("rotated tracked PKI leaf certificates");
                Ok(())
            }
        },
        Command::Import(args) => match args.command {
            ImportSubcommand::Env(args) => {
                let (profile_input, input_paths) = args.resolve(global_profile);
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

                let mut referenced_specs: BTreeMap<(PathBuf, String), FileImportSpec> =
                    BTreeMap::new();
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
                            apply_file_import_spec(
                                &mut profile,
                                &mut vault,
                                &key,
                                spec,
                                &password,
                            )?;
                        } else {
                            vault.set_plain_text(&key, value)?;
                            profile.remove_file_spec(&key);
                        }
                    }
                }

                save_profile_to_path(&profile_path, &profile)?;
                save_vault_with_password(&profile, &profile_path, &vault, password)
            }
            ImportSubcommand::Resources(args) => {
                if args.uses_inline_spec() {
                    let (profile_input, src) = args
                        .resolve_inline(global_profile)
                        .map_err(Error::InvalidImportSpec)?;
                    ensure_default_profile_exists(&profile_input)?;
                    let profile_path = resolve_profile_path(&profile_input);
                    let mut profile = Profile::from_path(&profile_path)?;
                    let target_path = args
                        .to_file
                        .clone()
                        .expect("inline resource to-file is required");
                    let key = args
                        .key
                        .clone()
                        .unwrap_or_else(|| infer_resource_key(&target_path));
                    apply_resource_import_spec(
                        &mut profile,
                        &key,
                        ResourceImportSpec {
                            src,
                            to_file: target_path,
                            mode: args.mode.clone().unwrap_or_else(|| "0600".to_string()),
                            cleanup: if args.on_exit {
                                FileCleanup::OnExit
                            } else {
                                FileCleanup::Keep
                            },
                        },
                    );
                    save_profile_to_path(&profile_path, &profile)
                } else {
                    let (profile_input, input_paths) = args.resolve(global_profile);
                    ensure_default_profile_exists(&profile_input)?;
                    let profile_path = resolve_profile_path(&profile_input);
                    let mut profile = Profile::from_path(&profile_path)?;

                    for input_path in input_paths {
                        let document = load_resource_import_document(&input_path)?;
                        for (key, spec) in document.resources {
                            apply_resource_import_spec(&mut profile, &key, spec);
                        }
                    }

                    save_profile_to_path(&profile_path, &profile)
                }
            }
        },
        Command::ImportFiles(args) => {
            let (profile_input, input_paths) = args.resolve(global_profile);
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
                    apply_file_import_spec(&mut profile, &mut vault, &key, spec, &password)?;
                }
            }

            save_profile_to_path(&profile_path, &profile)?;
            save_vault_with_password(&profile, &profile_path, &vault, password)
        }
        Command::Delete(args) => {
            let (profile_input, key) = args.resolve(global_profile);
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
            let (profile_input, key) = args.resolve(global_profile);
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
            if let Some(target) = args.profile.as_ref() {
                if global_profile.is_none() && looks_like_profile_input(target) {
                    run_profile(target).await
                } else {
                    run_bundle_path(target).await
                }
            } else {
                let profile_input = args.explicit_profile(global_profile).ok_or_else(|| {
                    Error::Registry(
                        "run without a bundle requires --profile so the bundle track can be resolved".to_string(),
                    )
                })?;
                run_registered_profile(&profile_input).await
            }
        }
        Command::Rollback(args) => {
            let profile_input = args.explicit_profile(global_profile).ok_or_else(|| {
                Error::Registry(
                    "rollback requires --profile so the bundle track can be resolved".to_string(),
                )
            })?;
            rollback_registered_profile(&profile_input).await
        }
        Command::Ping(args) => match args.command {
            Some(runvault::cli::PingSubcommand::Add(add)) => {
                let (profile_input, name, url) = add.resolve(global_profile);
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
            None => ping_profile(&args.profile_or_default(global_profile)).await,
        },
    }
}

async fn run_bundle_path(bundle_path: &Path) -> Result<(), Error> {
    let bundle = load_bundle(bundle_path)?;
    let version = bundle_version(&bundle)?;
    let track = bundle_track_name(&bundle)?;
    let stored_bundle_path = stage_bundle_for_track(bundle_path, &bundle, &track, &version)?;
    let stored_dir = stored_bundle_path
        .parent()
        .ok_or_else(|| {
            Error::Registry(format!(
                "stored bundle path '{}' has no parent directory",
                stored_bundle_path.display()
            ))
        })?
        .to_path_buf();

    let mut registry = load_registry()?;
    let reuse_current =
        current_version(&registry, &track).is_some_and(|current| current == version);
    let history_index = if reuse_current {
        None
    } else {
        let index =
            append_history_entry(&mut registry, &track, &version, stored_bundle_path.clone())?;
        save_registry(&registry)?;
        Some(index)
    };

    let run_result = execute_bundle_at_path(&stored_bundle_path, &stored_dir).await;

    if let Some(index) = history_index {
        match run_result {
            Ok(()) => {
                mark_history_entry(&mut registry, &track, index, RegistryEntryStatus::Succeeded)?;
                save_registry(&registry)?;
                Ok(())
            }
            Err(err) => {
                mark_history_entry(&mut registry, &track, index, RegistryEntryStatus::Failed)?;
                save_registry(&registry)?;
                Err(err)
            }
        }
    } else {
        run_result
    }
}

async fn run_registered_profile(profile_input: &Path) -> Result<(), Error> {
    ensure_default_profile_exists(profile_input)?;
    let profile_path = resolve_profile_path(profile_input);
    let profile = Profile::from_path(&profile_path)?;
    let track = profile.name.clone();
    let registry = load_registry()?;
    let bundle_path = current_bundle_path(&registry, &track)?;
    let bundle_dir = bundle_path
        .parent()
        .ok_or_else(|| {
            Error::Registry(format!(
                "registered bundle path '{}' has no parent directory",
                bundle_path.display()
            ))
        })?
        .to_path_buf();
    execute_bundle_at_path(&bundle_path, &bundle_dir).await
}

async fn rollback_registered_profile(profile_input: &Path) -> Result<(), Error> {
    ensure_default_profile_exists(profile_input)?;
    let profile_path = resolve_profile_path(profile_input);
    let profile = Profile::from_path(&profile_path)?;
    let track = profile.name.clone();

    let mut registry = load_registry()?;
    let bundle_path = previous_successful_bundle_path(&registry, &track)?;
    let bundle = load_bundle(&bundle_path)?;
    let version = bundle_version(&bundle)?;
    let bundle_dir = bundle_path
        .parent()
        .ok_or_else(|| {
            Error::Registry(format!(
                "registered bundle path '{}' has no parent directory",
                bundle_path.display()
            ))
        })?
        .to_path_buf();

    let index = append_history_entry(&mut registry, &track, &version, bundle_path.clone())?;
    save_registry(&registry)?;

    match execute_bundle_at_path(&bundle_path, &bundle_dir).await {
        Ok(()) => {
            mark_history_entry(&mut registry, &track, index, RegistryEntryStatus::Succeeded)?;
            save_registry(&registry)?;
            Ok(())
        }
        Err(err) => {
            mark_history_entry(&mut registry, &track, index, RegistryEntryStatus::Failed)?;
            save_registry(&registry)?;
            Err(err)
        }
    }
}

fn stage_bundle_for_track(
    source_bundle_path: &Path,
    bundle: &BundleDocument,
    track: &str,
    version: &str,
) -> Result<PathBuf, Error> {
    let bundle_dir = track_bundle_dir(track, version)?;
    std::fs::create_dir_all(&bundle_dir).map_err(|source| Error::WriteFile {
        path: bundle_dir.clone(),
        source,
    })?;
    let stored_bundle_path = bundle_dir.join("bundle.yaml");
    let source_bytes = std::fs::read(source_bundle_path).map_err(|source| Error::ReadFile {
        path: source_bundle_path.to_path_buf(),
        source,
    })?;
    if stored_bundle_path.exists() {
        let existing = std::fs::read(&stored_bundle_path).map_err(|source| Error::ReadFile {
            path: stored_bundle_path.clone(),
            source,
        })?;
        if existing != source_bytes {
            return Err(Error::Registry(format!(
                "bundle version '{}' for track '{}' is already registered with different content",
                version, track
            )));
        }
    } else {
        std::fs::write(&stored_bundle_path, source_bytes).map_err(|source| Error::WriteFile {
            path: stored_bundle_path.clone(),
            source,
        })?;
    }
    materialize_bundle_into(&bundle_dir, bundle)?;
    Ok(stored_bundle_path)
}

async fn execute_bundle_at_path(bundle_path: &Path, bundle_dir: &Path) -> Result<(), Error> {
    let bundle = load_bundle(bundle_path)?;
    let profile_path = materialize_bundle_into(bundle_dir, &bundle)?;
    let secure_store_key = global_passphrase_store_key()?;
    run_profile_with_secure_store_key_in_dir(&profile_path, &secure_store_key, bundle_dir).await
}

fn bundle_version(bundle: &BundleDocument) -> Result<String, Error> {
    bundle
        .version
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::InvalidBundle(
                "bundle version is required for registry-backed execution".to_string(),
            )
        })
}

fn bundle_track_name(bundle: &BundleDocument) -> Result<String, Error> {
    let track = bundle.profile.name.trim();
    if track.is_empty() {
        return Err(Error::InvalidBundle(
            "bundle profile.name must not be empty".to_string(),
        ));
    }
    Ok(track.to_string())
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
    password: &age::secrecy::SecretString,
) -> Result<(), Error> {
    let content = read_profile_source_bytes(&spec.src, password)?;
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

fn read_profile_source_bytes(
    path: &Path,
    password: &age::secrecy::SecretString,
) -> Result<Vec<u8>, Error> {
    let content = std::fs::read(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(maybe_decrypt_file_payload(&content, password.clone())?.to_vec())
}

fn apply_resource_import_spec(profile: &mut Profile, key: &str, spec: ResourceImportSpec) {
    profile.resources.insert(
        key.to_string(),
        ResourceSpec {
            source_path: spec.src,
            target_path: spec.to_file,
            mode: spec.mode,
            cleanup: spec.cleanup,
        },
    );
}

fn infer_resource_key(target_path: &Path) -> String {
    let mut key = String::from("RESOURCE_");
    let mut last_was_underscore = true;

    for ch in target_path.to_string_lossy().chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_uppercase()
        } else {
            '_'
        };
        if mapped == '_' {
            if !last_was_underscore {
                key.push(mapped);
            }
            last_was_underscore = true;
        } else {
            key.push(mapped);
            last_was_underscore = false;
        }
    }

    while key.ends_with('_') {
        key.pop();
    }

    if key == "RESOURCE" || key == "RESOURCE_" {
        "RESOURCE_FILE".to_string()
    } else {
        key
    }
}

fn load_vault_with_lazy_password(
    profile: &Profile,
    profile_path: &PathBuf,
) -> Result<(VaultDocument, age::secrecy::SecretString), Error> {
    let secure_store_key = global_passphrase_store_key()?;
    if let Some(password) = load_secure_password(&secure_store_key)? {
        match load_vault_with_password(profile, profile_path, password.clone()) {
            Ok(vault) => {
                store_password_if_possible(&secure_store_key, &password)?;
                return Ok((vault, password));
            }
            Err(Error::Decryption(_)) => {
                clear_password(&secure_store_key)?;
            }
            Err(err) => return Err(err),
        }
    }

    let password = prompt_password_once()?;
    let vault = load_vault_with_password(profile, profile_path, password.clone())?;
    store_password_if_possible(&secure_store_key, &password)?;
    Ok((vault, password))
}

fn load_pki_secret_password(
    confirm_if_uncached: bool,
) -> Result<age::secrecy::SecretString, Error> {
    let secure_store_key = global_passphrase_store_key()?;

    if let Some(password) = load_secure_password(&secure_store_key)? {
        store_password_if_possible(&secure_store_key, &password)?;
        return Ok(password);
    }

    let password = if confirm_if_uncached {
        prompt_password_confirm()?
    } else {
        prompt_password_once()?
    };
    store_password_if_possible(&secure_store_key, &password)?;
    Ok(password)
}

fn load_vault_with_lazy_password_for_update(
    profile: &Profile,
    profile_path: &PathBuf,
) -> Result<(VaultDocument, age::secrecy::SecretString), Error> {
    let secure_store_key = global_passphrase_store_key()?;
    if let Some(password) = load_secure_password(&secure_store_key)? {
        match load_vault_for_update_with_password(profile, profile_path, password.clone()) {
            Ok(vault) => {
                store_password_if_possible(&secure_store_key, &password)?;
                return Ok((vault, password));
            }
            Err(Error::Decryption(_)) => {
                clear_password(&secure_store_key)?;
            }
            Err(err) => return Err(err),
        }
    }

    let password = prompt_password_once()?;
    let vault = load_vault_for_update_with_password(profile, profile_path, password.clone())?;
    store_password_if_possible(&secure_store_key, &password)?;
    Ok((vault, password))
}

fn password_for_new_vault(_profile_path: &PathBuf) -> Result<age::secrecy::SecretString, Error> {
    let secure_store_key = global_passphrase_store_key()?;
    if let Some(password) = load_secure_password(&secure_store_key)? {
        store_password_if_possible(&secure_store_key, &password)?;
        return Ok(password);
    }
    let password = prompt_password_confirm()?;
    store_password_if_possible(&secure_store_key, &password)?;
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

use age::secrecy::SecretString;
use clap::Parser;
use std::{
    collections::BTreeMap,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};

use crate::{
    bundle::{self, BundleDocument, BundleExportOptions},
    cli::{
        AssetsSubcommand, BundleVersionsArgs, BundlesSubcommand, Cli, CmdSubcommand, Command,
        EnvSubcommand, ImportAssetsArgs, ImportEnvArgs, ImportSubcommand, JwtSubcommand,
        PingSubcommand, PkiSubcommand, ProfileArgs, ProfileSubcommand, ResourcesAddSubcommand,
        ResourcesSubcommand, RollbackArgs,
    },
    crypto::{encrypt_file_payload, maybe_decrypt_file_payload},
    envfile::{apply_prefix, parse_env_bytes, parse_reference_value},
    error::Error,
    jwt::{JwtOptions, generate_hs256, generate_signing_secret, parse_ttl_seconds},
    password::{prompt_password_confirm, prompt_password_once},
    pki::{self, PkiInitOptions, PkiIssueOptions},
    profile::{
        self, AssetImportSpec, AssetSpec, CreateProfileOptions, FileCleanup, FileImportSpec,
        FileSpec, PingTarget, Profile, ResourceRegistryEntry,
    },
    registry::{
        RegistryEntryStatus, RegistryTrack, append_history_entry, current_bundle_path,
        current_version, global_passphrase_store_key, load_registry, mark_history_entry,
        previous_successful_bundle_path, reset_runvault_root, runvault_root, save_registry,
        track_bundle_dir,
    },
    run, secure_store,
    vault::{self, VaultDocument, VaultValue},
};

/// High-level application facade for embedding `runvault` as a library.
///
/// `Runvault` owns the command-dispatch logic that used to live only in the
/// binary entrypoint and exposes reusable methods for the crate's major
/// features: profiles, bundles, vault values, runtime execution, JWTs, and PKI.
#[derive(Debug, Clone)]
pub struct Runvault {
    default_profile: PathBuf,
    execution_dir: Option<PathBuf>,
    secure_store_key: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSource {
    PlainText(String),
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretUpdate {
    pub key: String,
    pub source: SecretSource,
    pub target_path: Option<PathBuf>,
    pub mode: u32,
    pub cleanup: FileCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealedValue {
    PlainText(String),
    File(RevealedFile),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealedFile {
    pub target_path: PathBuf,
    pub content: Vec<u8>,
    pub mode: u32,
    pub cleanup: FileCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceListing {
    pub name: String,
    pub kind: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleListing {
    pub name: String,
    pub current_version: Option<String>,
    pub version_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleVersionListing {
    pub name: String,
    pub version: String,
    pub status: RegistryEntryStatus,
    pub current: bool,
    pub bundle_path: PathBuf,
}

impl Default for Runvault {
    fn default() -> Self {
        Self {
            default_profile: PathBuf::from(profile::DEFAULT_PROFILE_DIR),
            execution_dir: None,
            secure_store_key: None,
        }
    }
}

impl SecretUpdate {
    pub fn plain_text(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            source: SecretSource::PlainText(value.into()),
            target_path: None,
            mode: 0o600,
            cleanup: FileCleanup::OnExit,
        }
    }

    pub fn from_file(key: impl Into<String>, source_path: impl Into<PathBuf>) -> Self {
        Self {
            key: key.into(),
            source: SecretSource::File(source_path.into()),
            target_path: None,
            mode: 0o600,
            cleanup: FileCleanup::OnExit,
        }
    }

    pub fn with_target_path(mut self, target_path: impl Into<PathBuf>) -> Self {
        self.target_path = Some(target_path.into());
        self
    }

    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_cleanup(mut self, cleanup: FileCleanup) -> Self {
        self.cleanup = cleanup;
        self
    }
}

impl Runvault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn default_profile(&self) -> &Path {
        &self.default_profile
    }

    pub fn configured_execution_dir(&self) -> Option<&Path> {
        self.execution_dir.as_deref()
    }

    pub fn configured_secure_store_key(&self) -> Option<&Path> {
        self.secure_store_key.as_deref()
    }

    pub fn set_default_profile(&mut self, path: impl Into<PathBuf>) {
        self.default_profile = path.into();
    }

    pub fn set_execution_dir(&mut self, path: Option<PathBuf>) {
        self.execution_dir = path;
    }

    pub fn set_secure_store_key(&mut self, path: Option<PathBuf>) {
        self.secure_store_key = path;
    }

    pub fn with_default_profile(mut self, path: impl Into<PathBuf>) -> Self {
        self.default_profile = path.into();
        self
    }

    pub fn with_execution_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.execution_dir = Some(path.into());
        self
    }

    pub fn with_secure_store_key(mut self, path: impl Into<PathBuf>) -> Self {
        self.secure_store_key = Some(path.into());
        self
    }

    pub async fn run_cli_env(&self) -> Result<(), Error> {
        self.run_cli(Cli::parse()).await
    }

    pub async fn run_cli(&self, cli: Cli) -> Result<(), Error> {
        let Cli { profile, command } = cli;
        let global_profile = profile.as_deref();
        match command {
            Command::Profile(args) => match args.command {
                ProfileSubcommand::Init(args) => {
                    self.run_profile_init_command(profile.as_ref(), args)
                }
                ProfileSubcommand::Reset => self.reset_state(),
                ProfileSubcommand::Run(args) => {
                    self.run_profile_or_bundle_command(global_profile, profile.as_ref(), args)
                        .await
                }
                ProfileSubcommand::Rollback(args) => {
                    self.run_rollback_command(profile.as_ref(), args).await
                }
            },
            Command::Bundles(args) => match args.command {
                BundlesSubcommand::Export(args) => {
                    self.run_bundle_export_command(profile.as_ref(), args)
                }
                BundlesSubcommand::Run(args) => {
                    self.run_profile_or_bundle_command(global_profile, profile.as_ref(), args)
                        .await
                }
                BundlesSubcommand::List(_) => self.list_bundles(),
                BundlesSubcommand::Versions(args) => self.list_bundle_versions(&args),
            },
            Command::Cmd(args) => match args.command {
                CmdSubcommand::Set(set) => {
                    let (profile_input, cmd) = set.resolve(profile.as_ref());
                    self.set_command(Some(profile_input.as_path()), cmd)
                }
            },
            Command::Init(args) => self.run_profile_init_command(profile.as_ref(), args),
            Command::Bundle(args) => self.run_bundle_export_command(profile.as_ref(), args),
            Command::Reset => self.reset_state(),
            Command::Jwt(args) => match args.command {
                JwtSubcommand::Generate(args) => {
                    self.run_jwt_generate_command(profile.as_ref(), args)
                }
            },
            Command::Set(args) => self.run_env_set_command(profile.as_ref(), args),
            Command::Pki(args) => match args.command {
                PkiSubcommand::Init(args) => {
                    let created = self.init_pki(&PkiInitOptions {
                        common_name: args.common_name,
                        days: args.days,
                        force: args.force,
                    })?;
                    println!("{}", created.display());
                    Ok(())
                }
                PkiSubcommand::Issue(args) => {
                    let created = self.issue_pki_certificate(
                        &args.name,
                        &PkiIssueOptions {
                            common_name: args.common_name,
                            dns_names: args.dns_names,
                            ip_addrs: parse_ip_addrs(args.ip_addrs)?,
                            client: args.client,
                            server: args.server,
                            days: args.days,
                            force: args.force,
                        },
                    )?;
                    println!("{}", created.display());
                    Ok(())
                }
                PkiSubcommand::Rotate(_) => {
                    self.rotate_pki()?;
                    println!("rotated tracked PKI leaf certificates");
                    Ok(())
                }
                PkiSubcommand::List(_) => self.list_pki_materials(),
            },
            Command::Env(args) => match args.command {
                EnvSubcommand::Import(args) => self.run_import_env_command(profile.as_ref(), args),
                EnvSubcommand::Set(args) => self.run_env_set_command(profile.as_ref(), args),
                EnvSubcommand::Delete(args) => self.run_env_delete_command(profile.as_ref(), args),
                EnvSubcommand::Unset(args) => self.run_env_unset_command(profile.as_ref(), args),
                EnvSubcommand::UnsetFrom(args) => {
                    self.run_env_unset_from_command(profile.as_ref(), args)
                }
                EnvSubcommand::Reveal(args) => self.run_env_reveal_command(profile.as_ref(), args),
            },
            Command::Assets(args) => match args.command {
                AssetsSubcommand::Import(args) => {
                    self.run_import_assets_command(profile.as_ref(), args)
                }
            },
            Command::Import(args) => match args.command {
                ImportSubcommand::Env(args) => self.run_import_env_command(profile.as_ref(), args),
                ImportSubcommand::Resources(args) => self.import_resources(&args.inputs),
                ImportSubcommand::Assets(args) => {
                    self.run_import_assets_command(profile.as_ref(), args)
                }
            },
            Command::Resources(args) => match args.command {
                ResourcesSubcommand::Import(args) => self.import_resources(&args.inputs),
                ResourcesSubcommand::List(_) => self.list_resources(),
                ResourcesSubcommand::Add(args) => match args.command {
                    ResourcesAddSubcommand::File(args) => {
                        self.add_file_resource(&args.name, args.path, args.description)
                    }
                    ResourcesAddSubcommand::Text(args) => {
                        self.add_text_resource(&args.name, args.value, args.description)
                    }
                },
                ResourcesSubcommand::Remove(args) => self.remove_resources(&args.names),
                ResourcesSubcommand::RemoveFrom(args) => self.remove_resources_from(&args.inputs),
            },
            Command::Delete(args) => self.run_env_delete_command(profile.as_ref(), args),
            Command::Unset(args) => self.run_env_unset_command(profile.as_ref(), args),
            Command::UnsetFrom(args) => self.run_env_unset_from_command(profile.as_ref(), args),
            Command::Reveal(args) => self.run_env_reveal_command(profile.as_ref(), args),
            Command::Run(args) => {
                self.run_profile_or_bundle_command(global_profile, profile.as_ref(), args)
                    .await
            }
            Command::Rollback(args) => self.run_rollback_command(profile.as_ref(), args).await,
            Command::Ping(args) => match args.command {
                PingSubcommand::Add(add) => {
                    let (profile_input, name, url) = add.resolve(profile.as_ref());
                    self.add_ping_target(
                        Some(profile_input.as_path()),
                        PingTarget {
                            name,
                            url,
                            timeout_seconds: add.timeout_seconds,
                            interval_millis: add.interval_millis,
                        },
                    )
                }
                PingSubcommand::Check(check) => {
                    self.ping_profile(&check.profile_or_default(profile.as_ref()))
                        .await
                }
            },
        }
    }

    fn run_profile_init_command(
        &self,
        global_profile: Option<&PathBuf>,
        args: crate::cli::CreateProfileArgs,
    ) -> Result<(), Error> {
        let created = self.init_profile(
            Some(args.profile_or_default(global_profile).as_path()),
            &CreateProfileOptions {
                name: args.name,
                env_file: args.env_file,
            },
        )?;
        println!("{}", created.display());
        Ok(())
    }

    fn run_bundle_export_command(
        &self,
        global_profile: Option<&PathBuf>,
        args: crate::cli::BundleArgs,
    ) -> Result<(), Error> {
        let (profile_input, output_path) = args.resolve(global_profile);
        self.export_bundle(
            Some(profile_input.as_path()),
            &output_path,
            &BundleExportOptions {
                name: args.name,
                version: args.version,
                description: args.description,
                force: args.force,
            },
        )
    }

    fn run_jwt_generate_command(
        &self,
        global_profile: Option<&PathBuf>,
        args: crate::cli::JwtArgs,
    ) -> Result<(), Error> {
        let profile_input = args.resolve(global_profile);
        let token = self.generate_jwt(
            Some(profile_input.as_path()),
            args.signing_key.as_deref(),
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

    fn run_env_set_command(
        &self,
        global_profile: Option<&PathBuf>,
        args: crate::cli::SetArgs,
    ) -> Result<(), Error> {
        let (profile_input, key) = args.resolve(global_profile);
        let cleanup = if args.to_file.is_some() {
            if args.on_exit {
                FileCleanup::OnExit
            } else {
                FileCleanup::Keep
            }
        } else {
            FileCleanup::OnExit
        };
        let mode = args
            .mode
            .as_deref()
            .map(profile::parse_file_mode)
            .transpose()?
            .unwrap_or(0o600);
        let request = match (args.value, args.from_file, args.to_file) {
            (Some(value), None, target_path) => SecretUpdate::plain_text(key, value)
                .with_mode(mode)
                .with_cleanup(cleanup)
                .with_optional_target_path(target_path),
            (None, Some(source_path), target_path) => SecretUpdate::from_file(key, source_path)
                .with_mode(mode)
                .with_cleanup(cleanup)
                .with_optional_target_path(target_path),
            _ => unreachable!("clap enforces set arguments"),
        };
        self.set_secret(Some(profile_input.as_path()), request)
    }

    fn run_env_delete_command(
        &self,
        global_profile: Option<&PathBuf>,
        args: crate::cli::DeleteArgs,
    ) -> Result<(), Error> {
        let (profile_input, key) = args.resolve(global_profile);
        self.delete_secret(Some(profile_input.as_path()), &key)
    }

    fn run_env_unset_command(
        &self,
        global_profile: Option<&PathBuf>,
        args: crate::cli::UnsetArgs,
    ) -> Result<(), Error> {
        let (profile_input, keys) = args.resolve(global_profile);
        self.delete_secrets(Some(profile_input.as_path()), &keys)
    }

    fn run_env_unset_from_command(
        &self,
        global_profile: Option<&PathBuf>,
        args: crate::cli::UnsetFromArgs,
    ) -> Result<(), Error> {
        let (profile_input, input_paths) = args.resolve(global_profile);
        self.unset_from_env_files(Some(profile_input.as_path()), &input_paths)
    }

    fn run_env_reveal_command(
        &self,
        global_profile: Option<&PathBuf>,
        args: crate::cli::RevealArgs,
    ) -> Result<(), Error> {
        let (profile_input, key) = args.resolve(global_profile);
        let value = self.reveal_secret(Some(profile_input.as_path()), &key)?;
        self.write_revealed_value(&key, &value, args.raw, args.output.as_deref())
    }

    async fn run_profile_or_bundle_command(
        &self,
        _global_profile: Option<&Path>,
        _profile: Option<&PathBuf>,
        args: ProfileArgs,
    ) -> Result<(), Error> {
        if let Some(target) = args.profile.as_deref() {
            self.run_bundle(target).await
        } else {
            let name = args.name.as_deref().ok_or_else(|| {
                Error::Registry(
                    "run requires a bundle path or --name so the registered bundle can be resolved"
                        .to_string(),
                )
            })?;
            self.run_registered_service(name).await
        }
    }

    async fn run_rollback_command(
        &self,
        _global_profile: Option<&PathBuf>,
        args: RollbackArgs,
    ) -> Result<(), Error> {
        self.rollback_service(&args.name).await
    }

    fn run_import_env_command(
        &self,
        global_profile: Option<&PathBuf>,
        args: ImportEnvArgs,
    ) -> Result<(), Error> {
        let (profile_input, input_paths) = args.resolve(global_profile);
        self.import_env_files(
            Some(profile_input.as_path()),
            &input_paths,
            args.prefix.as_deref(),
        )
    }

    fn run_import_assets_command(
        &self,
        global_profile: Option<&PathBuf>,
        args: ImportAssetsArgs,
    ) -> Result<(), Error> {
        if args.uses_inline_spec() {
            let (profile_input, src) = args
                .resolve_inline(global_profile)
                .map_err(Error::InvalidImportSpec)?;
            let target_path = args
                .to_file
                .clone()
                .expect("inline asset to-file is required");
            let key = args
                .key
                .clone()
                .unwrap_or_else(|| infer_asset_key(&target_path));
            self.upsert_asset(
                Some(profile_input.as_path()),
                &key,
                AssetImportSpec {
                    src: Some(src),
                    ref_name: None,
                    to_file: target_path,
                    mode: args.mode.clone().unwrap_or_else(|| "0600".to_string()),
                    cleanup: if args.on_exit {
                        FileCleanup::OnExit
                    } else {
                        FileCleanup::Keep
                    },
                },
            )
        } else {
            let (profile_input, input_paths) = args.resolve(global_profile);
            self.import_asset_specs(Some(profile_input.as_path()), &input_paths)
        }
    }

    pub fn init_profile(
        &self,
        profile_input: Option<&Path>,
        options: &CreateProfileOptions,
    ) -> Result<PathBuf, Error> {
        profile::create_profile(&self.profile_or_default(profile_input), options)
    }

    pub fn set_command(&self, profile_input: Option<&Path>, cmd: Vec<String>) -> Result<(), Error> {
        let profile_input = self.profile_or_default(profile_input);
        profile::ensure_default_profile_exists(&profile_input)?;
        let profile_path = profile::resolve_profile_path(&profile_input);
        let mut loaded = Profile::from_path(&profile_path)?;
        loaded.run.cmd = cmd;
        profile::save_profile_to_path(&profile_path, &loaded)
    }

    pub fn export_bundle(
        &self,
        profile_input: Option<&Path>,
        output_path: &Path,
        options: &BundleExportOptions,
    ) -> Result<(), Error> {
        let profile_input = self.profile_or_default(profile_input);
        profile::ensure_default_profile_exists(&profile_input)?;
        bundle::export_bundle(&profile_input, output_path, options)
    }

    pub fn clear_cached_passphrase(&self) -> Result<(), Error> {
        secure_store::clear_password(&self.secure_store_key()?)
    }

    pub fn reset_state(&self) -> Result<(), Error> {
        let secure_store_key = self.secure_store_key()?;
        secure_store::clear_password(&secure_store_key)?;
        reset_runvault_root()
    }

    pub fn encrypt_file(
        &self,
        input_path: &Path,
        output_path: Option<&Path>,
    ) -> Result<PathBuf, Error> {
        let input = std::fs::read(input_path).map_err(|source| Error::ReadFile {
            path: input_path.to_path_buf(),
            source,
        })?;
        let output_path = output_path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| default_encrypted_path(input_path));
        let password = prompt_password_confirm()?;
        let encrypted = encrypt_file_payload(&input, password)?;
        std::fs::write(&output_path, encrypted).map_err(|source| Error::WriteFile {
            path: output_path.clone(),
            source,
        })?;
        Ok(output_path)
    }

    pub fn generate_jwt(
        &self,
        profile_input: Option<&Path>,
        signing_key: Option<&str>,
        options: &JwtOptions,
    ) -> Result<String, Error> {
        let profile_input = self.profile_or_default(profile_input);
        profile::ensure_default_profile_exists(&profile_input)?;
        let profile_path = profile::resolve_profile_path(&profile_input);
        let loaded = Profile::from_path(&profile_path)?;
        let signing_secret = if let Some(signing_key) = signing_key {
            let env_path = loaded.resolve_env_path(&profile_path);
            if !env_path.exists() {
                return Err(Error::MissingConfigKey(signing_key.to_string()));
            }
            let (vault, _) = self.load_vault_with_lazy_password(&loaded, &profile_path)?;
            match vault.entries().get(signing_key) {
                Some(VaultValue::PlainText(value)) => value.clone(),
                Some(VaultValue::FileContent { .. }) => {
                    return Err(Error::JwtSecretMustBePlainText {
                        key: signing_key.to_string(),
                    });
                }
                Some(VaultValue::SealedVisible(_)) => {
                    unreachable!("JWT command uses the fully materialized vault loader")
                }
                None => return Err(Error::MissingConfigKey(signing_key.to_string())),
            }
        } else {
            generate_signing_secret()?
        };
        generate_hs256(&signing_secret, options)
    }

    pub fn set_secret(
        &self,
        profile_input: Option<&Path>,
        request: SecretUpdate,
    ) -> Result<(), Error> {
        let profile_input = self.profile_or_default(profile_input);
        profile::ensure_default_profile_exists(&profile_input)?;
        let profile_path = profile::resolve_profile_path(&profile_input);
        let mut loaded = Profile::from_path(&profile_path)?;
        let env_path = loaded.resolve_env_path(&profile_path);
        let (mut vault, password) = if env_path.exists() {
            self.load_vault_with_lazy_password_for_update(&loaded, &profile_path)?
        } else {
            (VaultDocument::default(), self.password_for_new_vault()?)
        };

        match (request.source, request.target_path) {
            (SecretSource::PlainText(value), None) => {
                vault.set_plain_text(&request.key, value)?;
                loaded.remove_file_spec(&request.key);
            }
            (SecretSource::PlainText(value), Some(target_path)) => {
                vault.set_file_content(
                    &request.key,
                    target_path.clone(),
                    value.into_bytes(),
                    request.mode,
                    request.cleanup,
                )?;
                loaded.upsert_file_spec(
                    &request.key,
                    FileSpec {
                        target_path,
                        mode: format!("{:04o}", request.mode),
                        cleanup: request.cleanup,
                    },
                );
            }
            (SecretSource::File(source_path), None) => {
                let content = read_profile_source_bytes(&source_path, &password)?;
                let value = String::from_utf8(content)
                    .map_err(|_| Error::FileSourceNotUtf8 { path: source_path })?;
                vault.set_plain_text(&request.key, value)?;
                loaded.remove_file_spec(&request.key);
            }
            (SecretSource::File(source_path), Some(target_path)) => {
                let content = read_profile_source_bytes(&source_path, &password)?;
                vault.set_file_content(
                    &request.key,
                    target_path.clone(),
                    content,
                    request.mode,
                    request.cleanup,
                )?;
                loaded.upsert_file_spec(
                    &request.key,
                    FileSpec {
                        target_path,
                        mode: format!("{:04o}", request.mode),
                        cleanup: request.cleanup,
                    },
                );
            }
        }

        profile::save_profile_to_path(&profile_path, &loaded)?;
        vault::save_vault_with_password(&loaded, &profile_path, &vault, password)
    }

    pub fn init_pki(&self, options: &PkiInitOptions) -> Result<PathBuf, Error> {
        pki::init_infra_pki(self.load_pki_secret_password(true)?, options)
    }

    pub fn issue_pki_certificate(
        &self,
        name: &str,
        options: &PkiIssueOptions,
    ) -> Result<PathBuf, Error> {
        pki::issue_infra_certificate(self.load_pki_secret_password_for_pki_use()?, name, options)
    }

    pub fn rotate_pki(&self) -> Result<(), Error> {
        pki::rotate_infra_certificates(self.load_pki_secret_password_for_pki_use()?)
    }

    pub fn pki_materials(&self) -> Result<Vec<pki::PkiMaterialListing>, Error> {
        pki::list_infra_materials()
    }

    pub fn list_pki_materials(&self) -> Result<(), Error> {
        let materials = self.pki_materials()?;
        println!(
            "{:<32} {:<13} {:<32} MATERIALS",
            "NAME", "KIND", "COMMON NAME"
        );
        for material in materials {
            println!(
                "{:<32} {:<13} {:<32} {}",
                material.name, material.kind, material.common_name, "cert, key, chain"
            );
        }
        Ok(())
    }

    pub fn bundles(&self) -> Result<Vec<BundleListing>, Error> {
        let registry = load_registry()?;
        Ok(registry
            .tracks
            .iter()
            .map(|(name, track)| BundleListing {
                name: name.clone(),
                current_version: track
                    .current_history_index
                    .and_then(|index| track.history.get(index))
                    .map(|entry| entry.version.clone()),
                version_count: bundle_version_entries(name, track).len(),
            })
            .collect())
    }

    pub fn bundle_versions(&self, name: &str) -> Result<Vec<BundleVersionListing>, Error> {
        validate_bundle_name(name)?;
        let registry = load_registry()?;
        let track = registry
            .tracks
            .get(name)
            .ok_or_else(|| Error::Registry(format!("bundle '{}' is not registered", name)))?;
        Ok(bundle_version_entries(name, track))
    }

    pub fn list_bundles(&self) -> Result<(), Error> {
        let bundles = self.bundles()?;
        println!("{:<32} {:<20} VERSIONS", "NAME", "CURRENT");
        for bundle in bundles {
            println!(
                "{:<32} {:<20} {}",
                bundle.name,
                bundle.current_version.as_deref().unwrap_or("-"),
                bundle.version_count
            );
        }
        Ok(())
    }

    fn list_bundle_versions(&self, args: &BundleVersionsArgs) -> Result<(), Error> {
        let versions = self.bundle_versions(&args.name)?;
        println!("{:<20} {:<10} {:<8} PATH", "VERSION", "STATUS", "CURRENT");
        for version in versions {
            println!(
                "{:<20} {:<10} {:<8} {}",
                version.version,
                registry_status_label(version.status),
                if version.current { "yes" } else { "no" },
                version.bundle_path.display()
            );
        }
        Ok(())
    }

    pub fn import_env_files(
        &self,
        profile_input: Option<&Path>,
        input_paths: &[PathBuf],
        prefix: Option<&str>,
    ) -> Result<(), Error> {
        let profile_input = self.profile_or_default(profile_input);
        profile::ensure_default_profile_exists(&profile_input)?;
        let profile_path = profile::resolve_profile_path(&profile_input);
        let mut loaded = Profile::from_path(&profile_path)?;
        let env_path = loaded.resolve_env_path(&profile_path);
        let (mut vault, password) = if env_path.exists() {
            self.load_vault_with_lazy_password_for_update(&loaded, &profile_path)?
        } else {
            (VaultDocument::default(), self.password_for_new_vault()?)
        };

        let mut referenced_specs: BTreeMap<(PathBuf, String), FileImportSpec> = BTreeMap::new();
        for input_path in input_paths {
            let input = std::fs::read(input_path).map_err(|source| Error::ReadFile {
                path: input_path.clone(),
                source,
            })?;
            let input_dir = input_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let vars = parse_env_bytes(&input)?;
            let vars = apply_prefix(vars, prefix.unwrap_or(""))?;
            for (key, value) in vars {
                if let Some(reference) = parse_reference_value(&value) {
                    let reference_path =
                        profile::resolve_source_path(Path::new(&reference), &input_dir)?;
                    let spec = if let Some(spec) =
                        referenced_specs.get(&(reference_path.clone(), key.clone()))
                    {
                        spec.clone()
                    } else {
                        let document = profile::load_file_import_document(&reference_path)?;
                        let spec = document.files.get(&key).cloned().ok_or_else(|| {
                            Error::InvalidImportSpec(format!(
                                "reference file '{}' does not define key '{}'",
                                reference_path.display(),
                                key
                            ))
                        })?;
                        let reference_base_dir =
                            reference_path.parent().unwrap_or_else(|| Path::new("."));
                        let resources = load_global_resources()?;
                        let spec = resolve_file_import_spec(&resources, spec, reference_base_dir)?;
                        referenced_specs
                            .insert((reference_path.clone(), key.clone()), spec.clone());
                        spec
                    };
                    apply_file_import_spec(&mut loaded, &mut vault, &key, spec, &password)?;
                } else {
                    vault.set_plain_text(&key, value)?;
                    loaded.remove_file_spec(&key);
                }
            }
        }

        profile::save_profile_to_path(&profile_path, &loaded)?;
        vault::save_vault_with_password(&loaded, &profile_path, &vault, password)
    }

    pub fn import_asset_specs(
        &self,
        profile_input: Option<&Path>,
        input_paths: &[PathBuf],
    ) -> Result<(), Error> {
        let profile_input = self.profile_or_default(profile_input);
        profile::ensure_default_profile_exists(&profile_input)?;
        let profile_path = profile::resolve_profile_path(&profile_input);
        let mut loaded = Profile::from_path(&profile_path)?;
        let resources = load_global_resources()?;

        for input_path in input_paths {
            let input_path = resolve_import_document_path(&resources, input_path)?;
            let base_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
            let document = profile::load_asset_import_document(&input_path)?;
            for (key, spec) in document.assets {
                let spec = resolve_asset_import_spec(&resources, spec, base_dir)?;
                apply_asset_import_spec(&mut loaded, &key, spec)?;
            }
        }

        profile::save_profile_to_path(&profile_path, &loaded)
    }

    pub fn import_resources(&self, input_paths: &[PathBuf]) -> Result<(), Error> {
        let mut resources = load_global_resources()?;
        for input_path in input_paths {
            let document = profile::load_resource_import_document(input_path)?;
            resources.extend(document.resources);
        }
        save_global_resources(&resources)
    }

    pub fn add_file_resource(
        &self,
        name: &str,
        path: PathBuf,
        description: Option<String>,
    ) -> Result<(), Error> {
        let mut resources = load_global_resources()?;
        resources.insert(
            name.to_string(),
            ResourceRegistryEntry::File { description, path },
        );
        save_global_resources(&resources)
    }

    pub fn add_text_resource(
        &self,
        name: &str,
        value: String,
        description: Option<String>,
    ) -> Result<(), Error> {
        let mut resources = load_global_resources()?;
        resources.insert(
            name.to_string(),
            ResourceRegistryEntry::Text { description, value },
        );
        save_global_resources(&resources)
    }

    pub fn remove_resources(&self, names: &[String]) -> Result<(), Error> {
        let mut resources = load_global_resources()?;
        for name in names {
            resources.remove(name);
        }
        save_global_resources(&resources)
    }

    pub fn remove_resources_from(&self, input_paths: &[PathBuf]) -> Result<(), Error> {
        let mut names = Vec::new();
        for input_path in input_paths {
            let document = profile::load_resource_import_document(input_path)?;
            for name in document.resources.into_keys() {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        self.remove_resources(&names)
    }

    pub fn upsert_asset(
        &self,
        profile_input: Option<&Path>,
        key: &str,
        spec: AssetImportSpec,
    ) -> Result<(), Error> {
        let profile_input = self.profile_or_default(profile_input);
        profile::ensure_default_profile_exists(&profile_input)?;
        let profile_path = profile::resolve_profile_path(&profile_input);
        let mut loaded = Profile::from_path(&profile_path)?;
        let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let resources = load_global_resources()?;
        let spec = resolve_asset_import_spec(&resources, spec, &base_dir)?;
        apply_asset_import_spec(&mut loaded, key, spec)?;
        profile::save_profile_to_path(&profile_path, &loaded)
    }

    pub fn import_file_specs(
        &self,
        profile_input: Option<&Path>,
        input_paths: &[PathBuf],
    ) -> Result<(), Error> {
        let profile_input = self.profile_or_default(profile_input);
        profile::ensure_default_profile_exists(&profile_input)?;
        let profile_path = profile::resolve_profile_path(&profile_input);
        let mut loaded = Profile::from_path(&profile_path)?;
        let env_path = loaded.resolve_env_path(&profile_path);
        let (mut vault, password) = if env_path.exists() {
            self.load_vault_with_lazy_password_for_update(&loaded, &profile_path)?
        } else {
            (VaultDocument::default(), self.password_for_new_vault()?)
        };

        for input_path in input_paths {
            let document = profile::load_file_import_document(input_path)?;
            let resources = load_global_resources()?;
            let base_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
            for (key, spec) in document.files {
                let spec = resolve_file_import_spec(&resources, spec, base_dir)?;
                apply_file_import_spec(&mut loaded, &mut vault, &key, spec, &password)?;
            }
        }

        profile::save_profile_to_path(&profile_path, &loaded)?;
        vault::save_vault_with_password(&loaded, &profile_path, &vault, password)
    }

    pub fn list_resources(&self) -> Result<(), Error> {
        let resources = self.resources()?;
        println!("{:<32} {:<6} DESCRIPTION", "NAME", "TYPE");
        for resource in resources {
            println!(
                "{:<32} {:<6} {}",
                resource.name,
                resource.kind,
                resource.description.unwrap_or_default()
            );
        }
        Ok(())
    }

    pub fn resources(&self) -> Result<Vec<ResourceListing>, Error> {
        Ok(load_global_resources()?
            .iter()
            .map(|(name, entry)| ResourceListing {
                name: name.clone(),
                kind: entry.kind().to_string(),
                description: entry.description().map(ToString::to_string),
            })
            .collect())
    }

    pub fn delete_secret(&self, profile_input: Option<&Path>, key: &str) -> Result<(), Error> {
        self.delete_secrets(profile_input, &[key.to_string()])
    }

    pub fn delete_secrets(
        &self,
        profile_input: Option<&Path>,
        keys: &[String],
    ) -> Result<(), Error> {
        let profile_input = self.profile_or_default(profile_input);
        profile::ensure_default_profile_exists(&profile_input)?;
        let profile_path = profile::resolve_profile_path(&profile_input);
        let mut loaded = Profile::from_path(&profile_path)?;
        let (mut vault, password) =
            self.load_vault_with_lazy_password_for_update(&loaded, &profile_path)?;
        for key in keys {
            vault.delete(key)?;
            loaded.remove_file_spec(key);
        }
        profile::save_profile_to_path(&profile_path, &loaded)?;
        vault::save_vault_with_password(&loaded, &profile_path, &vault, password)
    }

    pub fn unset_from_env_files(
        &self,
        profile_input: Option<&Path>,
        input_paths: &[PathBuf],
    ) -> Result<(), Error> {
        let mut keys = Vec::new();
        for input_path in input_paths {
            let input = std::fs::read(input_path).map_err(|source| Error::ReadFile {
                path: input_path.clone(),
                source,
            })?;
            for key in parse_env_bytes(&input)?.into_keys() {
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        self.delete_secrets(profile_input, &keys)
    }

    pub fn reveal_secret(
        &self,
        profile_input: Option<&Path>,
        key: &str,
    ) -> Result<RevealedValue, Error> {
        let profile_input = self.profile_or_default(profile_input);
        profile::ensure_default_profile_exists(&profile_input)?;
        let profile_path = profile::resolve_profile_path(&profile_input);
        let loaded = Profile::from_path(&profile_path)?;
        let (vault, _) = self.load_vault_with_lazy_password(&loaded, &profile_path)?;
        let value = vault
            .entries()
            .get(key)
            .ok_or_else(|| Error::MissingConfigKey(key.to_string()))?;
        match value {
            VaultValue::PlainText(text) => Ok(RevealedValue::PlainText(text.clone())),
            VaultValue::FileContent {
                path,
                content,
                mode,
                cleanup,
            } => {
                let target_path = loaded
                    .file_spec(key)
                    .map(|spec| spec.target_path.clone())
                    .unwrap_or_else(|| path.clone());
                let mode = loaded
                    .file_spec(key)
                    .map(|spec| profile::parse_file_mode(&spec.mode))
                    .transpose()?
                    .unwrap_or(*mode);
                let cleanup = loaded
                    .file_spec(key)
                    .map(|spec| spec.cleanup)
                    .unwrap_or(*cleanup);
                Ok(RevealedValue::File(RevealedFile {
                    target_path,
                    content: content.clone(),
                    mode,
                    cleanup,
                }))
            }
            VaultValue::SealedVisible(_) => Err(Error::VaultFormat(format!(
                "key '{key}' was not materialized before reveal"
            ))),
        }
    }

    pub fn add_ping_target(
        &self,
        profile_input: Option<&Path>,
        target: PingTarget,
    ) -> Result<(), Error> {
        let profile_input = self.profile_or_default(profile_input);
        profile::ensure_default_profile_exists(&profile_input)?;
        let profile_path = profile::resolve_profile_path(&profile_input);
        let mut loaded = Profile::from_path(&profile_path)?;
        loaded.upsert_ping_target(target);
        profile::save_profile_to_path(&profile_path, &loaded)
    }

    pub async fn run_profile(&self, profile_input: &Path) -> Result<(), Error> {
        let profile_input = self.profile_or_default(Some(profile_input));
        profile::ensure_default_profile_exists(&profile_input)?;
        let profile_path = profile::resolve_profile_path(&profile_input);
        run::run_profile_with_secure_store_key_in_dir(
            &profile_path,
            &self.secure_store_key()?,
            &self.execution_dir(),
        )
        .await
    }

    pub async fn run_bundle(&self, bundle_path: &Path) -> Result<(), Error> {
        let bundle = bundle::load_bundle(bundle_path)?;
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

        let run_result = self
            .execute_bundle_at_path(&stored_bundle_path, &stored_dir)
            .await;

        if let Some(index) = history_index {
            match run_result {
                Ok(()) => {
                    mark_history_entry(
                        &mut registry,
                        &track,
                        index,
                        RegistryEntryStatus::Succeeded,
                    )?;
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

    pub async fn run_registered_service(&self, name: &str) -> Result<(), Error> {
        validate_bundle_name(name)?;
        let registry = load_registry()?;
        let bundle_path = current_bundle_path(&registry, name)?;
        let bundle_dir = bundle_path
            .parent()
            .ok_or_else(|| {
                Error::Registry(format!(
                    "registered bundle path '{}' has no parent directory",
                    bundle_path.display()
                ))
            })?
            .to_path_buf();
        self.execute_bundle_at_path(&bundle_path, &bundle_dir).await
    }

    pub async fn rollback_service(&self, name: &str) -> Result<(), Error> {
        validate_bundle_name(name)?;
        let mut registry = load_registry()?;
        let bundle_path = previous_successful_bundle_path(&registry, name)?;
        let bundle = bundle::load_bundle(&bundle_path)?;
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

        let index = append_history_entry(&mut registry, name, &version, bundle_path.clone())?;
        save_registry(&registry)?;

        match self.execute_bundle_at_path(&bundle_path, &bundle_dir).await {
            Ok(()) => {
                mark_history_entry(&mut registry, name, index, RegistryEntryStatus::Succeeded)?;
                save_registry(&registry)?;
                Ok(())
            }
            Err(err) => {
                mark_history_entry(&mut registry, name, index, RegistryEntryStatus::Failed)?;
                save_registry(&registry)?;
                Err(err)
            }
        }
    }

    pub async fn ping_profile(&self, profile_input: &Path) -> Result<(), Error> {
        run::ping_profile(&self.profile_or_default(Some(profile_input))).await
    }

    fn write_revealed_value(
        &self,
        key: &str,
        value: &RevealedValue,
        raw: bool,
        output: Option<&Path>,
    ) -> Result<(), Error> {
        match value {
            RevealedValue::PlainText(text) => {
                if let Some(path) = output {
                    std::fs::write(path, text.as_bytes()).map_err(|source| Error::WriteFile {
                        path: path.to_path_buf(),
                        source,
                    })?;
                } else {
                    println!("{}", text);
                }
            }
            RevealedValue::File(file) => {
                if let Some(output_path) = output {
                    std::fs::write(output_path, &file.content).map_err(|source| {
                        Error::WriteFile {
                            path: output_path.to_path_buf(),
                            source,
                        }
                    })?;
                } else if raw {
                    let mut stdout = std::io::stdout().lock();
                    stdout
                        .write_all(&file.content)
                        .map_err(Error::PasswordPrompt)?;
                    stdout.flush().map_err(Error::PasswordPrompt)?;
                } else {
                    println!("key: {}", key);
                    println!("kind: file");
                    println!("target_path: {}", file.target_path.display());
                    println!("size_bytes: {}", file.content.len());
                    println!("mode: {:04o}", file.mode);
                    println!(
                        "cleanup: {}",
                        match file.cleanup {
                            FileCleanup::OnExit => "on_exit",
                            FileCleanup::Keep => "keep",
                        }
                    );
                }
            }
        }
        Ok(())
    }

    async fn execute_bundle_at_path(
        &self,
        bundle_path: &Path,
        bundle_dir: &Path,
    ) -> Result<(), Error> {
        let bundle = bundle::load_bundle(bundle_path)?;
        let profile_path = bundle::materialize_bundle_into(bundle_dir, &bundle)?;
        run::run_profile_with_secure_store_key_in_dir(
            &profile_path,
            &self.secure_store_key()?,
            bundle_dir,
        )
        .await
    }

    fn load_vault_with_lazy_password(
        &self,
        profile: &Profile,
        profile_path: &Path,
    ) -> Result<(VaultDocument, SecretString), Error> {
        let secure_store_key = self.secure_store_key()?;
        if let Some(password) = secure_store::load_password(&secure_store_key)? {
            match vault::load_vault_with_password(profile, profile_path, password.clone()) {
                Ok(vault) => {
                    secure_store::store_password_if_possible(&secure_store_key, &password)?;
                    return Ok((vault, password));
                }
                Err(Error::Decryption(_)) => {
                    secure_store::clear_password(&secure_store_key)?;
                }
                Err(err) => return Err(err),
            }
        }

        let password = prompt_password_once()?;
        let vault = vault::load_vault_with_password(profile, profile_path, password.clone())?;
        secure_store::store_password_if_possible(&secure_store_key, &password)?;
        Ok((vault, password))
    }

    fn load_pki_secret_password(&self, confirm_if_uncached: bool) -> Result<SecretString, Error> {
        let secure_store_key = self.secure_store_key()?;
        if let Some(password) = secure_store::load_password(&secure_store_key)? {
            secure_store::store_password_if_possible(&secure_store_key, &password)?;
            return Ok(password);
        }

        let password = if confirm_if_uncached {
            prompt_password_confirm()?
        } else {
            prompt_password_once()?
        };
        secure_store::store_password_if_possible(&secure_store_key, &password)?;
        Ok(password)
    }

    fn load_pki_secret_password_for_pki_use(&self) -> Result<SecretString, Error> {
        let needs_init = !pki::pki_infra_path()?.exists();
        self.load_pki_secret_password(needs_init)
    }

    fn load_vault_with_lazy_password_for_update(
        &self,
        profile: &Profile,
        profile_path: &Path,
    ) -> Result<(VaultDocument, SecretString), Error> {
        let secure_store_key = self.secure_store_key()?;
        if let Some(password) = secure_store::load_password(&secure_store_key)? {
            match vault::load_vault_for_update_with_password(
                profile,
                profile_path,
                password.clone(),
            ) {
                Ok(vault) => {
                    secure_store::store_password_if_possible(&secure_store_key, &password)?;
                    return Ok((vault, password));
                }
                Err(Error::Decryption(_)) => {
                    secure_store::clear_password(&secure_store_key)?;
                }
                Err(err) => return Err(err),
            }
        }

        let password = prompt_password_once()?;
        let vault =
            vault::load_vault_for_update_with_password(profile, profile_path, password.clone())?;
        secure_store::store_password_if_possible(&secure_store_key, &password)?;
        Ok((vault, password))
    }

    fn password_for_new_vault(&self) -> Result<SecretString, Error> {
        let secure_store_key = self.secure_store_key()?;
        if let Some(password) = secure_store::load_password(&secure_store_key)? {
            secure_store::store_password_if_possible(&secure_store_key, &password)?;
            return Ok(password);
        }
        let password = prompt_password_confirm()?;
        secure_store::store_password_if_possible(&secure_store_key, &password)?;
        Ok(password)
    }

    fn profile_or_default(&self, profile_input: Option<&Path>) -> PathBuf {
        profile_input
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.default_profile.clone())
    }

    fn secure_store_key(&self) -> Result<PathBuf, Error> {
        if let Some(path) = &self.secure_store_key {
            Ok(path.clone())
        } else {
            global_passphrase_store_key()
        }
    }

    fn execution_dir(&self) -> PathBuf {
        self.execution_dir
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }
}

impl SecretUpdate {
    fn with_optional_target_path(mut self, target_path: Option<PathBuf>) -> Self {
        self.target_path = target_path;
        self
    }
}

fn parse_ip_addrs(values: Vec<String>) -> Result<Vec<IpAddr>, Error> {
    values
        .into_iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| Error::Pki(format!("invalid IP address '{}'", value)))
        })
        .collect()
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
    bundle::materialize_bundle_into(&bundle_dir, bundle)?;
    Ok(stored_bundle_path)
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
    let name = bundle_name(bundle)?;
    validate_bundle_name(&name)?;
    Ok(name)
}

fn bundle_name(bundle: &BundleDocument) -> Result<String, Error> {
    bundle
        .name
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::InvalidBundle(
                "bundle name is required for registry-backed execution".to_string(),
            )
        })
}

fn validate_bundle_name(name: &str) -> Result<(), Error> {
    if name.trim().is_empty() {
        return Err(Error::Registry("bundle name must not be empty".to_string()));
    }
    Ok(())
}

fn bundle_version_entries(name: &str, track: &RegistryTrack) -> Vec<BundleVersionListing> {
    let current_version = track
        .current_history_index
        .and_then(|index| track.history.get(index))
        .map(|entry| entry.version.as_str());
    let mut versions: BTreeMap<String, BundleVersionListing> = BTreeMap::new();
    for entry in &track.history {
        let listing =
            versions
                .entry(entry.version.clone())
                .or_insert_with(|| BundleVersionListing {
                    name: name.to_string(),
                    version: entry.version.clone(),
                    status: entry.status,
                    current: current_version.is_some_and(|current| current == entry.version),
                    bundle_path: entry.bundle_path.clone(),
                });
        listing.current = current_version.is_some_and(|current| current == entry.version);
        listing.status = merge_registry_status(listing.status, entry.status);
        if entry.status == RegistryEntryStatus::Succeeded {
            listing.bundle_path = entry.bundle_path.clone();
        }
    }
    versions.into_values().collect()
}

fn merge_registry_status(
    left: RegistryEntryStatus,
    right: RegistryEntryStatus,
) -> RegistryEntryStatus {
    match (left, right) {
        (RegistryEntryStatus::Succeeded, _) | (_, RegistryEntryStatus::Succeeded) => {
            RegistryEntryStatus::Succeeded
        }
        (RegistryEntryStatus::Failed, _) | (_, RegistryEntryStatus::Failed) => {
            RegistryEntryStatus::Failed
        }
        _ => RegistryEntryStatus::Registered,
    }
}

fn registry_status_label(status: RegistryEntryStatus) -> &'static str {
    match status {
        RegistryEntryStatus::Registered => "registered",
        RegistryEntryStatus::Succeeded => "succeeded",
        RegistryEntryStatus::Failed => "failed",
    }
}

fn global_resources_path() -> Result<PathBuf, Error> {
    Ok(runvault_root()?.join("resources.yaml"))
}

fn load_global_resources() -> Result<BTreeMap<String, ResourceRegistryEntry>, Error> {
    let path = global_resources_path()?;
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let content = std::fs::read_to_string(&path).map_err(|source| Error::ReadFile {
        path: path.clone(),
        source,
    })?;
    let document: profile::ResourceImportDocument =
        serde_yaml::from_str(&content).map_err(|source| {
            Error::Registry(format!("failed to parse {}: {}", path.display(), source))
        })?;
    Ok(document.resources)
}

fn save_global_resources(resources: &BTreeMap<String, ResourceRegistryEntry>) -> Result<(), Error> {
    let path = global_resources_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| Error::WriteFile {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let document = profile::ResourceImportDocument {
        resources: resources.clone(),
    };
    let yaml = serde_yaml::to_string(&document)
        .map_err(|source| Error::Registry(format!("failed to serialize resources: {source}")))?;
    std::fs::write(&path, yaml).map_err(|source| Error::WriteFile { path, source })
}

fn apply_file_import_spec(
    profile: &mut Profile,
    vault: &mut VaultDocument,
    key: &str,
    spec: FileImportSpec,
    password: &SecretString,
) -> Result<(), Error> {
    let content = if let Some(value) = spec.resolved_value.clone() {
        value
    } else {
        let src = spec.src.as_deref().ok_or_else(|| {
            Error::InvalidImportSpec(format!("file import '{}' was not resolved to a src", key))
        })?;
        read_profile_source_bytes(src, password)?
    };
    if let Some(target_path) = spec.to_file {
        let mode = profile::parse_file_mode(&spec.mode)?;
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
        let value = String::from_utf8(content).map_err(|_| Error::FileSourceNotUtf8 {
            path: spec
                .src
                .clone()
                .unwrap_or_else(|| PathBuf::from("<resource-registry-text>")),
        })?;
        vault.set_plain_text(key, value)?;
        profile.remove_file_spec(key);
    }
    Ok(())
}

fn resolve_file_import_spec(
    resources: &BTreeMap<String, ResourceRegistryEntry>,
    mut spec: FileImportSpec,
    base_dir: &Path,
) -> Result<FileImportSpec, Error> {
    if let Some(ref_name) = spec.ref_name.take() {
        resolve_file_registry_ref(resources, &mut spec, &ref_name, base_dir)?;
    } else if let Some(ref_name) = spec.src.as_deref().and_then(parse_source_reference) {
        if resources.contains_key(&ref_name) {
            resolve_file_registry_ref(resources, &mut spec, &ref_name, base_dir)?;
        } else {
            spec.src = Some(profile::resolve_source_path(
                Path::new(&ref_name),
                base_dir,
            )?);
        }
    }

    if let Some(src) = &mut spec.src {
        *src = profile::resolve_source_path(src, base_dir)?;
    }
    Ok(spec)
}

fn resolve_import_document_path(
    resources: &BTreeMap<String, ResourceRegistryEntry>,
    path: &Path,
) -> Result<PathBuf, Error> {
    let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if let Some(ref_name) = parse_source_reference(path) {
        return match resources.get(&ref_name) {
            Some(ResourceRegistryEntry::File { path, .. }) => {
                profile::resolve_source_path(path, &base_dir)
            }
            Some(ResourceRegistryEntry::Text { .. }) => Err(Error::InvalidImportSpec(format!(
                "import document ref '{}' must point to a file resource",
                ref_name
            ))),
            None => Err(Error::InvalidImportSpec(format!(
                "import document ref '{}' does not exist",
                ref_name
            ))),
        };
    }
    profile::resolve_source_path(path, &base_dir)
}

fn resolve_file_registry_ref(
    resources: &BTreeMap<String, ResourceRegistryEntry>,
    spec: &mut FileImportSpec,
    ref_name: &str,
    base_dir: &Path,
) -> Result<(), Error> {
    let entry = resources.get(ref_name).ok_or_else(|| {
        Error::InvalidImportSpec(format!(
            "resource registry entry '{}' does not exist",
            ref_name
        ))
    })?;
    match entry {
        ResourceRegistryEntry::File { path, .. } => {
            spec.src = Some(profile::resolve_source_path(path, base_dir)?);
        }
        ResourceRegistryEntry::Text { value, .. } => {
            spec.src = None;
            spec.resolved_value = Some(value.as_bytes().to_vec());
        }
    }
    Ok(())
}

fn read_profile_source_bytes(path: &Path, password: &SecretString) -> Result<Vec<u8>, Error> {
    let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let resolved = profile::resolve_source_path(path, &base_dir)?;
    let content = std::fs::read(&resolved).map_err(|source| Error::ReadFile {
        path: resolved,
        source,
    })?;
    Ok(maybe_decrypt_file_payload(&content, password.clone())?.to_vec())
}

fn resolve_asset_import_spec(
    resources: &BTreeMap<String, ResourceRegistryEntry>,
    mut spec: AssetImportSpec,
    base_dir: &Path,
) -> Result<AssetImportSpec, Error> {
    if let Some(ref_name) = spec.ref_name.take() {
        resolve_resource_registry_ref(resources, &mut spec, &ref_name, base_dir)?;
    } else if let Some(ref_name) = spec.src.as_deref().and_then(parse_source_reference) {
        if resources.contains_key(&ref_name) {
            resolve_resource_registry_ref(resources, &mut spec, &ref_name, base_dir)?;
        } else {
            spec.src = Some(profile::resolve_source_path(
                Path::new(&ref_name),
                base_dir,
            )?);
        }
    }
    if let Some(src) = &mut spec.src {
        *src = profile::resolve_source_path(src, base_dir)?;
    }
    Ok(spec)
}

fn resolve_resource_registry_ref(
    resources: &BTreeMap<String, ResourceRegistryEntry>,
    spec: &mut AssetImportSpec,
    ref_name: &str,
    base_dir: &Path,
) -> Result<(), Error> {
    let entry = resources.get(ref_name).ok_or_else(|| {
        Error::InvalidImportSpec(format!(
            "resource registry entry '{}' does not exist",
            ref_name
        ))
    })?;
    match entry {
        ResourceRegistryEntry::File { path, .. } => {
            spec.src = Some(profile::resolve_source_path(path, base_dir)?);
        }
        ResourceRegistryEntry::Text { .. } => {
            return Err(Error::InvalidImportSpec(format!(
                "asset import ref '{}' must point to a file resource",
                ref_name
            )));
        }
    }
    Ok(())
}

fn parse_source_reference(path: &Path) -> Option<String> {
    path.to_str()
        .and_then(parse_reference_value)
        .filter(|value| !value.trim().is_empty())
}

fn apply_asset_import_spec(
    profile: &mut Profile,
    key: &str,
    spec: AssetImportSpec,
) -> Result<(), Error> {
    let source_path = spec.src.ok_or_else(|| {
        Error::InvalidImportSpec(format!("asset import '{}' was not resolved to a src", key))
    })?;
    profile.assets.insert(
        key.to_string(),
        AssetSpec {
            source_path,
            target_path: spec.to_file,
            mode: spec.mode,
            cleanup: spec.cleanup,
        },
    );
    Ok(())
}

fn infer_asset_key(target_path: &Path) -> String {
    let mut key = String::from("ASSET_");
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

    if key == "ASSET" || key == "ASSET_" {
        "ASSET_FILE".to_string()
    } else {
        key
    }
}

#[cfg(test)]
mod tests {
    use super::Runvault;
    use crate::{
        profile::{self, CreateProfileOptions, Profile},
        registry::{
            RegistryDocument, RegistryEntryStatus, append_history_entry, mark_history_entry,
            save_registry,
        },
    };
    use std::{
        path::{Path, PathBuf},
        sync::Mutex,
    };
    use tempfile::tempdir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn bundle_listing_returns_registered_names_and_versions() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", dir.path());
        }

        let mut registry = RegistryDocument::default();
        let v1 = append_history_entry(
            &mut registry,
            "workers",
            "v1",
            PathBuf::from("/tmp/workers/v1/bundle.yaml"),
        )
        .unwrap();
        mark_history_entry(&mut registry, "workers", v1, RegistryEntryStatus::Succeeded).unwrap();
        let v2 = append_history_entry(
            &mut registry,
            "workers",
            "v2",
            PathBuf::from("/tmp/workers/v2/bundle.yaml"),
        )
        .unwrap();
        mark_history_entry(&mut registry, "workers", v2, RegistryEntryStatus::Failed).unwrap();
        save_registry(&registry).unwrap();

        let bundles = Runvault::default().bundles().unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].name, "workers");
        assert_eq!(bundles[0].current_version.as_deref(), Some("v1"));
        assert_eq!(bundles[0].version_count, 2);

        let versions = Runvault::default().bundle_versions("workers").unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "v1");
        assert_eq!(versions[0].status, RegistryEntryStatus::Succeeded);
        assert!(versions[0].current);
        assert_eq!(versions[1].version, "v2");
        assert_eq!(versions[1].status, RegistryEntryStatus::Failed);
        assert!(!versions[1].current);

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn import_assets_resolves_at_source_from_resources_first() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
        let profile_dir = dir.path().join("profile");
        profile::create_profile(
            &profile_dir,
            &CreateProfileOptions {
                name: Some("test".to_string()),
                env_file: PathBuf::from("env.sec"),
            },
        )
        .unwrap();
        std::fs::write(dir.path().join("Caddyfile"), ":443 { respond ok }\n").unwrap();
        let spec_path = dir.path().join("assets.yaml");
        std::fs::write(
            &spec_path,
            r#"
assets:
  CADDY_CONFIG_FILE:
    src: "@caddy.main_config"
    to-file: ./Caddyfile
"#,
        )
        .unwrap();

        Runvault::default()
            .add_file_resource(
                "caddy.main_config",
                PathBuf::from("./Caddyfile"),
                Some("Main Caddy config".to_string()),
            )
            .unwrap();
        Runvault::default()
            .import_asset_specs(Some(&profile_dir), &[spec_path])
            .unwrap();

        let profile = Profile::from_path(&profile_dir.join(profile::DEFAULT_PROFILE_FILE)).unwrap();
        let spec = profile.assets().get("CADDY_CONFIG_FILE").unwrap();
        assert_eq!(spec.source_path, dir.path().join("Caddyfile"));

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn import_assets_loads_spec_file_from_resource_reference() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
        let profile_dir = dir.path().join("profile");
        profile::create_profile(
            &profile_dir,
            &CreateProfileOptions {
                name: Some("test".to_string()),
                env_file: PathBuf::from("env.sec"),
            },
        )
        .unwrap();

        let specs_dir = dir.path().join("specs");
        std::fs::create_dir_all(&specs_dir).unwrap();
        std::fs::write(specs_dir.join("Caddyfile"), ":443 { respond ok }\n").unwrap();
        let spec_path = specs_dir.join("run.assets.yaml");
        std::fs::write(
            &spec_path,
            r#"
assets:
  CADDY_CONFIG_FILE:
    src: ./Caddyfile
    to-file: ./Caddyfile
"#,
        )
        .unwrap();

        Runvault::default()
            .add_file_resource("run.assets", spec_path.clone(), None)
            .unwrap();
        Runvault::default()
            .import_asset_specs(Some(&profile_dir), &[PathBuf::from("@run.assets")])
            .unwrap();

        let profile = Profile::from_path(&profile_dir.join(profile::DEFAULT_PROFILE_FILE)).unwrap();
        let spec = profile.assets().get("CADDY_CONFIG_FILE").unwrap();
        assert_eq!(spec.source_path, specs_dir.join("Caddyfile"));

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn import_assets_rejects_missing_spec_file_resource_reference() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
        let profile_dir = dir.path().join("profile");
        profile::create_profile(
            &profile_dir,
            &CreateProfileOptions {
                name: Some("test".to_string()),
                env_file: PathBuf::from("env.sec"),
            },
        )
        .unwrap();

        let err = Runvault::default()
            .import_asset_specs(Some(&profile_dir), &[PathBuf::from("@run.assets")])
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("import document ref 'run.assets' does not exist")
        );

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn import_assets_falls_back_to_at_source_as_relative_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
        let profile_dir = dir.path().join("profile");
        profile::create_profile(
            &profile_dir,
            &CreateProfileOptions {
                name: Some("test".to_string()),
                env_file: PathBuf::from("env.sec"),
            },
        )
        .unwrap();
        std::fs::write(dir.path().join("Caddyfile"), ":443 { respond ok }\n").unwrap();
        let spec_path = dir.path().join("assets.yaml");
        std::fs::write(
            &spec_path,
            r#"
assets:
  CADDY_CONFIG_FILE:
    src: "@Caddyfile"
    to-file: ./Caddyfile
"#,
        )
        .unwrap();

        Runvault::default()
            .import_asset_specs(Some(&profile_dir), &[spec_path])
            .unwrap();

        let profile = Profile::from_path(&profile_dir.join(profile::DEFAULT_PROFILE_FILE)).unwrap();
        let spec = profile.assets().get("CADDY_CONFIG_FILE").unwrap();
        assert_eq!(spec.source_path, dir.path().join(Path::new("Caddyfile")));

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn resources_returns_registry_entries_for_library_callers() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", dir.path());
        }

        Runvault::default()
            .add_text_resource(
                "app.namespace",
                "glt-market".to_string(),
                Some("Shared app namespace".to_string()),
            )
            .unwrap();

        let resources = Runvault::default().resources().unwrap();

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].name, "app.namespace");
        assert_eq!(resources[0].kind, "text");
        assert_eq!(
            resources[0].description.as_deref(),
            Some("Shared app namespace")
        );

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn import_and_remove_resources_use_global_registry() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempdir().unwrap();
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
        let resources_path = dir.path().join("resources.yaml");
        std::fs::write(
            &resources_path,
            r#"
resources:
  caddy.main_config:
    type: file
    description: Main Caddy config
    path: ./Caddyfile
"#,
        )
        .unwrap();

        let runvault = Runvault::default();
        runvault
            .import_resources(std::slice::from_ref(&resources_path))
            .unwrap();
        assert_eq!(runvault.resources().unwrap().len(), 1);

        runvault
            .remove_resources_from(std::slice::from_ref(&resources_path))
            .unwrap();
        assert!(runvault.resources().unwrap().is_empty());

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}

fn default_encrypted_path(input: &Path) -> PathBuf {
    if let Some(file_name) = input.file_name().and_then(|value| value.to_str()) {
        if matches!(file_name, ".env" | "env") {
            return input.with_file_name("env.sec");
        }
        return input.with_file_name(format!("{}.enc", file_name));
    }
    input.with_extension("enc")
}

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned},
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::{
    envfile::{parse_reference_value, validate_env_key},
    error::Error,
    pki,
};

pub const DEFAULT_PROFILE_FILE: &str = "runvault.yaml";
pub const DEFAULT_ENV_FILE: &str = "env.sec";
pub const DEFAULT_PROFILE_DIR: &str = ".vault";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FileCleanup {
    #[default]
    OnExit,
    Keep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSpec {
    pub target_path: PathBuf,
    #[serde(default = "default_file_mode")]
    pub mode: String,
    #[serde(default)]
    pub cleanup: FileCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetSpec {
    pub source_path: PathBuf,
    pub target_path: PathBuf,
    #[serde(default = "default_file_mode")]
    pub mode: String,
    #[serde(default)]
    pub cleanup: FileCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileImportSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<PathBuf>,
    #[serde(
        default,
        rename = "ref",
        alias = "resource",
        skip_serializing_if = "Option::is_none"
    )]
    pub ref_name: Option<String>,
    #[serde(
        default,
        rename = "to-file",
        alias = "to_file",
        alias = "target_path",
        skip_serializing_if = "Option::is_none"
    )]
    pub to_file: Option<PathBuf>,
    #[serde(default = "default_file_mode")]
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<FileCleanup>,
    #[serde(skip)]
    pub(crate) resolved_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FileImportDocument {
    #[serde(
        default,
        rename = "resources",
        alias = "resource_registry",
        alias = "resources_registry",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub resources: BTreeMap<String, ResourceRegistryEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, FileImportSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetImportSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<PathBuf>,
    #[serde(
        default,
        rename = "ref",
        alias = "resource",
        skip_serializing_if = "Option::is_none"
    )]
    pub ref_name: Option<String>,
    #[serde(rename = "to-file", alias = "to_file", alias = "target_path")]
    pub to_file: PathBuf,
    #[serde(default = "default_file_mode")]
    pub mode: String,
    #[serde(default)]
    pub cleanup: FileCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct AssetImportDocument {
    #[serde(
        default,
        rename = "resources",
        alias = "resource_registry",
        alias = "resources_registry",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub resources: BTreeMap<String, ResourceRegistryEntry>,
    #[serde(default, rename = "assets", skip_serializing_if = "BTreeMap::is_empty")]
    pub assets: BTreeMap<String, AssetImportSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResourceRegistryEntry {
    File {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        path: PathBuf,
    },
    Text {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        value: String,
    },
}

impl ResourceRegistryEntry {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Text { .. } => "text",
        }
    }

    pub fn description(&self) -> Option<&str> {
        match self {
            Self::File { description, .. } | Self::Text { description, .. } => {
                description.as_deref()
            }
        }
    }
}

impl<'de> Deserialize<'de> for AssetImportDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawAssetImportDocument {
            #[serde(default)]
            assets: BTreeMap<String, AssetImportSpec>,
            #[serde(default)]
            resources: Option<serde_yaml::Value>,
            #[serde(default)]
            resource_registry: BTreeMap<String, ResourceRegistryEntry>,
            #[serde(default)]
            resources_registry: BTreeMap<String, ResourceRegistryEntry>,
        }

        let raw = RawAssetImportDocument::deserialize(deserializer)?;
        let mut assets = raw.assets;
        let mut resources = raw.resource_registry;
        resources.extend(raw.resources_registry);

        if let Some(value) = raw.resources {
            if let Some(parsed_resources) =
                parse_optional_yaml_map::<ResourceRegistryEntry, D::Error>(&value)?
            {
                resources.extend(parsed_resources);
            } else {
                assets.extend(parse_yaml_map::<AssetImportSpec, D::Error>(value)?);
            }
        }

        Ok(Self { resources, assets })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Profile {
    pub name: String,
    #[serde(default = "default_env_file")]
    pub env_file: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, FileSpec>,
    #[serde(default, rename = "assets", skip_serializing_if = "BTreeMap::is_empty")]
    pub assets: BTreeMap<String, AssetSpec>,
    #[serde(
        default,
        rename = "resources",
        alias = "resource_registry",
        alias = "resources_registry",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub resources: BTreeMap<String, ResourceRegistryEntry>,
    pub run: RunConfig,
    #[serde(default)]
    pub pings: Vec<PingTarget>,
    #[serde(skip)]
    pub(crate) implicit_workdir: bool,
}

impl<'de> Deserialize<'de> for Profile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawProfile {
            name: String,
            #[serde(default = "default_env_file")]
            env_file: PathBuf,
            #[serde(default)]
            workdir: Option<PathBuf>,
            #[serde(default)]
            files: BTreeMap<String, FileSpec>,
            #[serde(default)]
            assets: BTreeMap<String, AssetSpec>,
            #[serde(default)]
            resources: Option<serde_yaml::Value>,
            #[serde(default)]
            resource_registry: BTreeMap<String, ResourceRegistryEntry>,
            #[serde(default)]
            resources_registry: BTreeMap<String, ResourceRegistryEntry>,
            run: RunConfig,
            #[serde(default)]
            pings: Vec<PingTarget>,
        }

        let raw = RawProfile::deserialize(deserializer)?;
        let mut assets = raw.assets;
        let mut resources = raw.resource_registry;
        resources.extend(raw.resources_registry);

        if let Some(value) = raw.resources {
            if let Some(parsed_resources) =
                parse_optional_yaml_map::<ResourceRegistryEntry, D::Error>(&value)?
            {
                resources.extend(parsed_resources);
            } else {
                assets.extend(parse_yaml_map::<AssetSpec, D::Error>(value)?);
            }
        }

        Ok(Self {
            name: raw.name,
            env_file: raw.env_file,
            workdir: raw.workdir,
            files: raw.files,
            assets,
            resources,
            run: raw.run,
            pings: raw.pings,
            implicit_workdir: false,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    pub cmd: Vec<String>,
    #[serde(default = "default_clear_env")]
    pub clear_env: bool,
    #[serde(default)]
    pub pass_env: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PingTarget {
    pub name: String,
    pub url: String,
    #[serde(default = "default_ping_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_ping_interval_millis")]
    pub interval_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateProfileOptions {
    pub name: Option<String>,
    pub env_file: PathBuf,
}

fn default_clear_env() -> bool {
    true
}

fn default_env_file() -> PathBuf {
    PathBuf::from(DEFAULT_ENV_FILE)
}

fn default_file_mode() -> String {
    "0600".to_string()
}

fn default_ping_timeout_seconds() -> u64 {
    30
}

fn default_ping_interval_millis() -> u64 {
    500
}

fn parse_optional_yaml_map<T, E>(
    value: &serde_yaml::Value,
) -> Result<Option<BTreeMap<String, T>>, E>
where
    T: DeserializeOwned,
    E: de::Error,
{
    match serde_yaml::from_value(value.clone()) {
        Ok(map) => Ok(Some(map)),
        Err(_) => Ok(None),
    }
}

fn parse_yaml_map<T, E>(value: serde_yaml::Value) -> Result<BTreeMap<String, T>, E>
where
    T: DeserializeOwned,
    E: de::Error,
{
    serde_yaml::from_value(value).map_err(E::custom)
}

impl Profile {
    pub fn from_path(path: &Path) -> Result<Self, Error> {
        let content = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        let mut profile: Profile =
            serde_yaml::from_str(&content).map_err(|source| Error::ProfileParse {
                path: path.to_path_buf(),
                source,
            })?;
        profile.implicit_workdir = profile.workdir.is_none();
        profile.validate()?;
        Ok(profile)
    }

    pub fn resolve_env_path(&self, profile_path: &Path) -> PathBuf {
        if self.env_file.is_absolute() {
            return self.env_file.clone();
        }
        profile_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&self.env_file)
    }

    pub fn file_spec(&self, key: &str) -> Option<&FileSpec> {
        self.files.get(key)
    }

    pub fn assets(&self) -> &BTreeMap<String, AssetSpec> {
        &self.assets
    }

    pub fn upsert_file_spec(&mut self, key: &str, spec: FileSpec) {
        self.files.insert(key.to_string(), spec);
    }

    pub fn remove_file_spec(&mut self, key: &str) {
        self.files.remove(key);
    }

    pub fn upsert_ping_target(&mut self, target: PingTarget) {
        if let Some(existing) = self.pings.iter_mut().find(|ping| ping.name == target.name) {
            *existing = target;
        } else {
            self.pings.push(target);
        }
    }

    pub fn merge_resource_registry(&mut self, entries: BTreeMap<String, ResourceRegistryEntry>) {
        self.resources.extend(entries);
    }

    fn validate(&self) -> Result<(), Error> {
        if self.name.trim().is_empty() {
            return Err(Error::InvalidProfile("name must not be empty".to_string()));
        }
        if self.run.cmd.is_empty() {
            return Err(Error::InvalidProfile(
                "run.cmd must include at least one command element".to_string(),
            ));
        }
        for ping in &self.pings {
            if ping.name.trim().is_empty() {
                return Err(Error::InvalidProfile(
                    "ping target name must not be empty".to_string(),
                ));
            }
            if ping.url.trim().is_empty() {
                return Err(Error::InvalidProfile(format!(
                    "ping target '{}' url must not be empty",
                    ping.name
                )));
            }
        }
        for (key, spec) in &self.files {
            if !validate_env_key(key) {
                return Err(Error::InvalidProfile(format!(
                    "file spec key '{}' is not a valid env key",
                    key
                )));
            }
            if spec.target_path.as_os_str().is_empty() {
                return Err(Error::InvalidProfile(format!(
                    "file spec '{}' target_path must not be empty",
                    key
                )));
            }
            parse_file_mode(&spec.mode)?;
        }
        for (key, spec) in &self.assets {
            if !validate_env_key(key) {
                return Err(Error::InvalidProfile(format!(
                    "resource key '{}' is not a valid env key",
                    key
                )));
            }
            if spec.source_path.as_os_str().is_empty() {
                return Err(Error::InvalidProfile(format!(
                    "resource '{}' source_path must not be empty",
                    key
                )));
            }
            if spec.target_path.as_os_str().is_empty() {
                return Err(Error::InvalidProfile(format!(
                    "resource '{}' target_path must not be empty",
                    key
                )));
            }
            parse_file_mode(&spec.mode)?;
        }
        validate_resource_registry(&self.resources)?;
        Ok(())
    }
}

pub fn resolve_profile_path(input: &Path) -> PathBuf {
    if input.is_dir() {
        input.join(DEFAULT_PROFILE_FILE)
    } else {
        input.to_path_buf()
    }
}

pub fn ensure_default_profile_exists(input: &Path) -> Result<(), Error> {
    let is_default_dir = input == Path::new(DEFAULT_PROFILE_DIR);
    let is_default_file = input == Path::new(DEFAULT_PROFILE_DIR).join(DEFAULT_PROFILE_FILE);
    if !is_default_dir && !is_default_file {
        return Ok(());
    }

    let profile_path = resolve_profile_path(input);
    if profile_path.exists() {
        return Ok(());
    }

    create_profile(
        Path::new(DEFAULT_PROFILE_DIR),
        &CreateProfileOptions {
            name: None,
            env_file: PathBuf::from(DEFAULT_ENV_FILE),
        },
    )?;

    Ok(())
}

pub fn create_profile(path: &Path, options: &CreateProfileOptions) -> Result<PathBuf, Error> {
    let profile_dir = if path.extension().is_some_and(|value| value == "yaml") {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        path.to_path_buf()
    };

    std::fs::create_dir_all(&profile_dir).map_err(|source| Error::WriteFile {
        path: profile_dir.clone(),
        source,
    })?;

    let profile_path = profile_dir.join(DEFAULT_PROFILE_FILE);
    if profile_path.exists() {
        return Err(Error::AlreadyExists(profile_path));
    }

    let name = options
        .name
        .clone()
        .unwrap_or_else(|| infer_profile_name(&profile_dir));
    if name.trim().is_empty() {
        return Err(Error::InvalidProfile(
            "profile name must not be empty".to_string(),
        ));
    }

    let env_file = if options.env_file.as_os_str().is_empty() {
        PathBuf::from(DEFAULT_ENV_FILE)
    } else {
        options.env_file.clone()
    };

    let profile = Profile {
        name,
        env_file,
        workdir: None,
        files: BTreeMap::new(),
        assets: BTreeMap::new(),
        resources: BTreeMap::new(),
        run: RunConfig {
            cmd: vec![
                "echo".to_string(),
                "configure run.cmd in runvault.yaml".to_string(),
            ],
            clear_env: true,
            pass_env: Vec::new(),
        },
        pings: Vec::new(),
        implicit_workdir: true,
    };

    save_profile_to_path(&profile_path, &profile)?;

    Ok(profile_path)
}

fn infer_profile_name(dir: &Path) -> String {
    dir.file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("profile")
        .to_string()
}

pub fn save_profile_to_path(path: &Path, profile: &Profile) -> Result<(), Error> {
    let mut serializable = profile.clone();
    if serializable.implicit_workdir {
        serializable.workdir = None;
    }
    let yaml = serde_yaml::to_string(&serializable)
        .map_err(|source| Error::ProfileSerialize(source.to_string()))?;
    std::fs::write(path, yaml).map_err(|source| Error::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

pub fn parse_file_mode(value: &str) -> Result<u32, Error> {
    let trimmed = value.trim();
    u32::from_str_radix(trimmed, 8).map_err(|_| Error::InvalidFileMode {
        value: trimmed.to_string(),
    })
}

pub fn load_file_import_document(path: &Path) -> Result<FileImportDocument, Error> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut document: FileImportDocument =
        serde_yaml::from_str(&content).map_err(|source| Error::ImportSpecParse {
            path: path.to_path_buf(),
            source,
        })?;
    validate_file_import_document(&document)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    for spec in document.files.values_mut() {
        if let Some(src) = &mut spec.src {
            if !is_at_source(src) {
                *src = resolve_source_path(src, base_dir)?;
            }
        }
    }
    Ok(document)
}

pub fn load_asset_import_document(path: &Path) -> Result<AssetImportDocument, Error> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let mut document: AssetImportDocument =
        serde_yaml::from_str(&content).map_err(|source| Error::ImportSpecParse {
            path: path.to_path_buf(),
            source,
        })?;
    validate_resource_import_document(&document)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    for spec in document.assets.values_mut() {
        if let Some(src) = &mut spec.src {
            if !is_at_source(src) {
                *src = resolve_source_path(src, base_dir)?;
            }
        }
    }
    Ok(document)
}

pub fn expand_user_home(path: &Path) -> PathBuf {
    let Some(raw) = path.to_str() else {
        return path.to_path_buf();
    };
    if raw == "~" {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| path.to_path_buf());
    }
    if let Some(suffix) = raw.strip_prefix("~/") {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(suffix))
            .unwrap_or_else(|| path.to_path_buf());
    }
    path.to_path_buf()
}

pub fn resolve_source_path(path: &Path, base_dir: &Path) -> Result<PathBuf, Error> {
    if let Some(resolved) = pki::resolve_pki_uri(path)? {
        return Ok(resolved);
    }

    let expanded = expand_user_home(path);
    if expanded.is_absolute() {
        Ok(expanded)
    } else {
        Ok(base_dir.join(expanded))
    }
}

fn is_at_source(path: &Path) -> bool {
    path.to_str()
        .and_then(parse_reference_value)
        .is_some_and(|value| !value.trim().is_empty())
}

fn validate_file_import_document(document: &FileImportDocument) -> Result<(), Error> {
    validate_resource_registry_import(&document.resources)?;
    if document.files.is_empty() && document.resources.is_empty() {
        return Err(Error::InvalidImportSpec(
            "files or resources must contain at least one entry".to_string(),
        ));
    }
    for (key, spec) in &document.files {
        if !validate_env_key(key) {
            return Err(Error::InvalidImportSpec(format!(
                "file import key '{}' is not a valid env key",
                key
            )));
        }
        validate_import_source(
            "file import",
            key,
            spec.src.as_ref(),
            spec.ref_name.as_deref(),
        )?;
        if let Some(src) = &spec.src {
            if src.as_os_str().is_empty() {
                return Err(Error::InvalidImportSpec(format!(
                    "file import '{}' src must not be empty",
                    key
                )));
            }
        }
        if let Some(ref_name) = &spec.ref_name {
            if ref_name.trim().is_empty() {
                return Err(Error::InvalidImportSpec(format!(
                    "file import '{}' ref must not be empty",
                    key
                )));
            }
        }
        if spec.src.is_none() && spec.ref_name.is_none() {
            return Err(Error::InvalidImportSpec(format!(
                "file import '{}' requires src or ref",
                key
            )));
        }
        if let Some(path) = &spec.to_file {
            if path.as_os_str().is_empty() {
                return Err(Error::InvalidImportSpec(format!(
                    "file import '{}' to-file must not be empty",
                    key
                )));
            }
            parse_file_mode(&spec.mode)?;
        } else if spec.mode != default_file_mode() || spec.cleanup.is_some() {
            return Err(Error::InvalidImportSpec(format!(
                "file import '{}' uses file options without to-file",
                key
            )));
        }
    }
    Ok(())
}

fn validate_resource_import_document(document: &AssetImportDocument) -> Result<(), Error> {
    validate_resource_registry_import(&document.resources)?;
    if document.assets.is_empty() && document.resources.is_empty() {
        return Err(Error::InvalidImportSpec(
            "assets or resources must contain at least one entry".to_string(),
        ));
    }
    for (key, spec) in &document.assets {
        if !validate_env_key(key) {
            return Err(Error::InvalidImportSpec(format!(
                "asset import key '{}' is not a valid env key",
                key
            )));
        }
        validate_import_source(
            "asset import",
            key,
            spec.src.as_ref(),
            spec.ref_name.as_deref(),
        )?;
        if let Some(src) = &spec.src {
            if src.as_os_str().is_empty() {
                return Err(Error::InvalidImportSpec(format!(
                    "asset import '{}' src must not be empty",
                    key
                )));
            }
        }
        if let Some(ref_name) = &spec.ref_name {
            if ref_name.trim().is_empty() {
                return Err(Error::InvalidImportSpec(format!(
                    "asset import '{}' ref must not be empty",
                    key
                )));
            }
        }
        if spec.src.is_none() && spec.ref_name.is_none() {
            return Err(Error::InvalidImportSpec(format!(
                "asset import '{}' requires src or ref",
                key
            )));
        }
        if spec.to_file.as_os_str().is_empty() {
            return Err(Error::InvalidImportSpec(format!(
                "asset import '{}' to-file must not be empty",
                key
            )));
        }
        parse_file_mode(&spec.mode)?;
    }
    Ok(())
}

fn validate_resource_registry_import(
    registry: &BTreeMap<String, ResourceRegistryEntry>,
) -> Result<(), Error> {
    for (name, entry) in registry {
        if name.trim().is_empty() {
            return Err(Error::InvalidImportSpec(
                "resource registry name must not be empty".to_string(),
            ));
        }
        if let ResourceRegistryEntry::File { path, .. } = entry {
            if path.as_os_str().is_empty() {
                return Err(Error::InvalidImportSpec(format!(
                    "resource registry file '{}' path must not be empty",
                    name
                )));
            }
        }
    }
    Ok(())
}

fn validate_import_source(
    kind: &str,
    key: &str,
    src: Option<&PathBuf>,
    ref_name: Option<&str>,
) -> Result<(), Error> {
    if src.is_some() && ref_name.is_some() {
        return Err(Error::InvalidImportSpec(format!(
            "{} '{}' must not set both src and ref",
            kind, key
        )));
    }
    Ok(())
}

fn validate_resource_registry(
    registry: &BTreeMap<String, ResourceRegistryEntry>,
) -> Result<(), Error> {
    for (name, entry) in registry {
        if name.trim().is_empty() {
            return Err(Error::InvalidProfile(
                "resource registry name must not be empty".to_string(),
            ));
        }
        match entry {
            ResourceRegistryEntry::File { path, .. } => {
                if path.as_os_str().is_empty() {
                    return Err(Error::InvalidProfile(format!(
                        "resource registry file '{}' path must not be empty",
                        name
                    )));
                }
            }
            ResourceRegistryEntry::Text { .. } => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AssetImportDocument, AssetSpec, CreateProfileOptions, DEFAULT_ENV_FILE,
        DEFAULT_PROFILE_DIR, DEFAULT_PROFILE_FILE, FileCleanup, FileImportDocument, FileSpec,
        PingTarget, Profile, create_profile, ensure_default_profile_exists, expand_user_home,
        load_asset_import_document, load_file_import_document, resolve_profile_path,
        resolve_source_path, save_profile_to_path,
    };
    use crate::error::Error;
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
    };
    use tempfile::tempdir;

    #[test]
    fn loads_profile_and_keeps_implicit_workdir_unset() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("local.yaml");
        std::fs::write(
            &profile_path,
            r#"
name: local
env_file: secrets.env.enc
run:
  cmd: ["cargo", "run"]
"#,
        )
        .unwrap();

        let profile = Profile::from_path(&profile_path).unwrap();
        assert_eq!(profile.name, "local");
        assert_eq!(profile.workdir, None);
        assert_eq!(
            profile.resolve_env_path(&profile_path),
            dir.path().join("secrets.env.enc")
        );
        assert!(profile.run.clear_env);
    }

    #[test]
    fn defaults_env_file_to_env_sec_when_omitted() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join(DEFAULT_PROFILE_FILE);
        std::fs::write(
            &profile_path,
            r#"
name: local
run:
  cmd: ["cargo", "run"]
"#,
        )
        .unwrap();

        let profile = Profile::from_path(&profile_path).unwrap();
        assert_eq!(profile.env_file, PathBuf::from(DEFAULT_ENV_FILE));
        assert_eq!(
            profile.resolve_env_path(&profile_path),
            dir.path().join(DEFAULT_ENV_FILE)
        );
    }

    #[test]
    fn resolves_directory_input_to_default_profile_file() {
        let dir = tempdir().unwrap();
        assert_eq!(
            resolve_profile_path(dir.path()),
            dir.path().join(DEFAULT_PROFILE_FILE)
        );
    }

    #[test]
    fn ensure_default_profile_exists_bootstraps_dot_vault() {
        let dir = tempdir().unwrap();
        let current = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        ensure_default_profile_exists(Path::new(DEFAULT_PROFILE_DIR)).unwrap();

        let profile_path = dir
            .path()
            .join(DEFAULT_PROFILE_DIR)
            .join(DEFAULT_PROFILE_FILE);
        assert!(profile_path.exists());
        let content = std::fs::read_to_string(profile_path).unwrap();
        assert!(content.contains("name: .vault"));
        assert!(content.contains("env_file: env.sec"));

        std::env::set_current_dir(current).unwrap();
    }

    #[test]
    fn rejects_empty_name() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("invalid.yaml");
        std::fs::write(
            &profile_path,
            r#"
name: "   "
env_file: secrets.env.enc
run:
  cmd: ["cargo", "run"]
"#,
        )
        .unwrap();

        let err = Profile::from_path(&profile_path).unwrap_err();
        assert!(matches!(err, Error::InvalidProfile(_)));
        assert!(err.to_string().contains("name must not be empty"));
    }

    #[test]
    fn rejects_empty_ping_url() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join("invalid-ping.yaml");
        std::fs::write(
            &profile_path,
            r#"
name: local
env_file: secrets.env.enc
run:
  cmd: ["cargo", "run"]
pings:
  - name: api
    url: ""
"#,
        )
        .unwrap();

        let err = Profile::from_path(&profile_path).unwrap_err();
        assert!(matches!(err, Error::InvalidProfile(_)));
        assert!(err.to_string().contains("url must not be empty"));
    }

    #[test]
    fn create_profile_bootstraps_folder_with_default_name() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("services");

        let created = create_profile(
            &target,
            &CreateProfileOptions {
                name: None,
                env_file: PathBuf::from(DEFAULT_ENV_FILE),
            },
        )
        .unwrap();

        assert_eq!(created, target.join(DEFAULT_PROFILE_FILE));
        let content = std::fs::read_to_string(created).unwrap();
        assert!(content.contains("name: services"));
        assert!(content.contains("env_file: env.sec"));
        assert!(content.contains("configure run.cmd in runvault.yaml"));
    }

    #[test]
    fn create_profile_rejects_existing_profile_file() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("services");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join(DEFAULT_PROFILE_FILE), "name: existing\n").unwrap();

        let err = create_profile(
            &target,
            &CreateProfileOptions {
                name: None,
                env_file: PathBuf::from(DEFAULT_ENV_FILE),
            },
        )
        .unwrap_err();

        assert!(matches!(err, Error::AlreadyExists(_)));
    }

    #[test]
    fn create_profile_uses_custom_name_and_env_file() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("workers");

        let created = create_profile(
            &target,
            &CreateProfileOptions {
                name: Some("ovh-workers".to_string()),
                env_file: PathBuf::from("secrets.sec"),
            },
        )
        .unwrap();

        let content = std::fs::read_to_string(created).unwrap();
        assert!(content.contains("name: ovh-workers"));
        assert!(content.contains("env_file: secrets.sec"));
    }

    #[test]
    fn save_profile_persists_file_specs() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join(DEFAULT_PROFILE_FILE);
        let mut profile = Profile {
            name: "local".to_string(),
            env_file: PathBuf::from(DEFAULT_ENV_FILE),
            workdir: Some(dir.path().to_path_buf()),
            files: BTreeMap::new(),
            assets: BTreeMap::new(),
            resources: BTreeMap::new(),
            run: super::RunConfig {
                cmd: vec!["echo".to_string(), "ok".to_string()],
                clear_env: true,
                pass_env: Vec::new(),
            },
            pings: Vec::new(),
            implicit_workdir: true,
        };
        profile.upsert_file_spec(
            "TLS_CA_FILE",
            FileSpec {
                target_path: PathBuf::from("/tmp/root.crt.pem"),
                mode: "0644".to_string(),
                cleanup: FileCleanup::Keep,
            },
        );

        save_profile_to_path(&profile_path, &profile).unwrap();
        let reloaded = Profile::from_path(&profile_path).unwrap();
        let spec = reloaded.file_spec("TLS_CA_FILE").unwrap();
        assert_eq!(spec.target_path, PathBuf::from("/tmp/root.crt.pem"));
        assert_eq!(spec.mode, "0644");
        assert_eq!(spec.cleanup, FileCleanup::Keep);
    }

    #[test]
    fn save_profile_persists_assets() {
        let dir = tempdir().unwrap();
        let profile_path = dir.path().join(DEFAULT_PROFILE_FILE);
        let mut profile = Profile {
            name: "local".to_string(),
            env_file: PathBuf::from(DEFAULT_ENV_FILE),
            workdir: Some(dir.path().to_path_buf()),
            files: BTreeMap::new(),
            assets: BTreeMap::new(),
            resources: BTreeMap::new(),
            run: super::RunConfig {
                cmd: vec!["echo".to_string(), "ok".to_string()],
                clear_env: true,
                pass_env: Vec::new(),
            },
            pings: Vec::new(),
            implicit_workdir: true,
        };
        profile.assets.insert(
            "BUNDLED_DOCKER_COMPOSE_FILE".to_string(),
            AssetSpec {
                source_path: PathBuf::from("./docker-compose.yml"),
                target_path: PathBuf::from("./docker-compose.yml"),
                mode: "0644".to_string(),
                cleanup: FileCleanup::Keep,
            },
        );

        save_profile_to_path(&profile_path, &profile).unwrap();
        let reloaded = Profile::from_path(&profile_path).unwrap();
        let spec = reloaded
            .assets()
            .get("BUNDLED_DOCKER_COMPOSE_FILE")
            .unwrap();
        assert_eq!(spec.source_path, PathBuf::from("./docker-compose.yml"));
        assert_eq!(spec.target_path, PathBuf::from("./docker-compose.yml"));
        assert_eq!(spec.mode, "0644");
        assert_eq!(spec.cleanup, FileCleanup::Keep);
    }

    #[test]
    fn profile_loads_legacy_resources_as_assets() {
        let profile: Profile = serde_yaml::from_str(
            r#"
name: local
resources:
  BUNDLED_DOCKER_COMPOSE_FILE:
    source_path: ./docker-compose.yml
    target_path: ./docker-compose.yml
run:
  cmd: ["true"]
"#,
        )
        .unwrap();

        assert!(profile.resources.is_empty());
        assert!(profile.assets().contains_key("BUNDLED_DOCKER_COMPOSE_FILE"));
    }

    #[test]
    fn profile_loads_resources_as_registry_entries() {
        let profile: Profile = serde_yaml::from_str(
            r#"
name: local
resources:
  app.namespace:
    type: text
    value: glt-market
run:
  cmd: ["true"]
"#,
        )
        .unwrap();

        assert!(profile.assets().is_empty());
        assert!(profile.resources.contains_key("app.namespace"));
    }

    #[test]
    fn upsert_ping_target_updates_existing_entry_by_name() {
        let dir = tempdir().unwrap();
        let mut profile = Profile {
            name: "local".to_string(),
            env_file: PathBuf::from(DEFAULT_ENV_FILE),
            workdir: Some(dir.path().to_path_buf()),
            files: BTreeMap::new(),
            assets: BTreeMap::new(),
            resources: BTreeMap::new(),
            run: super::RunConfig {
                cmd: vec!["echo".to_string(), "ok".to_string()],
                clear_env: true,
                pass_env: Vec::new(),
            },
            pings: vec![PingTarget {
                name: "api".to_string(),
                url: "http://127.0.0.1:8080/health".to_string(),
                timeout_seconds: 30,
                interval_millis: 500,
            }],
            implicit_workdir: true,
        };

        profile.upsert_ping_target(PingTarget {
            name: "api".to_string(),
            url: "http://127.0.0.1:8081/health".to_string(),
            timeout_seconds: 10,
            interval_millis: 250,
        });

        assert_eq!(profile.pings.len(), 1);
        assert_eq!(profile.pings[0].url, "http://127.0.0.1:8081/health");
        assert_eq!(profile.pings[0].timeout_seconds, 10);
        assert_eq!(profile.pings[0].interval_millis, 250);
    }

    #[test]
    fn loads_file_import_document_and_resolves_relative_src_paths() {
        let dir = tempdir().unwrap();
        let spec_path = dir.path().join("files.yaml");
        std::fs::write(
            &spec_path,
            r#"
files:
  SERVICE_CA_CRT:
    src: ../pki/root.crt.pem
    to-file: /home/debian/mata35/pki/root.crt.pem
    mode: "0644"
    cleanup: keep
"#,
        )
        .unwrap();

        let document = load_file_import_document(&spec_path).unwrap();
        let spec = document.files.get("SERVICE_CA_CRT").unwrap();
        assert_eq!(spec.src, Some(dir.path().join("../pki/root.crt.pem")));
        assert_eq!(
            spec.to_file.as_ref().unwrap(),
            &PathBuf::from("/home/debian/mata35/pki/root.crt.pem")
        );
        assert_eq!(spec.mode, "0644");
        assert_eq!(spec.cleanup, Some(FileCleanup::Keep));
    }

    #[test]
    fn rejects_empty_file_import_document() {
        let dir = tempdir().unwrap();
        let spec_path = dir.path().join("files.yaml");
        std::fs::write(&spec_path, "files: {}\n").unwrap();

        let err = load_file_import_document(&spec_path).unwrap_err();
        assert!(matches!(err, Error::InvalidImportSpec(_)));
        assert!(
            err.to_string()
                .contains("files or resources must contain at least one entry")
        );
    }

    #[test]
    fn file_import_document_defaults_mode_and_cleanup() {
        let document: FileImportDocument = serde_yaml::from_str(
            r#"
files:
  SERVICE_CRT:
    src: ./issued/service.crt.pem
    to-file: /tls/service.crt.pem
"#,
        )
        .unwrap();

        let spec = document.files.get("SERVICE_CRT").unwrap();
        assert_eq!(
            spec.to_file.as_ref().unwrap(),
            &PathBuf::from("/tls/service.crt.pem")
        );
        assert_eq!(spec.mode, "0600");
        assert_eq!(spec.cleanup, None);
    }

    #[test]
    fn file_import_document_allows_plain_env_import_from_src_only() {
        let document: FileImportDocument = serde_yaml::from_str(
            r#"
files:
  FIREBASE_JSON:
    src: ./firebase.json
"#,
        )
        .unwrap();

        let spec = document.files.get("FIREBASE_JSON").unwrap();
        assert_eq!(spec.src, Some(PathBuf::from("./firebase.json")));
        assert_eq!(spec.to_file, None);
        assert_eq!(spec.mode, "0600");
        assert_eq!(spec.cleanup, None);
    }

    #[test]
    fn file_import_document_accepts_resource_registry_refs() {
        let document: FileImportDocument = serde_yaml::from_str(
            r#"
resources:
  postgres.password:
    type: text
    description: Shared Postgres password
    value: secret
files:
  POSTGRES_PASSWORD:
    ref: postgres.password
"#,
        )
        .unwrap();

        let spec = document.files.get("POSTGRES_PASSWORD").unwrap();
        assert_eq!(spec.ref_name.as_deref(), Some("postgres.password"));
        let entry = document.resources.get("postgres.password").unwrap();
        assert_eq!(entry.kind(), "text");
        assert_eq!(entry.description(), Some("Shared Postgres password"));
    }

    #[test]
    fn file_import_document_preserves_at_sources_for_late_resolution() {
        let document: FileImportDocument = serde_yaml::from_str(
            r#"
files:
  APP_ID:
    src: "@app.namespace"
"#,
        )
        .unwrap();

        let spec = document.files.get("APP_ID").unwrap();
        assert_eq!(spec.src, Some(PathBuf::from("@app.namespace")));
    }

    #[test]
    fn rejects_file_options_without_to_file() {
        let dir = tempdir().unwrap();
        let spec_path = dir.path().join("files.yaml");
        std::fs::write(
            &spec_path,
            r#"
files:
  SERVICE_CA_CRT:
    src: ../pki/root.crt.pem
    mode: "0644"
"#,
        )
        .unwrap();

        let err = load_file_import_document(&spec_path).unwrap_err();
        assert!(matches!(err, Error::InvalidImportSpec(_)));
        assert!(
            err.to_string()
                .contains("uses file options without to-file")
        );
    }

    #[test]
    fn file_import_document_accepts_legacy_target_path_alias() {
        let document: FileImportDocument = serde_yaml::from_str(
            r#"
files:
  SERVICE_CRT:
    src: ./issued/service.crt.pem
    target_path: /tls/service.crt.pem
"#,
        )
        .unwrap();

        let spec = document.files.get("SERVICE_CRT").unwrap();
        assert_eq!(
            spec.to_file.as_ref().unwrap(),
            &PathBuf::from("/tls/service.crt.pem")
        );
    }

    #[test]
    fn loads_asset_import_document_and_resolves_relative_src_paths() {
        let dir = tempdir().unwrap();
        let spec_path = dir.path().join("assets.yaml");
        std::fs::write(
            &spec_path,
            r#"
assets:
  BUNDLED_DOCKER_COMPOSE_FILE:
    src: ../docker-compose.yml
    to-file: ./docker-compose.yml
    mode: "0644"
    cleanup: keep
"#,
        )
        .unwrap();

        let document = load_asset_import_document(&spec_path).unwrap();
        let spec = document.assets.get("BUNDLED_DOCKER_COMPOSE_FILE").unwrap();
        assert_eq!(spec.src, Some(dir.path().join("../docker-compose.yml")));
        assert_eq!(spec.to_file, PathBuf::from("./docker-compose.yml"));
        assert_eq!(spec.mode, "0644");
        assert_eq!(spec.cleanup, FileCleanup::Keep);
    }

    #[test]
    fn rejects_empty_asset_import_document() {
        let dir = tempdir().unwrap();
        let spec_path = dir.path().join("assets.yaml");
        std::fs::write(&spec_path, "assets: {}\n").unwrap();

        let err = load_asset_import_document(&spec_path).unwrap_err();
        assert!(matches!(err, Error::InvalidImportSpec(_)));
        assert!(
            err.to_string()
                .contains("assets or resources must contain at least one entry")
        );
    }

    #[test]
    fn asset_import_document_defaults_mode_and_cleanup() {
        let document: AssetImportDocument = serde_yaml::from_str(
            r#"
assets:
  BUNDLED_DOCKER_COMPOSE_FILE:
    src: ./docker-compose.yml
    to-file: ./docker-compose.yml
"#,
        )
        .unwrap();

        let spec = document.assets.get("BUNDLED_DOCKER_COMPOSE_FILE").unwrap();
        assert_eq!(spec.src, Some(PathBuf::from("./docker-compose.yml")));
        assert_eq!(spec.to_file, PathBuf::from("./docker-compose.yml"));
        assert_eq!(spec.mode, "0600");
        assert_eq!(spec.cleanup, FileCleanup::OnExit);
    }

    #[test]
    fn asset_import_document_loads_legacy_resources_as_assets() {
        let document: AssetImportDocument = serde_yaml::from_str(
            r#"
resources:
  BUNDLED_DOCKER_COMPOSE_FILE:
    src: ./docker-compose.yml
    to-file: ./docker-compose.yml
"#,
        )
        .unwrap();

        assert!(document.resources.is_empty());
        assert!(document.assets.contains_key("BUNDLED_DOCKER_COMPOSE_FILE"));
    }

    #[test]
    fn asset_import_document_accepts_registry_only_specs() {
        let document: AssetImportDocument = serde_yaml::from_str(
            r#"
resources:
  caddy.main_config:
    type: file
    description: Main Caddy config
    path: ./Caddyfile
"#,
        )
        .unwrap();

        assert!(document.assets.is_empty());
        let entry = document.resources.get("caddy.main_config").unwrap();
        assert_eq!(entry.kind(), "file");
        assert_eq!(entry.description(), Some("Main Caddy config"));
    }

    #[test]
    fn asset_import_document_preserves_at_sources_for_late_resolution() {
        let document: AssetImportDocument = serde_yaml::from_str(
            r#"
assets:
  CADDY_CONFIG_FILE:
    src: "@caddy.main_config"
    to-file: ./Caddyfile
"#,
        )
        .unwrap();

        let spec = document.assets.get("CADDY_CONFIG_FILE").unwrap();
        assert_eq!(spec.src, Some(PathBuf::from("@caddy.main_config")));
    }

    #[test]
    fn expands_tilde_to_home_directory() {
        let home = std::env::var_os("HOME").unwrap();
        assert_eq!(
            expand_user_home(Path::new("~/secret.txt")),
            PathBuf::from(home).join("secret.txt")
        );
        assert_eq!(
            expand_user_home(Path::new("/tmp/secret.txt")),
            PathBuf::from("/tmp/secret.txt")
        );
    }

    #[test]
    fn resolves_pki_uri_source_paths() {
        let home = tempdir().unwrap();
        let previous_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home.path());
        }

        let resolved =
            resolve_source_path(Path::new("pki://ca/crt.pem"), Path::new("/unused")).unwrap();

        assert_eq!(resolved, home.path().join(".runvault/pki/ca/crt.pem"));

        unsafe {
            match previous_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
        }
    }
}

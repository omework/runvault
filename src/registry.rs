use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use crate::error::Error;

const REGISTRY_DIR_NAME: &str = ".runvault";
const REGISTRY_FILE_NAME: &str = "registry.yaml";
const BUNDLES_DIR_NAME: &str = "bundles";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryDocument {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tracks: BTreeMap<String, RegistryTrack>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryTrack {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_history_index: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<RegistryHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryHistoryEntry {
    pub version: String,
    pub bundle_path: PathBuf,
    #[serde(default)]
    pub status: RegistryEntryStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RegistryEntryStatus {
    #[default]
    Registered,
    Succeeded,
    Failed,
}

pub fn registry_root() -> Result<PathBuf, Error> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| path.join(REGISTRY_DIR_NAME))
        .ok_or_else(|| Error::Registry("HOME is not set; cannot resolve ~/.runvault".to_string()))
}

pub fn registry_path() -> Result<PathBuf, Error> {
    Ok(registry_root()?.join(REGISTRY_FILE_NAME))
}

pub fn track_bundle_dir(track: &str, version: &str) -> Result<PathBuf, Error> {
    validate_registry_segment("track name", track)?;
    validate_registry_segment("bundle version", version)?;
    Ok(registry_root()?
        .join(BUNDLES_DIR_NAME)
        .join(track)
        .join(version))
}

pub fn load_registry() -> Result<RegistryDocument, Error> {
    let path = registry_path()?;
    if !path.exists() {
        return Ok(RegistryDocument::default());
    }

    let content = fs::read_to_string(&path).map_err(|source| Error::ReadFile {
        path: path.clone(),
        source,
    })?;
    serde_yaml::from_str(&content).map_err(|source| {
        Error::Registry(format!("failed to parse {}: {}", path.display(), source))
    })
}

pub fn save_registry(registry: &RegistryDocument) -> Result<(), Error> {
    let path = registry_path()?;
    let root = registry_root()?;
    fs::create_dir_all(&root).map_err(|source| Error::WriteFile { path: root, source })?;
    let yaml = serde_yaml::to_string(registry)
        .map_err(|source| Error::Registry(format!("failed to serialize registry: {}", source)))?;
    fs::write(&path, yaml).map_err(|source| Error::WriteFile { path, source })
}

pub fn append_history_entry(
    registry: &mut RegistryDocument,
    track: &str,
    version: &str,
    bundle_path: PathBuf,
) -> Result<usize, Error> {
    validate_registry_segment("track name", track)?;
    validate_registry_segment("bundle version", version)?;
    let track = registry.tracks.entry(track.to_string()).or_default();
    track.history.push(RegistryHistoryEntry {
        version: version.to_string(),
        bundle_path,
        status: RegistryEntryStatus::Registered,
    });
    Ok(track.history.len() - 1)
}

pub fn mark_history_entry(
    registry: &mut RegistryDocument,
    track: &str,
    index: usize,
    status: RegistryEntryStatus,
) -> Result<(), Error> {
    let track_state = registry
        .tracks
        .get_mut(track)
        .ok_or_else(|| Error::Registry(format!("track '{}' is not registered", track)))?;
    let entry = track_state.history.get_mut(index).ok_or_else(|| {
        Error::Registry(format!(
            "track '{}' history index {} does not exist",
            track, index
        ))
    })?;
    entry.status = status;
    if status == RegistryEntryStatus::Succeeded {
        track_state.current_history_index = Some(index);
    }
    Ok(())
}

pub fn current_version<'a>(registry: &'a RegistryDocument, track: &str) -> Option<&'a str> {
    let track = registry.tracks.get(track)?;
    let index = track.current_history_index?;
    track.history.get(index).map(|entry| entry.version.as_str())
}

pub fn current_bundle_path(registry: &RegistryDocument, track: &str) -> Result<PathBuf, Error> {
    let track_state = registry
        .tracks
        .get(track)
        .ok_or_else(|| Error::Registry(format!("track '{}' is not registered", track)))?;
    let current_index = track_state.current_history_index.ok_or_else(|| {
        Error::Registry(format!(
            "track '{}' has no successful deployed bundle yet",
            track
        ))
    })?;
    track_state
        .history
        .get(current_index)
        .map(|entry| entry.bundle_path.clone())
        .ok_or_else(|| {
            Error::Registry(format!(
                "track '{}' current history index {} is invalid",
                track, current_index
            ))
        })
}

pub fn previous_successful_bundle_path(
    registry: &RegistryDocument,
    track: &str,
) -> Result<PathBuf, Error> {
    let track_state = registry
        .tracks
        .get(track)
        .ok_or_else(|| Error::Registry(format!("track '{}' is not registered", track)))?;
    let current_index = track_state.current_history_index.ok_or_else(|| {
        Error::Registry(format!(
            "track '{}' has no successful deployed bundle yet",
            track
        ))
    })?;
    let previous = track_state.history[..current_index]
        .iter()
        .enumerate()
        .rev()
        .find(|(_, entry)| entry.status == RegistryEntryStatus::Succeeded)
        .map(|(_, entry)| entry.bundle_path.clone());
    previous.ok_or_else(|| {
        Error::Registry(format!(
            "track '{}' has no previous successful bundle to roll back to",
            track
        ))
    })
}

fn validate_registry_segment(label: &str, value: &str) -> Result<(), Error> {
    if value.trim().is_empty() {
        return Err(Error::Registry(format!("{label} must not be empty")));
    }
    let path = Path::new(value);
    match path.components().next() {
        Some(Component::Normal(_)) if path.components().count() == 1 => Ok(()),
        _ => Err(Error::Registry(format!(
            "{label} '{}' must be a single path-safe segment",
            value
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RegistryDocument, RegistryEntryStatus, append_history_entry, current_bundle_path,
        current_version, mark_history_entry, previous_successful_bundle_path,
    };
    use std::path::PathBuf;

    #[test]
    fn resolves_previous_successful_bundle_by_execution_history() {
        let mut registry = RegistryDocument::default();

        let a = append_history_entry(
            &mut registry,
            "workers",
            "v1",
            PathBuf::from("/tmp/workers/v1/bundle.yaml"),
        )
        .unwrap();
        mark_history_entry(&mut registry, "workers", a, RegistryEntryStatus::Succeeded).unwrap();

        let b = append_history_entry(
            &mut registry,
            "workers",
            "v2",
            PathBuf::from("/tmp/workers/v2/bundle.yaml"),
        )
        .unwrap();
        mark_history_entry(&mut registry, "workers", b, RegistryEntryStatus::Succeeded).unwrap();

        let rollback = previous_successful_bundle_path(&registry, "workers").unwrap();
        assert_eq!(rollback, PathBuf::from("/tmp/workers/v1/bundle.yaml"));
    }

    #[test]
    fn failed_attempt_does_not_replace_current_successful_bundle() {
        let mut registry = RegistryDocument::default();

        let first = append_history_entry(
            &mut registry,
            "workers",
            "v1",
            PathBuf::from("/tmp/workers/v1/bundle.yaml"),
        )
        .unwrap();
        mark_history_entry(
            &mut registry,
            "workers",
            first,
            RegistryEntryStatus::Succeeded,
        )
        .unwrap();

        let failed = append_history_entry(
            &mut registry,
            "workers",
            "v2",
            PathBuf::from("/tmp/workers/v2/bundle.yaml"),
        )
        .unwrap();
        mark_history_entry(
            &mut registry,
            "workers",
            failed,
            RegistryEntryStatus::Failed,
        )
        .unwrap();

        assert_eq!(current_version(&registry, "workers"), Some("v1"));
        assert_eq!(
            current_bundle_path(&registry, "workers").unwrap(),
            PathBuf::from("/tmp/workers/v1/bundle.yaml")
        );
    }

    #[test]
    fn rejects_non_segment_track_or_version_names() {
        let mut registry = RegistryDocument::default();
        let err = append_history_entry(
            &mut registry,
            "workers/home",
            "v1",
            PathBuf::from("/tmp/workers/v1/bundle.yaml"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("path-safe segment"));

        let err = append_history_entry(
            &mut registry,
            "workers",
            "../v1",
            PathBuf::from("/tmp/workers/v1/bundle.yaml"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("path-safe segment"));
    }
}

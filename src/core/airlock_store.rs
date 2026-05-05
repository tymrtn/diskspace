use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::profile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirlockEntry {
    pub id: String,
    pub candidate_id: String,
    pub original_path: PathBuf,
    pub airlock_path: PathBuf,
    pub size_bytes: u64,
    pub airlocked_at: DateTime<Utc>,
    pub auto_purge_at: DateTime<Utc>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AirlockManifest {
    pub entries: Vec<AirlockEntry>,
}

pub fn manifest_path() -> PathBuf {
    profile::data_dir().join("airlock").join("manifest.json")
}

pub fn airlock_root() -> PathBuf {
    profile::data_dir().join("airlock")
}

pub fn load_manifest() -> Result<AirlockManifest> {
    let path = manifest_path();
    if !path.exists() {
        return Ok(AirlockManifest::default());
    }
    let content = std::fs::read_to_string(&path).context("reading airlock manifest")?;
    serde_json::from_str(&content).context("parsing airlock manifest")
}

pub fn save_manifest(manifest: &AirlockManifest) -> Result<()> {
    let path = manifest_path();
    std::fs::create_dir_all(path.parent().unwrap())?;
    let content = serde_json::to_string_pretty(manifest)?;
    std::fs::write(&path, content)?;
    Ok(())
}

/// Move a path into airlock. Returns the AirlockEntry.
pub fn airlock_path(
    candidate_id: &str,
    original: &Path,
    retention_days: u32,
) -> Result<AirlockEntry> {
    let entry_id = format!("{}-{}", candidate_id, Utc::now().timestamp());
    let dest = airlock_root()
        .join(&entry_id)
        .join(original.file_name().unwrap_or_default());

    std::fs::create_dir_all(dest.parent().unwrap())?;

    // Try rename first (same volume), fall back to copy+remove
    let size = dir_size(original);
    if std::fs::rename(original, &dest).is_err() {
        copy_recursive(original, &dest)?;
        remove_recursive(original)?;
    }

    let now = Utc::now();
    Ok(AirlockEntry {
        id: entry_id,
        candidate_id: candidate_id.to_string(),
        original_path: original.to_path_buf(),
        airlock_path: dest,
        size_bytes: size,
        airlocked_at: now,
        auto_purge_at: now + chrono::Duration::days(retention_days as i64),
    })
}

/// Restore an airlocked entry back to its original path.
pub fn restore_entry(entry: &AirlockEntry) -> Result<()> {
    if let Some(parent) = entry.original_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if std::fs::rename(&entry.airlock_path, &entry.original_path).is_err() {
        copy_recursive(&entry.airlock_path, &entry.original_path)?;
        remove_recursive(&entry.airlock_path)?;
    }
    // Clean up the airlock slot directory
    if let Some(slot) = entry.airlock_path.parent() {
        let _ = std::fs::remove_dir(slot);
    }
    Ok(())
}

pub fn dir_size(path: &Path) -> u64 {
    if path.is_file() {
        return std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    }
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            total += dir_size(&entry.path());
        }
    }
    total
}

fn copy_recursive(src: &Path, dst: &Path) -> Result<()> {
    if src.is_file() {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)?;
        return Ok(());
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)?.flatten() {
        let dest_child = dst.join(entry.file_name());
        copy_recursive(&entry.path(), &dest_child)?;
    }
    Ok(())
}

fn remove_recursive(path: &Path) -> Result<()> {
    if path.is_file() {
        std::fs::remove_file(path)?;
    } else {
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

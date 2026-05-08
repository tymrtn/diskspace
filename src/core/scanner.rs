use anyhow::Result;
use chrono::{DateTime, Utc};
use jwalk::WalkDir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::candidate::{Category, ScannedEntry};
use super::rules::Rule;

/// Cached scan result written to ~/.diskspace/scan.json
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanned_at: DateTime<Utc>,
    pub root: PathBuf,
    /// Only rule-matched entries — keeps the cache small.
    pub entries: Vec<ScannedEntry>,
    pub total_bytes: u64,
    /// Bytes in cloud-only placeholder files (iCloud evicted, Dropbox Smart Sync) — not counted in total_bytes.
    #[serde(default)]
    pub cloud_placeholder_bytes: u64,
    /// Per-category byte totals — populated during walk so we don't need to keep all entries.
    #[serde(default)]
    pub category_totals: HashMap<String, u64>,
}

/// Walk the filesystem in parallel, classify entries against rules.
///
/// Only rule-matched entries are kept in `entries`. Per-category totals are computed
/// during the walk so we can render the scan summary without holding every file path
/// in memory or persisting them to disk.
pub fn scan(root: &Path, rules: &[Rule]) -> Result<ScanResult> {
    let home = dirs_home();
    let mut entries: Vec<ScannedEntry> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut cloud_placeholder_bytes: u64 = 0;
    let mut category_totals: HashMap<String, u64> = HashMap::new();
    let mut dir_sizes: HashMap<PathBuf, u64> = HashMap::new();

    // Build a map of rule path patterns to categories for fast lookup
    let rule_map: Vec<(glob::Pattern, Category)> = rules
        .iter()
        .filter_map(|r| {
            let pattern_str = expand_home(&r.path_pattern, &home);
            glob::Pattern::new(&pattern_str)
                .ok()
                .map(|p| (p, category_from_str(&r.category)))
        })
        .collect();

    for entry in WalkDir::new(root)
        .skip_hidden(false)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if !metadata.is_file() && !metadata.is_dir() {
            continue;
        }

        // Skip iCloud Drive evicted and Dropbox Smart Sync online-only files —
        // they have reported size but zero disk blocks allocated.
        // Also use actual on-disk allocation (not logical size) for everything else,
        // so sparse files like virtual disk images report what they really take up.
        let size: u64;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.is_file() && metadata.len() > 4096 && metadata.blocks() == 0 {
                cloud_placeholder_bytes += metadata.len();
                continue;
            }
            size = if metadata.is_file() {
                metadata.blocks() * 512
            } else {
                0
            };
        }
        #[cfg(not(unix))]
        {
            size = if metadata.is_file() {
                metadata.len()
            } else {
                0
            };
        }

        total_bytes += size;

        let matched = rule_map.iter().find(|(pat, _)| pat.matches_path(&path));

        // Accumulate file sizes into ancestor directories so a rule-matched
        // directory entry knows its total size.
        if size > 0 {
            let mut p = path.parent();
            while let Some(parent) = p {
                *dir_sizes.entry(parent.to_path_buf()).or_insert(0) += size;
                p = parent.parent();
            }
        }

        // Only persist rule-matched entries — this is the cache-size fix.
        if let Some((_, cat)) = matched {
            entries.push(ScannedEntry {
                path: path.to_path_buf(),
                size_bytes: size,
                category: cat.clone(),
                modified: system_time_to_dt(metadata.modified().ok()),
                accessed: system_time_to_dt(metadata.accessed().ok()),
            });
        }
    }

    // Patch directory entries (size 0 from walk) with their aggregated descendant size.
    for entry in &mut entries {
        if entry.size_bytes == 0 {
            if let Some(&s) = dir_sizes.get(&entry.path) {
                entry.size_bytes = s;
            }
        }
    }

    // Compute category totals from top-level matched entries only.
    // (Nested matches would double-count since their bytes are already included
    // in an ancestor's aggregated size.)
    let mut top_level_total: u64 = 0;
    for entry in &entries {
        let is_nested = entries
            .iter()
            .any(|other| other.path != entry.path && entry.path.starts_with(&other.path));
        if !is_nested && entry.size_bytes > 0 {
            *category_totals
                .entry(entry.category.to_string())
                .or_insert(0) += entry.size_bytes;
            top_level_total += entry.size_bytes;
        }
    }
    // Whatever isn't covered by a rule lands in "unknown".
    if total_bytes > top_level_total {
        *category_totals.entry("unknown".to_string()).or_insert(0) += total_bytes - top_level_total;
    }

    Ok(ScanResult {
        scanned_at: Utc::now(),
        root: root.to_path_buf(),
        entries,
        total_bytes,
        cloud_placeholder_bytes,
        category_totals,
    })
}

fn category_from_str(s: &str) -> Category {
    match s {
        "dev-artifact" => Category::DevArtifact,
        "app-cache" => Category::AppCache,
        "download-entropy" => Category::DownloadEntropy,
        "vm-disk" => Category::VmDisk,
        _ => Category::Unknown,
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/"))
}

pub fn expand_home(pattern: &str, home: &Path) -> String {
    if let Some(rest) = pattern.strip_prefix("~/") {
        home.join(rest).to_string_lossy().into_owned()
    } else if pattern == "~" {
        home.to_string_lossy().into_owned()
    } else {
        pattern.to_string()
    }
}

fn system_time_to_dt(t: Option<SystemTime>) -> Option<DateTime<Utc>> {
    t.map(DateTime::from)
}

use anyhow::Result;
use chrono::{DateTime, Utc};
use jwalk::WalkDir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::candidate::{Category, ScannedEntry};
use super::rules::Rule;

/// Cached scan result written to ~/.disk-advisor/scan.json
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanned_at: DateTime<Utc>,
    pub root: PathBuf,
    pub entries: Vec<ScannedEntry>,
    pub total_bytes: u64,
}

/// Walk the filesystem in parallel, classify entries against rules.
pub fn scan(root: &Path, rules: &[Rule]) -> Result<ScanResult> {
    let home = dirs_home();
    let mut entries: Vec<ScannedEntry> = Vec::new();
    let mut total_bytes: u64 = 0;

    // Build a map of rule path patterns to categories for fast lookup
    let rule_map: Vec<(glob::Pattern, Category, &Rule)> = rules
        .iter()
        .filter_map(|r| {
            let pattern_str = expand_home(&r.path_pattern, &home);
            glob::Pattern::new(&pattern_str)
                .ok()
                .map(|p| (p, category_from_str(&r.category), r))
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

        // For directories matched by rules we record the entry at that level
        // and skip descending (we use DirEntry depth to manage this via post-processing)
        let size = if metadata.is_file() {
            metadata.len()
        } else {
            0 // directories get aggregated below
        };

        total_bytes += size;

        let (cat, _rule) = rule_map
            .iter()
            .find(|(pat, _, _)| pat.matches_path(&path))
            .map(|(_, cat, rule)| (cat.clone(), Some(rule)))
            .unwrap_or((Category::Unknown, None));

        if cat != Category::Unknown || metadata.is_file() {
            entries.push(ScannedEntry {
                path: path.to_path_buf(),
                size_bytes: size,
                category: cat,
                modified: system_time_to_dt(metadata.modified().ok()),
                accessed: system_time_to_dt(metadata.accessed().ok()),
            });
        }
    }

    Ok(ScanResult {
        scanned_at: Utc::now(),
        root: root.to_path_buf(),
        entries,
        total_bytes,
    })
}

/// Aggregate directory sizes: for each rule-matched directory path,
/// sum all descendant file sizes.
pub fn aggregate_dir_sizes(result: &mut ScanResult) {
    let mut dir_sizes: HashMap<PathBuf, u64> = HashMap::new();

    for entry in &result.entries {
        if entry.size_bytes == 0 {
            continue;
        }
        // Walk up the path tree and accumulate into parent directories
        let mut p = entry.path.parent();
        while let Some(parent) = p {
            *dir_sizes.entry(parent.to_path_buf()).or_insert(0) += entry.size_bytes;
            p = parent.parent();
        }
    }

    // Patch directory entries with their aggregated sizes
    for entry in &mut result.entries {
        if entry.size_bytes == 0 {
            if let Some(&size) = dir_sizes.get(&entry.path) {
                entry.size_bytes = size;
            }
        }
    }
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

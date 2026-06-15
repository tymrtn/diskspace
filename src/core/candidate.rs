use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    DevArtifact,
    AppCache,
    DownloadEntropy,
    VmDisk,
    Unknown,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::DevArtifact => write!(f, "dev-artifact"),
            Category::AppCache => write!(f, "app-cache"),
            Category::DownloadEntropy => write!(f, "download-entropy"),
            Category::VmDisk => write!(f, "vm-disk"),
            Category::Unknown => write!(f, "unknown"),
        }
    }
}

/// A scanned filesystem entry, annotated with category and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedEntry {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub category: Category,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    /// Device id (unix `stat.st_dev`) — half of the inode identity used to key
    /// the time series. `None` on non-unix or when unavailable. Additive +
    /// serde-default so legacy scan.json still deserializes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<u64>,
    /// Inode number (unix `stat.st_ino`). `None` on non-unix or when unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ino: Option<u64>,
    /// Inode change time as nanoseconds-since-epoch (`st_ctime * 1e9 +
    /// st_ctime_nsec`), NOT whole seconds. The series layer keys continuity on
    /// `(dev, ino)` alone and uses this ctime only as an inode-reuse tiebreaker;
    /// full sub-second resolution is required because a delete + create can
    /// reuse the same inode inside one wall-clock second. `None` on non-unix or
    /// when unavailable. Additive + serde-default so legacy scan.json still
    /// deserializes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctime: Option<i64>,
}

/// A candidate for cleanup: a scanned entry promoted by a matching rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    pub rule_id: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub category: Category,
    pub confidence: f32,
    pub reason: String,
    pub domain: Option<String>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    /// Consequence metadata copied from the matching rule (M6).
    #[serde(default)]
    pub consequences: Option<crate::core::rules::Consequences>,
}

impl Candidate {
    /// Sort key: larger yield and higher confidence rank first.
    pub fn score(&self) -> f64 {
        self.size_bytes as f64 * self.confidence as f64
    }
}

/// The result of a pressure-test on a candidate (used in M2).
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckResult {
    pub candidate_id: String,
    pub safe: bool,
    pub confidence: f32,
    pub steps: Vec<CheckStep>,
    /// Consequence metadata: what happens if you delete this (M6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consequences: Option<crate::core::rules::Consequences>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckStep {
    pub name: String,
    pub passed: bool,
    pub note: String,
}

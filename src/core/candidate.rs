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
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckStep {
    pub name: String,
    pub passed: bool,
    pub note: String,
}

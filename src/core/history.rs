//! Receipts ledger — append-only audit trail of every action diskspace takes.
//! Stored at `~/.diskspace/history.jsonl` (one JSON object per line).

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::profile;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Airlock,
    Reclaim,
    Purge,
    Restore,
    Doctor,
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionKind::Airlock => write!(f, "airlock"),
            ActionKind::Reclaim => write!(f, "reclaim"),
            ActionKind::Purge => write!(f, "purge"),
            ActionKind::Restore => write!(f, "restore"),
            ActionKind::Doctor => write!(f, "doctor"),
        }
    }
}

/// One entry in the history ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub ts: DateTime<Utc>,
    pub command: ActionKind,
    pub candidate_id: Option<String>,
    pub rule_id: Option<String>,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub df_before: Option<u64>,
    pub df_after: Option<u64>,
    /// Bytes the OS confirms were actually freed (df delta). May be None for
    /// same-volume airlock where bytes are staged but not yet released.
    pub actually_freed: Option<u64>,
    /// Whether this action is reversible (e.g. cross-volume airlock can be
    /// restored; reclaim cannot).
    pub reversible: bool,
    /// If reversible, the command the user could run to undo it.
    pub undo_cmd: Option<String>,
    pub rule_confidence: Option<f32>,
    /// Free-form context — `MoveKind`, pressure-test summary, etc.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub context: serde_json::Map<String, serde_json::Value>,
}

pub fn history_path() -> PathBuf {
    profile::data_dir().join("history.jsonl")
}

/// Append one entry to `~/.diskspace/history.jsonl`.
/// Logged failures don't propagate — history is best-effort, never blocks an action.
pub fn append(entry: &Entry) {
    if let Err(e) = append_inner(entry) {
        eprintln!("(history: failed to write entry: {})", e);
    }
}

fn append_inner(entry: &Entry) -> Result<()> {
    let path = history_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let line = serde_json::to_string(entry)?;
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(f, "{}", line)?;
    Ok(())
}

/// Read the last `n` entries from history, newest first.
pub fn tail(n: usize) -> Result<Vec<Entry>> {
    let path = history_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)?;
    let mut entries: Vec<Entry> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    entries.reverse();
    entries.truncate(n);
    Ok(entries)
}

/// Free bytes available on the filesystem containing `path`. Returns None if `df` fails.
pub fn free_bytes(path: &Path) -> Option<u64> {
    let output = std::process::Command::new("df")
        .arg("-k")
        .arg(path)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().nth(1)?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    let kb_avail: u64 = fields.get(3)?.parse().ok()?;
    Some(kb_avail * 1024)
}

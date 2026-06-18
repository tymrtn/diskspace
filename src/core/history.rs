//! Receipts ledger — append-only audit trail of every action diskspace takes.
//! Stored at `~/.diskspace/history.jsonl` (one JSON object per line).

use anyhow::Result;
use chrono::{DateTime, Utc};
use fs4::FileExt;
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
    /// `stow` offloaded a cloud-synced path's LOCAL copy to the cloud (iCloud
    /// `brctl evict` or Maestral `excluded add`). The bytes are freed locally but
    /// the data remains in the cloud — fully reversible, NOT a deletion.
    Offload,
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionKind::Airlock => write!(f, "airlock"),
            ActionKind::Reclaim => write!(f, "reclaim"),
            ActionKind::Purge => write!(f, "purge"),
            ActionKind::Restore => write!(f, "restore"),
            ActionKind::Doctor => write!(f, "doctor"),
            ActionKind::Offload => write!(f, "offload"),
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
    append_inner_to(&history_path(), entry)
}

/// Append one entry to `<base>/history.jsonl` (a base-dir seam, mirroring
/// [`read_all_in_pub`]). Production callers that already know they want the real
/// ledger pass [`profile::data_dir`]; the seam exists so a caller under test can
/// redirect its receipt into a tempdir instead of polluting `~/.diskspace`.
/// Best-effort like [`append`] — a write failure is logged, never propagated.
pub(crate) fn append_to_base(base: &Path, entry: &Entry) {
    if let Err(e) = append_inner_to(&base.join("history.jsonl"), entry) {
        eprintln!("(history: failed to write entry: {})", e);
    }
}

/// Append one entry to `path` under an exclusive lock. Path-parameterized so
/// tests can target a tempdir without touching the real `~/.diskspace`.
fn append_inner_to(path: &Path, entry: &Entry) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Serialize before taking the lock so a bad value never holds the lock or
    // leaves a half-written line.
    let line = serde_json::to_string(entry)?;
    let f = OpenOptions::new().create(true).append(true).open(path)?;
    // history.jsonl is written by both a launchd tick and a user reclaim, and
    // read concurrently by the metrics regrowth join — same race class as
    // series.rs. Take ONE exclusive lock around the append so concurrent
    // writers never interleave or tear a line. `FileExt::lock` is the blocking
    // exclusive lock (flock LOCK_EX on unix).
    FileExt::lock(&f)?;
    let write_res = (|| -> std::io::Result<()> {
        // `&f` is opened in append mode, so each write lands at EOF.
        let mut w = &f;
        writeln!(w, "{}", line)?;
        w.flush()?;
        Ok(())
    })();
    // Always release the lock, even if the write failed.
    let unlock_res = FileExt::unlock(&f);
    write_res?;
    unlock_res?;
    Ok(())
}

/// Read every entry from history, file order (oldest-first). Blank/torn lines
/// are skipped. Base-dir parameterized so the advisory `metrics` regrowth join
/// can target a tempdir in tests without touching the real `~/.diskspace`.
fn read_all_in(base: &Path) -> Result<Vec<Entry>> {
    let path = base.join("history.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)?;
    Ok(content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

/// Crate-internal base-dir seam mirroring [`read_all_in`], exposed so `metrics`
/// can read a tempdir history in tests and under the real `~/.diskspace`.
pub(crate) fn read_all_in_pub(base: &Path) -> Result<Vec<Entry>> {
    read_all_in(base)
}

/// Crate-internal base-dir seam for the locked appender, exposed so `metrics`
/// tests can seed a tempdir history. Writes to `<base>/history.jsonl`.
/// Test-only: production writes go through [`append`].
#[cfg(test)]
pub(crate) fn append_inner_to_pub(base: &Path, entry: &Entry) -> Result<()> {
    append_inner_to(&base.join("history.jsonl"), entry)
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
///
/// Delegates to the single consolidated POSIX `df -kP` parser in
/// [`crate::core::fsutil`] so macOS and Linux share one code path (the old
/// inline `df -k` parse mis-read Linux's line-wrapped output).
pub fn free_bytes(path: &Path) -> Option<u64> {
    crate::core::fsutil::free_bytes(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// A throwaway dir under the OS temp dir, cleaned up on drop. We point the
    /// path-parameterized helpers at it so tests never touch the real
    /// `~/.diskspace`.
    struct TempBase {
        path: PathBuf,
    }
    impl TempBase {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let uniq = format!(
                "diskspace-history-test-{}-{}-{}",
                tag,
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            );
            p.push(uniq);
            std::fs::create_dir_all(&p).unwrap();
            Self { path: p }
        }
        fn jsonl(&self) -> PathBuf {
            self.path.join("history.jsonl")
        }
    }
    impl Drop for TempBase {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn entry(i: u64) -> Entry {
        Entry {
            ts: Utc::now(),
            command: ActionKind::Reclaim,
            candidate_id: Some(format!("cand-{i}")),
            rule_id: Some("rule-x".into()),
            path: PathBuf::from(format!("/tmp/thing/{i}")),
            size_bytes: i * 10,
            df_before: None,
            df_after: None,
            actually_freed: None,
            reversible: false,
            undo_cmd: None,
            rule_confidence: None,
            context: serde_json::Map::new(),
        }
    }

    /// Two threads each append >= 50 entries (>= 100 total). The exclusive lock
    /// must guarantee every line parses (no torn/interleaved writes) and the
    /// total count is exactly what was written. Mirrors the series concurrency
    /// test.
    #[test]
    fn concurrent_append_no_torn_lines_and_correct_count() {
        let base = Arc::new(TempBase::new("concurrent"));
        let path = Arc::new(base.jsonl());
        let threads = 2;
        let per_thread = 60; // 2 * 60 = 120 lines total (>= 100)

        let mut handles = Vec::new();
        for t in 0..threads {
            let path = Arc::clone(&path);
            handles.push(thread::spawn(move || {
                for i in 0..per_thread {
                    append_inner_to(&path, &entry((t * 1000 + i) as u64)).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let content = std::fs::read_to_string(&*path).unwrap();
        let non_empty: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            non_empty.len(),
            threads * per_thread,
            "no lines lost or duplicated"
        );
        // Every line must be valid JSON — a torn/interleaved write would fail here.
        let mut malformed = 0;
        for l in &non_empty {
            if serde_json::from_str::<Entry>(l).is_err() {
                malformed += 1;
            }
        }
        assert_eq!(malformed, 0, "lock prevented torn/interleaved writes");

        // `tail`-style read parses every line too.
        let parsed: Vec<Entry> = non_empty
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        assert_eq!(parsed.len(), threads * per_thread, "every line parses");
    }
}

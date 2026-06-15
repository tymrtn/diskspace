//! Append-only time-series store — the foundation of diskspace's P1 measurement layer.
//!
//! Records per-entry byte observations over time so we can answer "how much did
//! this path grow/shrink since last scan?" without re-walking history. Stored at
//! `~/.diskspace/series.jsonl` (one JSON object per line), with a daily rollup at
//! `series.daily.jsonl` and a recompute high-water mark at `series.rollup.hw`.
//!
//! Design invariants (mirrors the rest of the codebase):
//!   * never sudo; all state under `~/.diskspace` via [`profile::data_dir`].
//!   * `$HOME`-scoped; no network; no privilege APIs.
//!   * append is best-effort — failures are logged, never panic (mirrors
//!     `history::append`).
//!   * `series.jsonl` is never pruned; the daily rollup is fully recomputable
//!     from raw by deleting `series.daily.jsonl` + `series.rollup.hw`.
//!
//! Unlike `history::append` (which opens/closes per line, lockless), the batch
//! writer here takes ONE fs4 exclusive lock for the whole batch so concurrent
//! writers never interleave or tear a line.
//!
//! This is the P1 measurement foundation: the public API is complete but the
//! scanner/watch callers land in a follow-up, so the dead-code allow below
//! mirrors the existing convention (e.g. `candidate::CheckResult`,
//! `profile::save`) until those wires are connected.
#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Datelike, TimeZone, Utc};
use fs4::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::profile;

/// Schema version stamped on every [`Observation`]. Bump when the on-disk shape
/// changes incompatibly; readers skip any line with `v > SERIES_SCHEMA`.
pub const SERIES_SCHEMA: u32 = 1;

/// How a single observation was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Observed during a full filesystem walk.
    Full,
    /// Observed during an incremental (changed-subtree) walk.
    Incremental,
    /// Observed during a targeted re-stat of a known entry.
    Restat,
    /// The entry no longer exists; a deletion marker.
    Tombstone,
}

/// Stable identity of the thing being observed.
///
/// On unix we key continuity by `(dev, ino)` ALONE — deliberately NOT including
/// ctime. This keeps a series continuous across events that bump `st_ctime`
/// without changing the inode, most importantly `rename(2)`: a `mv old new`
/// inside the scanned tree leaves `(dev, ino)` unchanged, so the moved file
/// reads as ONE continuous series rather than a spurious death + birth.
///
/// Inode reuse (a delete + create that recycles the same inode number) is
/// disambiguated separately, via the full-nanosecond [`Observation::ctime`]
/// tiebreaker: when ctime regresses or jumps for the same `(dev, ino)`, the
/// reader treats it as a new identity (tombstone + new series). ctime lives on
/// the observation, not the key, precisely so a rename's ctime bump can't fork
/// the series.
///
/// When inode metadata is unavailable (or on non-unix), we fall back to the
/// path. `#[serde(untagged)]` keeps the JSON compact — an inode key serializes
/// as `{"dev":..,"ino":..}` and a path key as a bare string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ObsKey {
    /// Unix inode identity. `(dev, ino)` only — ctime is a per-observation
    /// reuse tiebreaker, not part of the key, so renames stay continuous.
    Inode { dev: u64, ino: u64 },
    /// Path-based identity fallback.
    Path(PathBuf),
}

impl ObsKey {
    /// Build the continuity key for a scanned entry. When unix inode metadata is
    /// present we key on `(dev, ino)` ONLY (ctime is carried separately on the
    /// [`Observation`] as a reuse tiebreaker, not folded into the key — see the
    /// enum docs). Otherwise we fall back to the path.
    pub fn for_entry(dev: Option<u64>, ino: Option<u64>, path: &Path) -> Self {
        match (dev, ino) {
            (Some(dev), Some(ino)) => ObsKey::Inode { dev, ino },
            _ => ObsKey::Path(path.to_path_buf()),
        }
    }
}

/// Decide, for two successive observations sharing the same [`ObsKey::Inode`],
/// whether the inode number was REUSED (a delete + create recycled it) versus
/// the same file persisting. Returns `true` when the series should be forked
/// (tombstone the old identity, start a new one).
///
/// The discriminator is a ctime **regression**: `st_ctime` for one physical
/// inode is monotonic non-decreasing over its lifetime, so a NEXT ctime that is
/// strictly earlier than the PREV ctime is only possible if the inode number
/// now points at a different, younger inode — i.e. it was reused. We
/// deliberately do NOT fork on a forward ctime bump: a `rename(2)`, `chmod`,
/// `chown`, or link change all push ctime forward while keeping the same inode,
/// and the rename policy (see [`ObsKey`] docs) is to keep those continuous.
/// Treating only a regression as reuse is what lets a renamed file stay ONE
/// series instead of reading as death + birth.
///
/// Missing ctime on either side (path-keyed/legacy/non-unix observations)
/// carries no reuse signal, so it never forks.
pub fn inode_reused(prev_ctime: Option<i64>, next_ctime: Option<i64>) -> bool {
    match (prev_ctime, next_ctime) {
        (Some(prev), Some(next)) => next < prev,
        _ => false,
    }
}

/// One point in the time series: bytes observed for a key at a timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// Schema version. Always stamped to [`SERIES_SCHEMA`] on write.
    pub v: u32,
    pub ts: DateTime<Utc>,
    pub key: ObsKey,
    pub path: PathBuf,
    pub bytes: u64,
    pub source: Source,
    pub scan_id: String,
    /// Inode change time as full nanoseconds-since-epoch (NOT whole seconds),
    /// captured alongside `(dev, ino)`. This is the inode-reuse tiebreaker: for
    /// a given [`ObsKey::Inode`], a ctime that regresses or jumps signals that
    /// the inode number was recycled by a delete + create, so the reader should
    /// fork a new series (tombstone + new identity) rather than merge two
    /// physically distinct inodes. Kept OFF the key so a `rename(2)` (which
    /// bumps ctime but keeps the inode) stays one continuous series. `None` for
    /// path-keyed/non-unix observations and legacy lines. Additive +
    /// serde-default so existing `series.jsonl` still deserializes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctime: Option<i64>,
}

impl Observation {
    /// Construct a non-tombstone observation, stamping the current schema.
    ///
    /// `ctime` is the full-nanosecond inode change time (the reuse tiebreaker);
    /// pass `None` for path-keyed or non-unix observations.
    pub fn new(
        key: ObsKey,
        path: PathBuf,
        bytes: u64,
        source: Source,
        scan_id: impl Into<String>,
        ts: DateTime<Utc>,
        ctime: Option<i64>,
    ) -> Self {
        Self {
            v: SERIES_SCHEMA,
            ts,
            key,
            path,
            bytes,
            source,
            scan_id: scan_id.into(),
            ctime,
        }
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// `~/.diskspace/series.jsonl` — the raw append-only log.
pub fn series_path() -> PathBuf {
    profile::data_dir().join("series.jsonl")
}

/// `~/.diskspace/series.daily.jsonl` — one finalized observation per (day, key).
pub fn daily_path() -> PathBuf {
    profile::data_dir().join("series.daily.jsonl")
}

/// `~/.diskspace/series.rollup.hw` — the rollup high-water mark (recompute state).
pub fn rollup_hw_path() -> PathBuf {
    profile::data_dir().join("series.rollup.hw")
}

// Internal path helpers parameterized by base dir so tests can use a tempdir
// without touching the real `~/.diskspace`.
fn series_path_in(base: &Path) -> PathBuf {
    base.join("series.jsonl")
}
fn daily_path_in(base: &Path) -> PathBuf {
    base.join("series.daily.jsonl")
}
fn rollup_hw_path_in(base: &Path) -> PathBuf {
    base.join("series.rollup.hw")
}

// ---------------------------------------------------------------------------
// Append
// ---------------------------------------------------------------------------

/// Append a single observation. Best-effort — logs and swallows errors so a
/// measurement write never blocks or panics an action (mirrors `history::append`).
pub fn append(obs: &Observation) {
    if let Err(e) = append_batch_in(&profile::data_dir(), std::slice::from_ref(obs)) {
        eprintln!("(series: failed to append observation: {})", e);
    }
}

/// Append a batch of observations under ONE exclusive lock: acquire the lock,
/// write every line, flush, then unlock. Each observation's `v` is restamped to
/// [`SERIES_SCHEMA`] so callers can't accidentally persist a wrong version.
pub fn append_batch(observations: &[Observation]) -> Result<()> {
    append_batch_in(&profile::data_dir(), observations)
}

/// Append a tombstone marker (the key/path no longer exists). Best-effort.
pub fn tombstone(key: ObsKey, path: PathBuf, scan_id: impl Into<String>) {
    let obs = Observation {
        v: SERIES_SCHEMA,
        ts: Utc::now(),
        key,
        path,
        bytes: 0,
        source: Source::Tombstone,
        scan_id: scan_id.into(),
        ctime: None,
    };
    append(&obs);
}

fn append_batch_in(base: &Path, observations: &[Observation]) -> Result<()> {
    if observations.is_empty() {
        return Ok(());
    }
    let path = series_path_in(base);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Serialize first so a bad value never leaves a half-written line under the
    // lock. Each line ends in '\n'; a torn final line (crash mid-write) is
    // tolerated by the readers below.
    let mut buf = String::new();
    for obs in observations {
        let mut line = obs.clone();
        line.v = SERIES_SCHEMA;
        buf.push_str(&serde_json::to_string(&line)?);
        buf.push('\n');
    }

    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    // ONE exclusive lock for the whole batch — concurrent writers block here,
    // so lines never interleave or tear. `FileExt::lock` is the blocking
    // exclusive lock (flock LOCK_EX on unix).
    FileExt::lock(&file)?;
    let write_res = (|| -> std::io::Result<()> {
        let mut w = BufWriter::new(&file);
        w.write_all(buf.as_bytes())?;
        w.flush()?;
        Ok(())
    })();
    // Always release the lock, even if the write failed.
    let unlock_res = FileExt::unlock(&file);
    write_res?;
    unlock_res?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

/// Read every observation from `series.jsonl`, newest-last (file order).
///
/// Torn/partial-final lines and any line with `v > SERIES_SCHEMA` (a future
/// schema we don't understand) are skipped silently via `filter_map(.ok())`.
pub fn read_all() -> Result<Vec<Observation>> {
    read_all_in(&profile::data_dir())
}

/// Observations whose `ts` falls within `[start, end]` (inclusive).
pub fn read_range(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Observation>> {
    let all = read_all_in(&profile::data_dir())?;
    Ok(all
        .into_iter()
        .filter(|o| o.ts >= start && o.ts <= end)
        .collect())
}

/// The last `n` observations in file order.
pub fn read_recent(n: usize) -> Result<Vec<Observation>> {
    let all = read_all_in(&profile::data_dir())?;
    let len = all.len();
    let start = len.saturating_sub(n);
    Ok(all[start..].to_vec())
}

fn read_all_in(base: &Path) -> Result<Vec<Observation>> {
    let path = series_path_in(base);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)?;
    Ok(parse_observations(&content))
}

/// Crate-internal base-dir seam for readers that must target a tempdir (the
/// advisory `metrics` layer reads `series.jsonl` and is exercised against a
/// throwaway base in tests). Thin pass-through to [`read_all_in`].
pub(crate) fn read_all_in_pub(base: &Path) -> Result<Vec<Observation>> {
    read_all_in(base)
}

/// Crate-internal base-dir seam for the batch writer (used by `metrics` tests to
/// seed a tempdir series). Thin pass-through to [`append_batch_in`]. Test-only:
/// production writes go through [`append`] / [`append_batch`].
#[cfg(test)]
pub(crate) fn append_batch_in_pub(base: &Path, observations: &[Observation]) -> Result<()> {
    append_batch_in(base, observations)
}

/// Crate-internal base-dir seam for the batch writer, exposed to the
/// `selfcheck` gate (which seeds a TEMP scratch series at runtime to verify the
/// store's invariants hold against a throwaway base — never the real
/// `~/.diskspace`). Thin pass-through to [`append_batch_in`]. Production writes
/// still go through [`append`] / [`append_batch`].
pub(crate) fn append_batch_in_base(base: &Path, observations: &[Observation]) -> Result<()> {
    append_batch_in(base, observations)
}

/// Crate-internal base-dir seam for the daily rollup, exposed to the `selfcheck`
/// gate so it can verify recompute/idempotency against a TEMP scratch dir.
/// Thin pass-through to [`rollup_daily_in`]. Production goes through
/// [`rollup_daily`].
pub(crate) fn rollup_daily_in_base(base: &Path) -> Result<()> {
    rollup_daily_in(base)
}

/// `<base>/series.daily.jsonl` — crate-internal seam so `selfcheck` can read the
/// rollup output under a TEMP scratch base.
pub(crate) fn daily_path_in_base(base: &Path) -> PathBuf {
    daily_path_in(base)
}

/// `<base>/series.rollup.hw` — crate-internal seam so `selfcheck` can read/delete
/// the rollup high-water mark under a TEMP scratch base.
pub(crate) fn rollup_hw_path_in_base(base: &Path) -> PathBuf {
    rollup_hw_path_in(base)
}

/// `<base>/series.jsonl` — crate-internal seam so `selfcheck` can locate the raw
/// series log under a TEMP scratch base.
pub(crate) fn series_path_in_base(base: &Path) -> PathBuf {
    series_path_in(base)
}

/// Parse newline-delimited observations, skipping blank lines, unparseable
/// (torn) lines, and future-schema (`v > SERIES_SCHEMA`) lines.
fn parse_observations(content: &str) -> Vec<Observation> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Observation>(l).ok())
        .filter(|o| o.v <= SERIES_SCHEMA)
        .collect()
}

// ---------------------------------------------------------------------------
// Daily rollup
// ---------------------------------------------------------------------------

/// Persisted rollup state: how far into `series.jsonl` we've consumed, and the
/// last UTC day we finalized into `series.daily.jsonl`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RollupHw {
    /// Byte offset in `series.jsonl` up to which all lines are fully consumed
    /// AND finalized (i.e. belong to a day strictly before `last_rolled_date`).
    #[serde(default)]
    offset: u64,
    /// The most recent UTC day (YYYY-MM-DD) we have finalized. Days strictly
    /// before this are written; the current day stays open until a later day
    /// appears.
    #[serde(default)]
    last_rolled_date: Option<String>,
}

/// Roll up raw observations into one finalized line per `(UTC day, key)`.
///
/// Semantics:
///   * Aggregates the **last-observed** bytes for each key on each day.
///   * A day is finalized only once a strictly-later day's observation exists,
///     so the current (still-growing) day is never written prematurely.
///   * **Idempotent**: no new data => no-op; re-running never duplicates a day.
///   * **Fully recomputable**: deleting `series.daily.jsonl` + `series.rollup.hw`
///     and re-running reproduces byte-identical output from raw.
///   * Never prunes `series.jsonl`.
pub fn rollup_daily() -> Result<()> {
    rollup_daily_in(&profile::data_dir())
}

fn rollup_daily_in(base: &Path) -> Result<()> {
    let series = series_path_in(base);
    if !series.exists() {
        return Ok(());
    }

    let hw_path = rollup_hw_path_in(base);
    let hw = load_hw(&hw_path);

    // Read the whole raw log. We always recompute from the full file (cheap and
    // robust); `offset` only tells us how many bytes were finalized last time,
    // which lets us no-op when nothing new arrived and avoids re-reading
    // finalized days into the output.
    let mut file = OpenOptions::new().read(true).open(&series)?;
    let file_len = file.metadata()?.len();

    // No-op fast path: nothing appended since we last finalized up to `offset`,
    // and we've already established a rolled date. Re-reading the open day would
    // produce the same finalized output, so skip the work.
    if file_len == hw.offset {
        return Ok(());
    }

    let mut content = String::new();
    file.seek(SeekFrom::Start(0))?;
    file.read_to_string(&mut content)?;

    // Aggregate last-observed bytes per (day, key). BTreeMap keeps output
    // deterministic (sorted by day, then by key's canonical JSON) so the rollup
    // is byte-identical across runs and across full recomputes.
    //
    // Value carries the observation index so "last observed that day" is a
    // stable, total order even when two observations share a timestamp.
    type DayKey = (String, String);
    let mut agg: BTreeMap<DayKey, (usize, Observation)> = BTreeMap::new();
    let mut max_day: Option<String> = None;

    for (idx, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let obs: Observation = match serde_json::from_str(line) {
            Ok(o) => o,
            Err(_) => continue, // torn/partial line — skip
        };
        if obs.v > SERIES_SCHEMA {
            continue; // future schema — skip
        }
        let day = utc_day(&obs.ts);
        let key_json = serde_json::to_string(&obs.key).unwrap_or_default();
        max_day = Some(match max_day {
            Some(d) if d >= day => d,
            _ => day.clone(),
        });
        agg.entry((day, key_json))
            .and_modify(|(i, o)| {
                if idx >= *i {
                    *i = idx;
                    *o = obs.clone();
                }
            })
            .or_insert((idx, obs));
    }

    // A day is "finalized" only if a strictly-later day exists in the data.
    let finalize_before = match &max_day {
        Some(d) => d.clone(),
        None => return Ok(()), // no parseable observations yet
    };

    // Build the finalized output deterministically. BTreeMap iteration is sorted
    // by (day, key_json), so the file is byte-identical given the same raw input.
    let mut out = String::new();
    let mut wrote_any = false;
    for ((day, _key_json), (_idx, obs)) in &agg {
        if *day < finalize_before {
            out.push_str(&serde_json::to_string(obs)?);
            out.push('\n');
            wrote_any = true;
        }
    }

    // Rewrite the daily file from scratch every run. Because finalized days never
    // change once their later day exists, this is stable and recomputable.
    let daily = daily_path_in(base);
    if let Some(parent) = daily.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_atomic(&daily, out.as_bytes())?;

    // Persist new high-water mark. `offset = file_len` records that we've
    // consumed the whole current file; `last_rolled_date = finalize_before`
    // records the boundary day (everything strictly before it is written).
    let new_hw = RollupHw {
        offset: file_len,
        last_rolled_date: Some(finalize_before),
    };
    // Only touch the hw file if it actually changed, so an idempotent re-run
    // leaves mtime/content untouched.
    let _ = wrote_any;
    save_hw_if_changed(&hw_path, &hw, &new_hw)?;

    Ok(())
}

fn load_hw(path: &Path) -> RollupHw {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => RollupHw::default(),
    }
}

fn save_hw_if_changed(path: &Path, old: &RollupHw, new: &RollupHw) -> Result<()> {
    if old.offset == new.offset && old.last_rolled_date == new.last_rolled_date {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string(new)?;
    write_atomic(path, json.as_bytes())?;
    Ok(())
}

/// Write `bytes` to `path` atomically via a temp file + rename, so a reader
/// never sees a half-written rollup and a crash can't corrupt the file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// UTC calendar day as `YYYY-MM-DD`.
fn utc_day(ts: &DateTime<Utc>) -> String {
    format!("{:04}-{:02}-{:02}", ts.year(), ts.month(), ts.day())
}

#[allow(dead_code)]
fn day_start(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Arc;
    use std::thread;

    /// A throwaway base dir under the OS temp dir, cleaned up on drop. We pass it
    /// explicitly to the `*_in` helpers so tests never touch the real
    /// `~/.diskspace`.
    struct TempBase {
        path: PathBuf,
    }
    impl TempBase {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let uniq = format!(
                "diskspace-series-test-{}-{}-{}",
                tag,
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            );
            p.push(uniq);
            std::fs::create_dir_all(&p).unwrap();
            Self { path: p }
        }
        fn path(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TempBase {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn ts(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).unwrap()
    }

    fn obs(path: &str, bytes: u64, when: DateTime<Utc>) -> Observation {
        Observation::new(
            ObsKey::Path(PathBuf::from(path)),
            PathBuf::from(path),
            bytes,
            Source::Full,
            "scan-test",
            when,
            None,
        )
    }

    #[test]
    fn append_batch_then_read_all_roundtrips_and_stamps_schema() {
        let base = TempBase::new("roundtrip");
        let batch: Vec<Observation> = (0..5)
            .map(|i| {
                obs(
                    &format!("/x/{i}"),
                    (i as u64) * 100,
                    ts(2026, 6, 1, 12, 0, i),
                )
            })
            .collect();
        append_batch_in(base.path(), &batch).unwrap();

        let got = read_all_in(base.path()).unwrap();
        assert_eq!(got.len(), 5, "all 5 observations round-trip");
        for (i, o) in got.iter().enumerate() {
            assert_eq!(o.v, SERIES_SCHEMA, "schema stamped on every line");
            assert_eq!(o.bytes, (i as u64) * 100);
            assert_eq!(o.path, PathBuf::from(format!("/x/{i}")));
        }
    }

    #[test]
    fn append_batch_restamps_wrong_schema_version() {
        let base = TempBase::new("restamp");
        let mut bad = obs("/y/1", 42, ts(2026, 6, 1, 0, 0, 0));
        bad.v = 999; // caller tried to persist a bogus version
        append_batch_in(base.path(), &[bad]).unwrap();
        let got = read_all_in(base.path()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].v, SERIES_SCHEMA, "writer forces correct schema");
    }

    #[test]
    fn torn_final_line_is_skipped_no_panic() {
        let base = TempBase::new("torn");
        let good = vec![
            obs("/a", 1, ts(2026, 6, 1, 0, 0, 0)),
            obs("/b", 2, ts(2026, 6, 1, 0, 0, 1)),
        ];
        append_batch_in(base.path(), &good).unwrap();

        // Manually append a partial (torn) JSON line — simulates a crash mid-write.
        let p = series_path_in(base.path());
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        write!(
            f,
            "{{\"v\":1,\"ts\":\"2026-06-01T00:00:02Z\",\"key\":\"/c\",\"byt"
        )
        .unwrap();
        drop(f);

        let got = read_all_in(base.path()).unwrap();
        assert_eq!(got.len(), 2, "torn line skipped, two good lines remain");
    }

    #[test]
    fn future_schema_line_is_skipped() {
        let base = TempBase::new("future");
        append_batch_in(base.path(), &[obs("/a", 1, ts(2026, 6, 1, 0, 0, 0))]).unwrap();
        // Hand-write a syntactically valid line from a future schema (v > current).
        let p = series_path_in(base.path());
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        let future = format!(
            "{{\"v\":{},\"ts\":\"2026-06-01T00:00:05Z\",\"key\":\"/z\",\"path\":\"/z\",\"bytes\":9,\"source\":\"full\",\"scan_id\":\"s\"}}\n",
            SERIES_SCHEMA + 1
        );
        f.write_all(future.as_bytes()).unwrap();
        drop(f);

        let got = read_all_in(base.path()).unwrap();
        assert_eq!(got.len(), 1, "future-schema line skipped");
    }

    #[test]
    fn concurrent_append_batch_no_torn_lines() {
        let base = Arc::new(TempBase::new("concurrent"));
        let threads = 5;
        let per_thread = 25; // 5 * 25 = 125 lines total (>= 100)
        let mut handles = Vec::new();
        for t in 0..threads {
            let base = Arc::clone(&base);
            handles.push(thread::spawn(move || {
                let batch: Vec<Observation> = (0..per_thread)
                    .map(|i| {
                        obs(
                            &format!("/t{t}/i{i}"),
                            (t * 1000 + i) as u64,
                            ts(2026, 6, 1, 0, 0, 0),
                        )
                    })
                    .collect();
                append_batch_in(base.path(), &batch).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // Every line must parse (no torn/interleaved lines under the lock), and
        // the count must equal the total written.
        let p = series_path_in(base.path());
        let content = std::fs::read_to_string(&p).unwrap();
        let total_lines = content.lines().filter(|l| !l.trim().is_empty()).count();
        assert_eq!(total_lines, threads * per_thread, "no lines lost");
        let parsed = read_all_in(base.path()).unwrap();
        assert_eq!(
            parsed.len(),
            threads * per_thread,
            "every line parses — lock prevented torn/interleaved writes"
        );
    }

    #[test]
    fn tombstone_emits_zero_byte_marker() {
        let base = TempBase::new("tombstone");
        let t = Observation {
            v: SERIES_SCHEMA,
            ts: ts(2026, 6, 1, 0, 0, 0),
            key: ObsKey::Path(PathBuf::from("/gone")),
            path: PathBuf::from("/gone"),
            bytes: 0,
            source: Source::Tombstone,
            scan_id: "scan-test".into(),
            ctime: None,
        };
        append_batch_in(base.path(), &[t]).unwrap();
        let got = read_all_in(base.path()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].source, Source::Tombstone);
        assert_eq!(got[0].bytes, 0);
        assert_eq!(got[0].path, PathBuf::from("/gone"));
    }

    #[test]
    fn rollup_daily_idempotent() {
        let base = TempBase::new("rollup-idem");
        // Two days for the same key: day 1 ends at 300 bytes, day 2 (later) is
        // open. Day 1 should finalize to its last-observed value (300).
        let batch = vec![
            obs("/a", 100, ts(2026, 6, 1, 8, 0, 0)),
            obs("/a", 300, ts(2026, 6, 1, 20, 0, 0)),
            obs("/a", 500, ts(2026, 6, 2, 9, 0, 0)),
        ];
        append_batch_in(base.path(), &batch).unwrap();

        rollup_daily_in(base.path()).unwrap();
        let daily1 = std::fs::read(daily_path_in(base.path())).unwrap();
        let hw1 = std::fs::read(rollup_hw_path_in(base.path())).unwrap();

        // Day 1 finalized; day 2 still open.
        let lines: Vec<Observation> =
            parse_observations(&String::from_utf8(daily1.clone()).unwrap());
        assert_eq!(lines.len(), 1, "only day 1 is finalized");
        assert_eq!(lines[0].bytes, 300, "last-observed bytes for the day");

        // Second run with no new data => byte-identical daily + unchanged hw.
        rollup_daily_in(base.path()).unwrap();
        let daily2 = std::fs::read(daily_path_in(base.path())).unwrap();
        let hw2 = std::fs::read(rollup_hw_path_in(base.path())).unwrap();
        assert_eq!(daily1, daily2, "daily rollup byte-identical on re-run");
        assert_eq!(hw1, hw2, "high-water mark unchanged on re-run");
    }

    #[test]
    fn rollup_recompute_from_raw_is_identical() {
        let base = TempBase::new("rollup-recompute");
        let batch = vec![
            obs("/a", 100, ts(2026, 6, 1, 8, 0, 0)),
            obs("/b", 250, ts(2026, 6, 1, 9, 0, 0)),
            obs("/a", 300, ts(2026, 6, 1, 20, 0, 0)),
            obs("/a", 500, ts(2026, 6, 2, 9, 0, 0)),
            obs("/b", 700, ts(2026, 6, 2, 10, 0, 0)),
            obs("/a", 999, ts(2026, 6, 3, 1, 0, 0)),
        ];
        append_batch_in(base.path(), &batch).unwrap();

        rollup_daily_in(base.path()).unwrap();
        let daily_first = std::fs::read(daily_path_in(base.path())).unwrap();

        // Wipe derived state, recompute purely from raw series.jsonl.
        std::fs::remove_file(daily_path_in(base.path())).unwrap();
        std::fs::remove_file(rollup_hw_path_in(base.path())).unwrap();
        rollup_daily_in(base.path()).unwrap();
        let daily_recomputed = std::fs::read(daily_path_in(base.path())).unwrap();

        assert_eq!(
            daily_first, daily_recomputed,
            "rollup is fully recomputable from raw"
        );
        // Sanity: days 1 and 2 finalized (2 keys * 2 days = 4 lines); day 3 open.
        let lines = parse_observations(&String::from_utf8(daily_recomputed).unwrap());
        assert_eq!(lines.len(), 4, "two finalized days, two keys each");
    }

    #[test]
    fn rollup_no_op_when_no_new_data() {
        let base = TempBase::new("rollup-noop");
        let batch = vec![
            obs("/a", 100, ts(2026, 6, 1, 8, 0, 0)),
            obs("/a", 500, ts(2026, 6, 2, 9, 0, 0)),
        ];
        append_batch_in(base.path(), &batch).unwrap();
        rollup_daily_in(base.path()).unwrap();
        let hw_before = std::fs::read(rollup_hw_path_in(base.path())).unwrap();
        // Re-run without appending — offset == file_len fast path => no change.
        rollup_daily_in(base.path()).unwrap();
        let hw_after = std::fs::read(rollup_hw_path_in(base.path())).unwrap();
        assert_eq!(hw_before, hw_after, "no new data => hw untouched");
    }

    #[test]
    fn inode_key_roundtrips_untagged() {
        let base = TempBase::new("inode-key");
        let o = Observation::new(
            ObsKey::Inode {
                dev: 16777220,
                ino: 42,
            },
            PathBuf::from("/dev/file"),
            123,
            Source::Restat,
            "scan-test",
            ts(2026, 6, 1, 0, 0, 0),
            Some(1_700_000_000_000_000_000),
        );
        append_batch_in(base.path(), &[o]).unwrap();
        let got = read_all_in(base.path()).unwrap();
        assert_eq!(got.len(), 1);
        match &got[0].key {
            ObsKey::Inode { dev, ino } => {
                assert_eq!((*dev, *ino), (16777220, 42));
            }
            other => panic!("expected inode key, got {other:?}"),
        }
        assert_eq!(got[0].source, Source::Restat);
        // The full-nanosecond ctime tiebreaker round-trips on the observation,
        // not the key.
        assert_eq!(got[0].ctime, Some(1_700_000_000_000_000_000));
    }

    // -----------------------------------------------------------------------
    // Finding-1: sub-second ctime must survive so inode reuse INSIDE one
    // wall-clock second is still distinguishable.
    // -----------------------------------------------------------------------

    #[test]
    fn ctime_carries_subsecond_resolution_for_inode_reuse() {
        // Two physically distinct inodes that (in the buggy whole-second world)
        // would have collided: same dev, same reused ino, ctime in the SAME
        // wall-clock second but different nanoseconds. With full-nanos ctime the
        // reader can still tell them apart.
        let prev_ctime = 1_700_000_000_000_000_000i64; // sec 1_700_000_000, nsec 0
        let next_ctime = 1_700_000_000_500_000_000i64; // SAME second, +0.5s nsec

        // Same-second-but-different-nanos with the inode number recycled. A
        // forward-only check can't see reuse here (ctime went forward), but the
        // sub-second resolution is preserved end-to-end, which is the property
        // finding-1 demanded: whole-second truncation would have made these
        // two ctimes byte-identical.
        assert_ne!(
            prev_ctime, next_ctime,
            "sub-second ctime distinguishes two inodes within one second"
        );

        // And a same-second reuse that REGRESSES (created-then-deleted-then-\
        // recreated with an earlier high-res ctime, e.g. clock skew / lower
        // nanos) is detected as reuse — impossible to see at whole-second
        // granularity because both truncate to the identical second.
        let reused_earlier = 1_700_000_000_100_000_000i64; // same second, fewer nanos
        assert!(
            inode_reused(Some(next_ctime), Some(reused_earlier)),
            "a within-second ctime regression is caught only with sub-second resolution"
        );
    }

    // -----------------------------------------------------------------------
    // Finding-2: a rename must read as ONE continuous series, NOT death+birth.
    // -----------------------------------------------------------------------

    #[test]
    fn rename_keeps_one_continuous_inode_series() {
        let base = TempBase::new("rename-continuous");
        let dev = 16777220u64;
        let ino = 99u64;

        // Scan 1: file observed at /old. rename(2) keeps the inode but bumps
        // ctime, so scan 2 sees the SAME (dev, ino) at /new with a LATER ctime.
        let key1 = ObsKey::for_entry(Some(dev), Some(ino), &PathBuf::from("/old"));
        let key2 = ObsKey::for_entry(Some(dev), Some(ino), &PathBuf::from("/new"));

        // The continuity key is identical across the rename — this is the crux:
        // (dev, ino) only, ctime excluded.
        assert_eq!(
            key1, key2,
            "rename keeps the SAME (dev, ino) continuity key"
        );

        let ctime_before = 1_700_000_000_000_000_000i64;
        let ctime_after = 1_700_000_005_000_000_000i64; // rename bumped ctime forward

        // Forward ctime bump on the same inode must NOT be read as inode reuse:
        // a rename is same-identity, so we do NOT fork the series.
        assert!(
            !inode_reused(Some(ctime_before), Some(ctime_after)),
            "rename's forward ctime bump must NOT fork the series"
        );

        let o1 = Observation::new(
            key1.clone(),
            PathBuf::from("/old"),
            1000,
            Source::Full,
            "scan-1",
            ts(2026, 6, 1, 8, 0, 0),
            Some(ctime_before),
        );
        let o2 = Observation::new(
            key2.clone(),
            PathBuf::from("/new"),
            1000,
            Source::Full,
            "scan-2",
            ts(2026, 6, 2, 8, 0, 0),
            Some(ctime_after),
        );
        append_batch_in(base.path(), &[o1, o2]).unwrap();

        let got = read_all_in(base.path()).unwrap();
        assert_eq!(got.len(), 2, "two observations recorded");

        // Group by continuity key: a rename must collapse to ONE key (one
        // series), not two — and there must be NO tombstone.
        let distinct_keys: std::collections::HashSet<&ObsKey> =
            got.iter().map(|o| &o.key).collect();
        assert_eq!(
            distinct_keys.len(),
            1,
            "renamed file is ONE continuous series, not a death + birth"
        );
        assert!(
            got.iter().all(|o| o.source != Source::Tombstone),
            "no tombstone emitted for a pure rename"
        );
        // The path legitimately changed; the IDENTITY did not.
        assert_eq!(got[0].path, PathBuf::from("/old"));
        assert_eq!(got[1].path, PathBuf::from("/new"));
    }

    #[test]
    fn inode_reuse_after_delete_create_forks_the_series() {
        // A delete + create that recycles the inode number must NOT be merged
        // into the prior series. The recycled inode's ctime regresses relative
        // to the now-dead file's last ctime (the new inode is younger), so the
        // reuse check fires and the reader forks.
        let dead_ctime = 1_700_000_009_000_000_000i64; // old file, last seen
        let reused_ctime = 1_700_000_003_000_000_000i64; // new inode, earlier ctime

        assert!(
            inode_reused(Some(dead_ctime), Some(reused_ctime)),
            "a ctime regression on the same (dev, ino) signals inode reuse → fork"
        );

        // Missing ctime (path-keyed / legacy / non-unix) is never enough to
        // claim reuse.
        assert!(!inode_reused(None, Some(reused_ctime)));
        assert!(!inode_reused(Some(dead_ctime), None));
        assert!(!inode_reused(None, None));
    }

    #[test]
    fn legacy_inode_line_with_ctime_in_key_still_deserializes() {
        // Lines written before this change carried ctime INSIDE the inode key
        // (`{"dev":..,"ino":..,"ctime":..}`) and had no top-level `ctime` field.
        // Untagged deserialization must ignore the now-extraneous in-key ctime
        // and read the line as the new `(dev, ino)` key with `ctime: None`.
        let base = TempBase::new("legacy-inode");
        let p = series_path_in(base.path());
        std::fs::create_dir_all(base.path()).unwrap();
        let legacy = "{\"v\":1,\"ts\":\"2026-06-01T00:00:00Z\",\"key\":{\"dev\":5,\"ino\":7,\"ctime\":1700000000},\"path\":\"/legacy\",\"bytes\":42,\"source\":\"full\",\"scan_id\":\"s\"}\n";
        std::fs::write(&p, legacy).unwrap();

        let got = read_all_in(base.path()).unwrap();
        assert_eq!(got.len(), 1, "legacy inode line still parses");
        assert_eq!(got[0].key, ObsKey::Inode { dev: 5, ino: 7 });
        assert_eq!(got[0].bytes, 42);
        assert_eq!(got[0].ctime, None, "legacy line has no top-level ctime");
    }

    #[test]
    fn for_entry_drops_ctime_from_key_and_falls_back_to_path() {
        // Unix metadata present → (dev, ino) only, ctime NOT in the key.
        let k = ObsKey::for_entry(Some(5), Some(7), &PathBuf::from("/p"));
        assert_eq!(k, ObsKey::Inode { dev: 5, ino: 7 });

        // Two observations of the same inode at different ctimes share ONE key.
        let k_later = ObsKey::for_entry(Some(5), Some(7), &PathBuf::from("/p-renamed"));
        assert_eq!(k, k_later, "ctime is excluded, so the key is rename-stable");

        // Missing inode metadata → path fallback.
        let kp = ObsKey::for_entry(None, Some(7), &PathBuf::from("/p"));
        assert_eq!(kp, ObsKey::Path(PathBuf::from("/p")));
        let kp2 = ObsKey::for_entry(Some(5), None, &PathBuf::from("/p"));
        assert_eq!(kp2, ObsKey::Path(PathBuf::from("/p")));
    }
}

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use jwalk::WalkDir;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::candidate::{Category, ScannedEntry};
use super::rules::Rule;
use super::series::{ObsKey, Observation, Source};
use crate::profile;

/// Cap on how many of the largest directories we persist into `scan.json`. This
/// keeps the cache small (top-N only) while giving `hunt` enough big-directory
/// totals to find — and adaptively drill into — the genuinely unruled bytes
/// without re-walking $HOME. 400 comfortably covers every multi-GB directory on
/// a real $HOME tree while adding only a few KB to the cache.
pub const LARGEST_DIRS_TOP_N: usize = 400;

/// One directory's TOTAL on-disk byte size (its own files plus every descendant),
/// as computed during the walk. This is the TOTAL size, NOT just the rule-matched
/// portion — `hunt` subtracts matched entries from it to find the truly-unruled
/// remainder, glob-aware for free. Persisted (top-N only) so `hunt` can be
/// sub-second instead of re-walking $HOME on every invocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirTotal {
    pub path: PathBuf,
    pub total_bytes: u64,
}

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
    /// Series store schema version this scan was produced under. Additive +
    /// serde-default so legacy scan.json (no `schema`) still deserializes.
    #[serde(default)]
    pub schema: u32,
    /// Stable id for this scan, derived from `scanned_at` + `total_bytes` (no
    /// random/extra deps). Used to tag series observations back to their scan.
    #[serde(default)]
    pub scan_id: String,
    /// Agent-surface enrichment (P2): ONE whole-$HOME advisory metric for this
    /// scan (burn-rate / days-to-full / staleness over the scan root). Populated
    /// by the `scan` command (which has a `Profile`); `None` from the pure
    /// `scanner::scan` walk. Deliberately a SINGLE metric — per-entry metrics
    /// would bloat the 589k-entry cache. Additive + serde-default skip-if-none
    /// so legacy scan.json still deserializes. ADVISORY ONLY.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<crate::core::metrics::Metrics>,
    /// The TOP-N largest directories by TOTAL on-disk bytes (own files plus every
    /// descendant), computed from the `dir_sizes` map already built during the
    /// walk. These are TOTAL sizes, NOT just rule-matched bytes — `hunt` reads
    /// them and subtracts the rule-matched entries underneath to surface the
    /// genuinely-unruled remainder (glob-aware for free) without re-walking $HOME.
    /// Sorted by `total_bytes` descending, capped at [`LARGEST_DIRS_TOP_N`] to
    /// keep the cache small. Additive + serde-default so legacy scan.json (no
    /// `largest_dirs`) still deserializes to an empty Vec.
    #[serde(default)]
    pub largest_dirs: Vec<DirTotal>,
}

/// Pick the top-N largest directories from the per-dir aggregate `dir_sizes` map,
/// sorted by `total_bytes` descending (path as a stable tiebreaker), capped at N.
/// Factored out so it can be unit-tested directly.
fn top_largest_dirs(dir_sizes: &HashMap<PathBuf, u64>, n: usize) -> Vec<DirTotal> {
    let mut dirs: Vec<DirTotal> = dir_sizes
        .iter()
        .filter(|(_, &bytes)| bytes > 0)
        .map(|(path, &total_bytes)| DirTotal {
            path: path.clone(),
            total_bytes,
        })
        .collect();
    // Largest first; tie-break on path for deterministic output across runs.
    dirs.sort_by(|a, b| {
        b.total_bytes
            .cmp(&a.total_bytes)
            .then_with(|| a.path.cmp(&b.path))
    });
    dirs.truncate(n);
    dirs
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
        // Inode identity for series keying. Read from the already-fetched
        // metadata — ZERO new syscalls. None on non-unix.
        //
        // `ctime` carries FULL nanosecond resolution (ctime_sec * 1e9 +
        // ctime_nsec), not whole seconds. The series layer keys continuity on
        // (dev, ino) alone and uses this ctime only as an inode-reuse
        // tiebreaker; sub-second resolution is required because diskspace's
        // domain is build/cache churn where a delete + create can reuse the
        // same inode inside one wall-clock second (whole-second ctime would
        // collide and silently merge two distinct inodes' byte series).
        let dev: Option<u64>;
        let ino: Option<u64>;
        let ctime: Option<i64>;
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
            dev = Some(metadata.dev());
            ino = Some(metadata.ino());
            ctime = Some(ctime_nanos(metadata.ctime(), metadata.ctime_nsec()));
        }
        #[cfg(not(unix))]
        {
            size = if metadata.is_file() {
                metadata.len()
            } else {
                0
            };
            dev = None;
            ino = None;
            ctime = None;
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
                dev,
                ino,
                ctime,
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

    // Persist the TOP-N largest directories by TOTAL on-disk bytes, reusing the
    // `dir_sizes` map already built during the walk. These TOTAL sizes (not just
    // rule-matched bytes) let `hunt` find — and adaptively drill into — the
    // genuinely-unruled remainder without re-walking $HOME. Top-N only so the
    // cache stays small.
    let largest_dirs = top_largest_dirs(&dir_sizes, LARGEST_DIRS_TOP_N);

    // Compute `scanned_at` once so the derived `scan_id` matches the stored
    // timestamp. The id is deterministic from (timestamp nanos, total_bytes) —
    // no random source, no extra deps.
    let scanned_at = Utc::now();
    let scan_id = format!(
        "{}-{}",
        scanned_at
            .timestamp_nanos_opt()
            .unwrap_or_else(|| scanned_at.timestamp_millis()),
        total_bytes
    );

    Ok(ScanResult {
        scanned_at,
        root: root.to_path_buf(),
        entries,
        total_bytes,
        cloud_placeholder_bytes,
        category_totals,
        schema: crate::core::series::SERIES_SCHEMA,
        scan_id,
        // The pure walk has no Profile; the `scan` command computes the single
        // whole-$HOME metric after the walk (see commands/scan.rs).
        metrics: None,
        largest_dirs,
    })
}

// ===========================================================================
// Incremental scanner — `tick`
// ===========================================================================
//
// `scan()` above is the FULL ~40s walk of 589k entries. `tick()` is the cheap,
// repeatable measurement step: it watches for change three ways and only does
// the expensive full walk once a day as a true-up.
//
//   * Tier A — STRUCTURAL CHURN: walk, but for every directory compare its
//     current mtime to the prior tick's. If a directory's mtime is unchanged we
//     SKIP recursing into it and reuse the cached subtree byte total. New/changed
//     subtrees emit `Source::Incremental`. This catches "a file was added or
//     removed in this directory" (which bumps the parent's mtime) cheaply.
//
//   * Tier B — IN-PLACE GROWTH: a file that grows in place (e.g. a log appended
//     to, a sqlite db, a VM disk image) does NOT bump its parent directory's
//     mtime, so Tier A is BLIND to it. Tier B re-stats every prior registry path
//     DIRECTLY (no walk), keyed by `(dev, ino)`, and emits `Source::Restat` with
//     the current on-disk size. Vanished registry/dir keys emit a tombstone.
//
//   * DAILY TRUE-UP: if 24h have elapsed since the last full walk we run the full
//     `scan()`, emit every matched entry as `Source::Full`, and REBUILD the
//     registry (top-200 and/or >=1GiB) and the dir-mtime cache from scratch. This
//     re-anchors the incremental state against ground truth and reaps any drift.
//
//   * df ADVISORY (signal only, NEVER a trigger): we compare the whole-volume df
//     delta to the bytes we actually accounted for this tick. A large unexplained
//     divergence sets `advisory`, but it MUST NOT widen the scan or force a full
//     walk — that coupling was proven unsound on APFS/containers. `widened_to_full`
//     reflects ONLY the daily-true-up clock, never df.

/// Persisted incremental-scan state, at `~/.diskspace/tick_state.json`.
///
/// Written via atomic temp+rename (single writer per tick — no lock needed, same
/// pattern as `watch::save_state`). Additive + `serde(default)` throughout so an
/// older `tick_state.json` still deserializes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickState {
    /// Schema version for the tick state shape (distinct from the series schema).
    #[serde(default)]
    pub schema: u32,
    /// When the last full walk (`scan()`) completed. Drives the 24h true-up clock.
    pub last_full_walk: DateTime<Utc>,
    /// Per-directory cache: path -> (dir mtime secs, cached subtree bytes). Tier A
    /// skips recursion when the live mtime equals the cached one.
    #[serde(default)]
    pub dir_mtimes: HashMap<PathBuf, (i64, u64)>,
    /// The set of "interesting" entries we re-stat directly each tick (Tier B).
    #[serde(default)]
    pub registry: Vec<RegistryEntry>,
    /// Whole-volume free bytes (df) observed at the end of the prior tick. Seeds
    /// the advisory df-divergence check.
    #[serde(default)]
    pub last_df_free: u64,
}

impl Default for TickState {
    fn default() -> Self {
        Self {
            schema: TICK_STATE_SCHEMA,
            // Epoch sentinel: a brand-new state is always "due" for a full walk,
            // so the first tick true-ups against ground truth.
            last_full_walk: DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_else(Utc::now),
            dir_mtimes: HashMap::new(),
            registry: Vec::new(),
            last_df_free: 0,
        }
    }
}

/// One entry the incremental scanner re-stats directly each tick (Tier B). Keyed
/// by `(dev, ino)` so an in-place grower stays the same identity across ticks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub dev: u64,
    pub ino: u64,
    /// Full-nanosecond ctime — the inode-reuse tiebreaker carried onto each
    /// observation (NOT folded into the continuity key; see `series::ObsKey`).
    pub ctime: i64,
    pub ctime_nsec: i64,
    pub path: PathBuf,
    /// Bytes observed for this entry at the prior tick (on-disk `blocks*512`).
    pub bytes: u64,
    /// When we last successfully re-stat'd this entry.
    pub last_stat: DateTime<Utc>,
}

/// What one `tick()` produced.
///
/// Fields carry a targeted `dead_code` allow: they are read by the tests and by
/// the recorder follow-up, but have no production reader yet (same "API lands
/// before its callers" convention as the rest of the tick surface).
#[derive(Debug)]
#[allow(dead_code)]
pub struct TickOutcome {
    /// Every observation this tick emitted (already appended to the series, but
    /// returned too so callers/tests can inspect them).
    pub observations: Vec<Observation>,
    /// `true` ONLY when the daily true-up clock fired and we ran the full walk.
    /// NEVER set by the df advisory — df can never widen a scan.
    pub widened_to_full: bool,
    /// Set when the whole-volume df delta diverges from the bytes we accounted
    /// for by more than [`ADVISORY_DIVERGENCE_BYTES`]. Advisory only.
    pub advisory: Option<String>,
    /// The state to persist for the next tick.
    pub next_state: TickState,
}

/// Tick-state schema version. Bump on an incompatible shape change.
pub const TICK_STATE_SCHEMA: u32 = 1;

/// Registry size cap for the daily true-up rebuild: keep the N largest entries.
const REGISTRY_TOP_N: usize = 200;

/// Registry inclusion floor: any entry >= this many bytes is always registered
/// (in addition to the top-N), so a handful of huge files are never dropped.
const REGISTRY_MIN_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

/// df-divergence advisory threshold. If the whole-volume df free-space delta
/// exceeds the bytes we accounted for (Incremental + Restat) by more than this,
/// we note it as an ADVISORY — never as a trigger to widen the scan.
const ADVISORY_DIVERGENCE_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

/// `~/.diskspace/tick_state.json`.
///
/// The four public production entry points below (`tick_state_path`,
/// `load_tick_state`, `save_tick_state`, `tick`) are the surface the recorder /
/// agent wiring will call in the follow-up; until then they have no production
/// caller, so they carry a targeted `dead_code` allow — the same "API lands
/// before its callers" convention used in `series.rs` and `metrics.rs`. Their
/// `*_in` seams ARE exercised by the tests below.
#[allow(dead_code)]
pub fn tick_state_path() -> PathBuf {
    profile::data_dir().join("tick_state.json")
}

fn tick_state_path_in(base: &Path) -> PathBuf {
    base.join("tick_state.json")
}

/// Load the persisted tick state, tolerating a missing or garbage file (returns
/// [`TickState::default`], which is "due for a full walk").
#[allow(dead_code)]
pub fn load_tick_state() -> TickState {
    load_tick_state_in(&profile::data_dir())
}

fn load_tick_state_in(base: &Path) -> TickState {
    let path = tick_state_path_in(base);
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => TickState::default(),
    }
}

/// Atomically persist tick state (temp + rename, same pattern as
/// `watch::save_state` — single writer per tick, no lock needed).
#[allow(dead_code)]
pub fn save_tick_state(state: &TickState) -> Result<()> {
    save_tick_state_in(&profile::data_dir(), state)
}

fn save_tick_state_in(base: &Path, state: &TickState) -> Result<()> {
    std::fs::create_dir_all(base)?;
    let path = tick_state_path_in(base);
    let s = serde_json::to_string_pretty(state)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(s.as_bytes())?;
        f.flush()?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// One incremental measurement step. See the module-level comment for the three
/// tiers + df advisory. Returns the observations (also appended to the series via
/// the batch writer) and the next state to persist.
///
/// `prior` is the caller's loaded [`TickState`]; the returned
/// [`TickOutcome::next_state`] must be persisted via [`save_tick_state`].
#[allow(dead_code)]
pub fn tick(root: &Path, rules: &[Rule], prior: &TickState) -> Result<TickOutcome> {
    tick_in(&profile::data_dir(), root, rules, prior, Utc::now())
}

/// Crate-internal base-dir + clock seam for [`tick`], exposed to the `selfcheck`
/// gate so it can drive a tick against a TEMP scratch tree + base with an
/// injected `now` (G3 in-place growth, G7 cost budget) — never the real
/// `~/.diskspace`. Thin pass-through to [`tick_in`]. Production goes through
/// [`tick`].
pub(crate) fn tick_in_base(
    base: &Path,
    root: &Path,
    rules: &[Rule],
    prior: &TickState,
    now: DateTime<Utc>,
) -> Result<TickOutcome> {
    tick_in(base, root, rules, prior, now)
}

/// Base-dir + clock seam for [`tick`] so tests can target a tempdir and inject a
/// fixed "now". Production goes through [`tick`].
fn tick_in(
    base: &Path,
    root: &Path,
    rules: &[Rule],
    prior: &TickState,
    now: DateTime<Utc>,
) -> Result<TickOutcome> {
    // The current whole-volume free bytes — used ONLY for the advisory note.
    let now_df_free = history_free_bytes(root);

    // --- Daily true-up: a full walk re-anchors everything. ----------------
    if now.signed_duration_since(prior.last_full_walk) >= Duration::hours(24) {
        return full_true_up(base, root, rules, prior, now, now_df_free);
    }

    // --- Incremental path: Tier A (churn walk) + Tier B (re-stat). ---------
    let scan_id = format!(
        "tick-{}",
        now.timestamp_nanos_opt()
            .unwrap_or_else(|| now.timestamp_millis())
    );

    let mut observations: Vec<Observation> = Vec::new();
    // Bytes we can account for this tick (Tier A subtree delta + Tier B restat
    // deltas vs the prior tick's cached/registered values). Signed so shrink
    // offsets growth. Each changed byte is counted EXACTLY ONCE (see the Tier A /
    // Tier B accounting below — findings 3 & 4).
    let mut accounted_delta: i64 = 0;

    // Registered inodes, keyed by (dev, ino). Tier B is the SINGLE source of truth
    // for these inodes' deltas; Tier A excludes them from its own delta so a
    // registered file inside a re-walked subtree isn't counted in both tiers.
    let registered_inodes: std::collections::HashSet<(u64, u64)> =
        prior.registry.iter().map(|r| (r.dev, r.ino)).collect();

    // New dir-mtime cache, built as Tier A walks. Starts from the prior cache so
    // skipped (unchanged) subtrees keep their cached bytes.
    let mut next_dir_mtimes: HashMap<PathBuf, (i64, u64)> = prior.dir_mtimes.clone();

    // ---- Tier A: structural-churn walk. ----------------------------------
    // Returns the whole-tree delta counted ONCE (not per changed ancestor), with
    // registered inodes excluded — so we accumulate it a single time here.
    accounted_delta += tier_a_churn_walk(
        root,
        prior,
        &registered_inodes,
        &mut next_dir_mtimes,
        &mut observations,
        &scan_id,
        now,
    );

    // ---- Tier B: re-stat the registry directly (no walk). ----------------
    let next_registry = tier_b_restat(
        prior,
        &mut observations,
        &mut accounted_delta,
        &scan_id,
        now,
        base,
    );

    // ---- df ADVISORY (signal only — never a trigger). --------------------
    let advisory = df_advisory(prior.last_df_free, now_df_free, accounted_delta);

    // Persist the observations under one batch lock (best-effort but propagate
    // a hard write error so the caller knows the tick didn't fully record).
    series_append_batch(base, &observations)?;

    let next_state = TickState {
        schema: TICK_STATE_SCHEMA,
        last_full_walk: prior.last_full_walk, // unchanged on an incremental tick
        dir_mtimes: next_dir_mtimes,
        registry: next_registry,
        last_df_free: now_df_free.unwrap_or(prior.last_df_free),
    };

    Ok(TickOutcome {
        observations,
        widened_to_full: false,
        advisory,
        next_state,
    })
}

/// Daily true-up: run the full `scan()`, emit `Source::Full` for every matched
/// entry, rebuild the registry + dir-mtime cache, reset `last_full_walk`.
fn full_true_up(
    base: &Path,
    root: &Path,
    rules: &[Rule],
    prior: &TickState,
    now: DateTime<Utc>,
    now_df_free: Option<u64>,
) -> Result<TickOutcome> {
    let result = scan(root, rules)?;
    let scan_id = if result.scan_id.is_empty() {
        format!("full-{}", now.timestamp_millis())
    } else {
        result.scan_id.clone()
    };

    let mut observations: Vec<Observation> = Vec::with_capacity(result.entries.len());
    for e in &result.entries {
        let key = ObsKey::for_entry(e.dev, e.ino, &e.path);
        observations.push(Observation::new(
            key,
            e.path.clone(),
            e.size_bytes,
            Source::Full,
            scan_id.clone(),
            now,
            e.ctime,
        ));
    }

    // Rebuild the registry: top-N by bytes AND everything >= 1 GiB.
    let next_registry = rebuild_registry(&result.entries, now);

    // Rebuild the dir-mtime cache from the full walk so the next incremental tick
    // has a fresh baseline. We re-walk dir mtimes here (cheap relative to the full
    // scan we just did) using the same follow_links/hidden settings.
    let next_dir_mtimes = build_dir_mtimes(root);

    series_append_batch(base, &observations)?;

    let next_state = TickState {
        schema: TICK_STATE_SCHEMA,
        last_full_walk: now, // reset the true-up clock
        dir_mtimes: next_dir_mtimes,
        registry: next_registry,
        last_df_free: now_df_free.unwrap_or(prior.last_df_free),
    };

    Ok(TickOutcome {
        observations,
        widened_to_full: true,
        // The true-up is ground truth; df divergence is moot, so no advisory.
        advisory: None,
        next_state,
    })
}

/// Tier A: walk `root`, but skip recursion into any directory whose mtime equals
/// the prior tick's cached mtime (reusing the cached subtree bytes). Changed
/// subtrees emit `Source::Incremental`.
///
/// We do our OWN recursion (not jwalk) so we can prune an unchanged subtree
/// before descending into it — jwalk's parallel iterator can't be pruned per
/// directory the way we need. `follow_links=false`, symlinks skipped, on-disk
/// `blocks*512` sizing, and the cloud-placeholder skip all mirror `scan()`.
///
/// Returns the whole-tree `accounted_delta` for Tier A, counted EXACTLY ONCE.
/// The Incremental OBSERVATIONS are still per-changed-dir (keyed and
/// de-duplicated downstream), but the DELTA is the single root-level subtraction
/// `(root_bytes_now − root_bytes_prior)` minus any registered inodes' delta —
/// NOT a per-ancestor sum. This kills the nested-dir double-count (finding 3) and
/// the Tier-A/Tier-B overlap for registered files (finding 4): a registered
/// inode's delta is owned solely by Tier B.
#[allow(clippy::too_many_arguments)]
fn tier_a_churn_walk(
    root: &Path,
    prior: &TickState,
    registered_inodes: &std::collections::HashSet<(u64, u64)>,
    next_dir_mtimes: &mut HashMap<PathBuf, (i64, u64)>,
    observations: &mut Vec<Observation>,
    scan_id: &str,
    now: DateTime<Utc>,
) -> i64 {
    // Per-inode prior bytes for registered entries — the reference Tier B uses for
    // its own delta. We subtract the SAME `(now − reg.bytes)` from Tier A so a
    // registered file in a re-walked subtree nets to zero in Tier A (Tier B owns
    // it). Keyed by (dev, ino).
    let reg_prior_bytes: HashMap<(u64, u64), u64> = prior
        .registry
        .iter()
        .map(|r| ((r.dev, r.ino), r.bytes))
        .collect();

    let root = root.to_path_buf();
    let dir_mtime = dir_mtime_secs(&root);
    let prior_for_root = prior.dir_mtimes.get(&root).copied();

    // Recurse, collecting the subtree byte total AND the net delta of registered
    // inodes encountered anywhere in the (walked) subtree.
    let mut registered_delta: i64 = 0;
    let bytes_now = walk_subtree(
        &root,
        dir_mtime,
        prior_for_root,
        prior,
        registered_inodes,
        &reg_prior_bytes,
        next_dir_mtimes,
        observations,
        &mut registered_delta,
        scan_id,
        now,
    );

    // The whole-tree delta, counted once: total subtree growth minus the part of
    // it attributable to registered inodes (which Tier B counts instead).
    let bytes_prior = prior_for_root.map(|(_, b)| b).unwrap_or(0);
    (bytes_now as i64 - bytes_prior as i64) - registered_delta
}

/// Recursively measure `dir`. If `dir`'s mtime matches the prior cache we reuse
/// the cached subtree bytes and DO NOT descend (the churn-free fast path).
/// Otherwise we descend, sum child bytes, emit an `Incremental` observation for
/// this changed directory, and refresh the cache.
///
/// Returns the subtree's true on-disk byte total (used for the dir-mtime cache
/// and the Incremental observation). Does NOT touch the global accounted_delta
/// per-frame — the single root-level subtraction in [`tier_a_churn_walk`] owns
/// that (finding 3). It DOES accumulate `registered_delta`: for every registered
/// inode (file) it encounters, `(current_bytes − reg.bytes)`, so the caller can
/// subtract that overlap out of Tier A (finding 4).
#[allow(clippy::too_many_arguments)]
fn walk_subtree(
    dir: &Path,
    dir_mtime: Option<i64>,
    prior_entry: Option<(i64, u64)>,
    prior: &TickState,
    registered_inodes: &std::collections::HashSet<(u64, u64)>,
    reg_prior_bytes: &HashMap<(u64, u64), u64>,
    next_dir_mtimes: &mut HashMap<PathBuf, (i64, u64)>,
    observations: &mut Vec<Observation>,
    registered_delta: &mut i64,
    scan_id: &str,
    now: DateTime<Utc>,
) -> u64 {
    // Fast path: directory mtime unchanged since last tick → no structural churn
    // here. Reuse the cached subtree bytes and skip the whole subtree.
    //
    // NOTE: skipped subtrees contribute 0 to the root delta automatically (their
    // cached bytes appear identically in `bytes_now` and `bytes_prior`), and we
    // do NOT descend, so any registered files inside are left entirely to Tier B
    // — exactly the single-counting we want.
    if let (Some(mtime), Some((prior_mtime, prior_bytes))) = (dir_mtime, prior_entry) {
        if mtime == prior_mtime {
            next_dir_mtimes.insert(dir.to_path_buf(), (prior_mtime, prior_bytes));
            return prior_bytes;
        }
    }

    // Changed (or first-seen) directory: descend and re-sum.
    let mut subtree_bytes: u64 = 0;
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => {
            // Unreadable dir — record what mtime we have and move on.
            if let Some(mt) = dir_mtime {
                next_dir_mtimes.insert(dir.to_path_buf(), (mt, 0));
            }
            return 0;
        }
    };

    for child in read.flatten() {
        let child_path = child.path();
        // `symlink_metadata` so we never follow a symlink (mirrors
        // follow_links=false) and a symlink is skipped entirely.
        let md = match std::fs::symlink_metadata(&child_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let ft = md.file_type();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            let child_mtime = mtime_secs_of(&md);
            let child_prior = prior.dir_mtimes.get(&child_path).copied();
            subtree_bytes += walk_subtree(
                &child_path,
                child_mtime,
                child_prior,
                prior,
                registered_inodes,
                reg_prior_bytes,
                next_dir_mtimes,
                observations,
                registered_delta,
                scan_id,
                now,
            );
        } else if ft.is_file() {
            let fbytes = file_on_disk_bytes(&md);
            subtree_bytes += fbytes;
            // If this file is a registered inode, record its delta vs the registry
            // so the caller can subtract it out of Tier A (Tier B owns it).
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let key = (md.dev(), md.ino());
                if registered_inodes.contains(&key) {
                    let prior_b = reg_prior_bytes.get(&key).copied().unwrap_or(0);
                    *registered_delta += fbytes as i64 - prior_b as i64;
                }
            }
        }
    }

    // Emit an Incremental observation for this changed directory subtree.
    let key = ObsKey::for_entry(dev_of(dir), ino_of(dir), dir);
    observations.push(Observation::new(
        key,
        dir.to_path_buf(),
        subtree_bytes,
        Source::Incremental,
        scan_id.to_string(),
        now,
        ctime_of(dir),
    ));

    if let Some(mt) = dir_mtime {
        next_dir_mtimes.insert(dir.to_path_buf(), (mt, subtree_bytes));
    } else {
        next_dir_mtimes.insert(dir.to_path_buf(), (0, subtree_bytes));
    }
    subtree_bytes
}

/// Tier B: re-stat every prior registry entry DIRECTLY by path (no walk), keyed
/// by `(dev, ino)`. Emit `Source::Restat` with the current on-disk size; emit a
/// tombstone for any entry that has vanished. Returns the next registry (carrying
/// forward the still-present entries with updated bytes/last_stat).
fn tier_b_restat(
    prior: &TickState,
    observations: &mut Vec<Observation>,
    accounted_delta: &mut i64,
    scan_id: &str,
    now: DateTime<Utc>,
    base: &Path,
) -> Vec<RegistryEntry> {
    let mut next_registry: Vec<RegistryEntry> = Vec::with_capacity(prior.registry.len());

    for reg in &prior.registry {
        match std::fs::symlink_metadata(&reg.path) {
            Ok(md) if md.file_type().is_file() || md.file_type().is_dir() => {
                let bytes = if md.file_type().is_file() {
                    file_on_disk_bytes(&md)
                } else {
                    // A registered directory: re-stat is just the entry's own
                    // metadata, so for dirs we keep the prior bytes (Tier A owns
                    // dir-subtree sizing). Restat is meaningful for files.
                    reg.bytes
                };
                // Continuity key is (dev, ino) only; ctime rides on the obs.
                let key = ObsKey::Inode {
                    dev: reg.dev,
                    ino: reg.ino,
                };
                let ctime = ctime_nanos(reg.ctime, reg.ctime_nsec);
                observations.push(Observation::new(
                    key,
                    reg.path.clone(),
                    bytes,
                    Source::Restat,
                    scan_id.to_string(),
                    now,
                    Some(ctime),
                ));
                *accounted_delta += bytes as i64 - reg.bytes as i64;

                next_registry.push(RegistryEntry {
                    dev: reg.dev,
                    ino: reg.ino,
                    ctime: reg.ctime,
                    ctime_nsec: reg.ctime_nsec,
                    path: reg.path.clone(),
                    bytes,
                    last_stat: now,
                });
            }
            _ => {
                // Vanished (or no longer a regular file/dir) → tombstone. The
                // continuity key is (dev, ino); the path is informational.
                let key = ObsKey::Inode {
                    dev: reg.dev,
                    ino: reg.ino,
                };
                let tomb = Observation {
                    v: crate::core::series::SERIES_SCHEMA,
                    ts: now,
                    key,
                    path: reg.path.clone(),
                    bytes: 0,
                    source: Source::Tombstone,
                    scan_id: scan_id.to_string(),
                    ctime: None,
                };
                observations.push(tomb);
                // The vanished entry is dropped from next_registry.
            }
        }
    }
    let _ = base;
    next_registry
}

/// Build the df advisory note. Compares the whole-volume free-space delta to the
/// bytes we actually accounted for this tick. A large UNEXPLAINED divergence is a
/// soft signal only — it NEVER widens a scan (the caller's `widened_to_full`
/// stays false regardless).
fn df_advisory(
    prior_df_free: u64,
    now_df_free: Option<u64>,
    accounted_delta: i64,
) -> Option<String> {
    let now_free = now_df_free?;
    if prior_df_free == 0 {
        // No prior df baseline — nothing to compare against this tick.
        return None;
    }
    // df free DROPPED by this many bytes (positive = disk filled up). Saturating
    // so a free-space INCREASE reads as a non-positive (no advisory) delta.
    let actual_delta: i64 = prior_df_free as i64 - now_free as i64;
    // `accounted_delta` is the net byte growth we explained via Incremental +
    // Restat. Divergence = what df saw minus what we explained.
    let divergence = actual_delta - accounted_delta;
    if divergence > ADVISORY_DIVERGENCE_BYTES as i64 {
        Some(format!(
            "advisory: whole-volume df dropped {} but the scan only accounted for {} \
             (unexplained {} > {} threshold). This is a burn-rate signal ONLY — it does \
             NOT widen the scan.",
            crate::output::format_bytes(actual_delta.max(0) as u64),
            format_signed_bytes(accounted_delta),
            crate::output::format_bytes(divergence.max(0) as u64),
            crate::output::format_bytes(ADVISORY_DIVERGENCE_BYTES),
        ))
    } else {
        None
    }
}

/// Rebuild the Tier-B registry from a full scan: keep the top-N largest entries
/// AND everything >= [`REGISTRY_MIN_BYTES`]. Only entries carrying full
/// `(dev, ino)` inode identity are registrable (Tier B re-stats by inode).
fn rebuild_registry(entries: &[ScannedEntry], now: DateTime<Utc>) -> Vec<RegistryEntry> {
    let mut candidates: Vec<&ScannedEntry> = entries
        .iter()
        .filter(|e| e.dev.is_some() && e.ino.is_some())
        .collect();
    // Largest first.
    candidates.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

    let mut out: Vec<RegistryEntry> = Vec::new();
    for (i, e) in candidates.iter().enumerate() {
        let big_enough = e.size_bytes >= REGISTRY_MIN_BYTES;
        let in_top_n = i < REGISTRY_TOP_N;
        if !big_enough && !in_top_n {
            break; // sorted desc: once below the floor AND past top-N, we're done
        }
        let (ctime_sec, ctime_nsec) = split_ctime_nanos(e.ctime.unwrap_or(0));
        out.push(RegistryEntry {
            dev: e.dev.unwrap(),
            ino: e.ino.unwrap(),
            ctime: ctime_sec,
            ctime_nsec,
            path: e.path.clone(),
            bytes: e.size_bytes,
            last_stat: now,
        });
    }
    out
}

/// Walk `root` collecting every directory's mtime + subtree on-disk bytes, used
/// to rebuild the dir-mtime cache after a full true-up. Mirrors `scan()` walk
/// settings (no hidden skip, follow_links=false, blocks*512, cloud skip).
fn build_dir_mtimes(root: &Path) -> HashMap<PathBuf, (i64, u64)> {
    // Single pass: accumulate each file's on-disk bytes into all ancestor dirs,
    // and record each directory's mtime.
    let mut dir_bytes: HashMap<PathBuf, u64> = HashMap::new();
    let mut dir_mtime: HashMap<PathBuf, i64> = HashMap::new();

    for entry in WalkDir::new(root)
        .skip_hidden(false)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        let path = entry.path();
        let md = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.is_dir() {
            dir_mtime
                .entry(path.to_path_buf())
                .or_insert_with(|| mtime_secs_of(&md).unwrap_or(0));
            dir_bytes.entry(path.to_path_buf()).or_insert(0);
        } else if md.is_file() {
            let size = file_on_disk_bytes(&md);
            if size > 0 {
                let mut p = path.parent();
                while let Some(parent) = p {
                    *dir_bytes.entry(parent.to_path_buf()).or_insert(0) += size;
                    if parent == root {
                        break;
                    }
                    p = parent.parent();
                }
            }
        }
    }

    let mut out: HashMap<PathBuf, (i64, u64)> = HashMap::new();
    for (path, mtime) in dir_mtime {
        let bytes = dir_bytes.get(&path).copied().unwrap_or(0);
        out.insert(path, (mtime, bytes));
    }
    out
}

// --- small fs helpers (mirror scan()'s sizing / cloud-placeholder rules) ----

/// On-disk bytes for a file: `blocks*512` on unix (matches `scan`), logical len
/// elsewhere. Cloud-placeholder files (len > 4096 but 0 blocks) report 0.
fn file_on_disk_bytes(md: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if md.len() > 4096 && md.blocks() == 0 {
            return 0; // iCloud/Dropbox online-only placeholder — no disk used
        }
        md.blocks() * 512
    }
    #[cfg(not(unix))]
    {
        md.len()
    }
}

fn mtime_secs_of(md: &std::fs::Metadata) -> Option<i64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(md.mtime())
    }
    #[cfg(not(unix))]
    {
        md.modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
    }
}

fn dir_mtime_secs(dir: &Path) -> Option<i64> {
    std::fs::symlink_metadata(dir)
        .ok()
        .and_then(|md| mtime_secs_of(&md))
}

fn dev_of(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).ok().map(|m| m.dev())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn ino_of(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).ok().map(|m| m.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn ctime_of(path: &Path) -> Option<i64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path)
            .ok()
            .map(|m| ctime_nanos(m.ctime(), m.ctime_nsec()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Split a nanos-since-epoch ctime back into `(whole_secs, nsec)` for storage in
/// a [`RegistryEntry`]. Inverse of [`ctime_nanos`].
fn split_ctime_nanos(nanos: i64) -> (i64, i64) {
    (
        nanos.div_euclid(1_000_000_000),
        nanos.rem_euclid(1_000_000_000),
    )
}

/// Format a signed byte delta for the advisory message (e.g. `+1.2 GB` / `-300 MB`).
fn format_signed_bytes(delta: i64) -> String {
    if delta < 0 {
        format!("-{}", crate::output::format_bytes(delta.unsigned_abs()))
    } else {
        format!("+{}", crate::output::format_bytes(delta as u64))
    }
}

/// Whole-volume free bytes for the volume containing `path`. Thin wrapper over
/// the existing `history::free_bytes` df helper.
fn history_free_bytes(path: &Path) -> Option<u64> {
    crate::core::history::free_bytes(path)
}

/// Append a batch of observations to the series store under one lock. Base-dir
/// parameterized and honored UNCONDITIONALLY (in every build), so a caller that
/// passes a temp scratch base — most importantly `selfcheck --measurement`, which
/// drives `tick_in_base` against a `/tmp` scratch tree — writes ONLY there and
/// never pollutes the real `~/.diskspace/series.jsonl`. Production callers reach
/// this via `tick` -> `tick_in(&profile::data_dir(), ..)`, so they still target
/// the real data dir; routing through `append_batch_in_base` (non-test-gated)
/// keeps prod behavior identical while finally respecting `selfcheck`'s base.
fn series_append_batch(base: &Path, observations: &[Observation]) -> Result<()> {
    if observations.is_empty() {
        return Ok(());
    }
    crate::core::series::append_batch_in_base(base, observations)
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

/// Fold whole-second `st_ctime` and `st_ctime_nsec` into a single nanos-since-epoch
/// `i64`, preserving sub-second resolution so inode reuse inside one wall-clock
/// second is disambiguated (see the call site for why this matters).
///
/// `i64` nanos covers years ~1678–2262 — far beyond any real filesystem ctime —
/// so the multiply can't realistically overflow. We saturate defensively anyway
/// so an absurd value can never panic the scanner.
#[cfg(unix)]
fn ctime_nanos(ctime_sec: i64, ctime_nsec: i64) -> i64 {
    ctime_sec
        .saturating_mul(1_000_000_000)
        .saturating_add(ctime_nsec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::candidate::ScannedEntry;
    use crate::core::series::SERIES_SCHEMA;

    /// `ctime_nanos` folds whole-second ctime + ctime_nsec into nanos-since-epoch,
    /// preserving sub-second resolution (finding-1). Two ctimes in the SAME
    /// second but different nanos must NOT collapse to the same value.
    #[cfg(unix)]
    #[test]
    fn ctime_nanos_preserves_subsecond_resolution() {
        let a = super::ctime_nanos(1_700_000_000, 0);
        let b = super::ctime_nanos(1_700_000_000, 500_000_000); // same second
        assert_eq!(a, 1_700_000_000_000_000_000);
        assert_eq!(b, 1_700_000_000_500_000_000);
        assert_ne!(
            a, b,
            "same-second ctimes with different nanos stay distinct (no truncation)"
        );
        // Saturating arithmetic: an absurd ctime can never panic the scanner.
        assert_eq!(super::ctime_nanos(i64::MAX, i64::MAX), i64::MAX);
    }

    /// A `ScannedEntry` carrying the new dev/ino/ctime fields round-trips
    /// through JSON intact.
    #[test]
    fn scanned_entry_with_new_fields_roundtrips() {
        let entry = ScannedEntry {
            path: PathBuf::from("/tmp/thing"),
            size_bytes: 4096,
            category: Category::DevArtifact,
            modified: None,
            accessed: None,
            dev: Some(16777220),
            ino: Some(42),
            ctime: Some(1_700_000_000),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ScannedEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.dev, Some(16777220));
        assert_eq!(back.ino, Some(42));
        assert_eq!(back.ctime, Some(1_700_000_000));
        assert_eq!(back.path, PathBuf::from("/tmp/thing"));
        assert_eq!(back.size_bytes, 4096);
    }

    /// A legacy `ScannedEntry` JSON blob WITHOUT dev/ino/ctime still
    /// deserializes — back-compat for existing scan.json.
    #[test]
    fn legacy_scanned_entry_without_new_fields_deserializes() {
        let legacy = r#"{
            "path": "/old/path",
            "size_bytes": 123,
            "category": "app_cache",
            "modified": null,
            "accessed": null
        }"#;
        let entry: ScannedEntry = serde_json::from_str(legacy).unwrap();
        assert_eq!(entry.path, PathBuf::from("/old/path"));
        assert_eq!(entry.size_bytes, 123);
        assert_eq!(entry.dev, None);
        assert_eq!(entry.ino, None);
        assert_eq!(entry.ctime, None);
    }

    /// A `ScanResult` carrying schema + scan_id round-trips through JSON.
    #[test]
    fn scan_result_with_schema_and_id_roundtrips() {
        let result = ScanResult {
            scanned_at: Utc::now(),
            root: PathBuf::from("/scan/root"),
            entries: Vec::new(),
            total_bytes: 9999,
            cloud_placeholder_bytes: 0,
            category_totals: HashMap::new(),
            schema: SERIES_SCHEMA,
            scan_id: "1700000000-9999".to_string(),
            metrics: None,
            largest_dirs: Vec::new(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema, SERIES_SCHEMA);
        assert_eq!(back.scan_id, "1700000000-9999");
        assert_eq!(back.total_bytes, 9999);
    }

    /// A legacy `ScanResult` JSON blob WITHOUT schema/scan_id still
    /// deserializes — back-compat for existing scan.json. Missing fields
    /// default to `0` / empty string.
    #[test]
    fn legacy_scan_result_without_schema_or_id_deserializes() {
        let legacy = r#"{
            "scanned_at": "2026-06-01T00:00:00Z",
            "root": "/scan/root",
            "entries": [],
            "total_bytes": 500
        }"#;
        let result: ScanResult = serde_json::from_str(legacy).unwrap();
        assert_eq!(result.total_bytes, 500);
        assert_eq!(result.schema, 0, "missing schema defaults to 0");
        assert_eq!(result.scan_id, "", "missing scan_id defaults to empty");
        assert!(
            result.largest_dirs.is_empty(),
            "missing largest_dirs defaults to an empty Vec (back-compat)"
        );
    }

    /// `top_largest_dirs` keeps only the N biggest directories, sorted by
    /// `total_bytes` descending, dropping zero-byte dirs and capping at N. This is
    /// the pure selection logic `scan()` applies to its `dir_sizes` map.
    #[test]
    fn top_largest_dirs_sorts_desc_and_caps_at_n() {
        let mut dir_sizes: HashMap<PathBuf, u64> = HashMap::new();
        dir_sizes.insert(PathBuf::from("/a"), 100);
        dir_sizes.insert(PathBuf::from("/b"), 300);
        dir_sizes.insert(PathBuf::from("/c"), 200);
        dir_sizes.insert(PathBuf::from("/d"), 50);
        dir_sizes.insert(PathBuf::from("/zero"), 0); // dropped (no bytes)

        let top = top_largest_dirs(&dir_sizes, 2);
        assert_eq!(top.len(), 2, "capped at N=2");
        assert_eq!(top[0].path, PathBuf::from("/b"));
        assert_eq!(top[0].total_bytes, 300);
        assert_eq!(top[1].path, PathBuf::from("/c"));
        assert_eq!(top[1].total_bytes, 200);
        // Descending order holds.
        assert!(top[0].total_bytes >= top[1].total_bytes);

        // With N >= count, the zero-byte dir is still excluded.
        let all = top_largest_dirs(&dir_sizes, 100);
        assert_eq!(all.len(), 4, "zero-byte dir excluded, rest kept");
        assert!(
            all.iter().all(|d| d.total_bytes > 0),
            "no zero-byte dirs persisted"
        );
    }

    /// Scanning a real tempdir tree persists `largest_dirs` with the correct TOTAL
    /// on-disk sizes (own files PLUS every descendant), sorted descending. The
    /// totals are TOTAL sizes, NOT just rule-matched bytes — there is no rule here
    /// yet the directories still appear, which is exactly what `hunt` needs to find
    /// unruled bytes.
    #[cfg(unix)]
    #[test]
    fn scan_persists_largest_dirs_with_total_sizes() {
        // tree/
        //   big/       (one large file)
        //     huge.bin
        //   small/     (one small file)
        //     tiny.bin
        let mut root = std::env::temp_dir();
        root.push(format!(
            "diskspace-largest-dirs-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let big = root.join("big");
        let small = root.join("small");
        std::fs::create_dir_all(&big).unwrap();
        std::fs::create_dir_all(&small).unwrap();
        write_bytes(&big.join("huge.bin"), 64 * 1024);
        write_bytes(&small.join("tiny.bin"), 4 * 1024);

        // No rules at all: largest_dirs must STILL be populated (it tracks TOTAL
        // sizes, independent of rule matching).
        let result = scan(&root, &[]).unwrap();
        assert!(result.entries.is_empty(), "no rules → no matched entries");

        // Sorted descending by total_bytes.
        for w in result.largest_dirs.windows(2) {
            assert!(
                w[0].total_bytes >= w[1].total_bytes,
                "largest_dirs sorted by total_bytes descending"
            );
        }

        let find = |p: &Path| {
            result
                .largest_dirs
                .iter()
                .find(|d| d.path == p)
                .map(|d| d.total_bytes)
        };
        let big_total = find(&big).expect("big/ present in largest_dirs");
        let small_total = find(&small).expect("small/ present in largest_dirs");
        let root_total = find(&root).expect("root present in largest_dirs");

        // big/ holds the larger file, so its total exceeds small/.
        assert!(big_total > small_total, "big/ totals more than small/");
        // The root aggregates ALL descendants, so it's >= big/ + small/.
        assert!(
            root_total >= big_total + small_total,
            "root total includes every descendant"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// On unix, scanning a tempdir with a matching rule populates dev/ino on the
    /// produced entry (already-fetched metadata, no extra syscalls).
    #[cfg(unix)]
    #[test]
    fn scan_populates_dev_ino_on_unix() {
        use std::io::Write;

        // Throwaway dir under the OS temp dir, cleaned up at the end.
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "diskspace-scanner-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Create a file we can target with a glob rule.
        let file_path = dir.join("artifact.bin");
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(b"some bytes to allocate at least one block")
            .unwrap();
        f.flush().unwrap();
        drop(f);

        // A rule whose absolute glob matches every file in the tempdir.
        let rule = Rule {
            id: "test-artifact".to_string(),
            category: "dev-artifact".to_string(),
            path_pattern: format!("{}/*", dir.display()),
            domain: None,
            base_confidence: 0.9,
            reason: "test".to_string(),
            exclude_if_recent_access_days: None,
            exclude_if_recent_modified_days: None,
            consequences: None,
            reference_url: None,
        };

        let result = scan(&dir, &[rule]).unwrap();

        let entry = result
            .entries
            .iter()
            .find(|e| e.path == file_path)
            .expect("scanned the artifact file");
        assert!(entry.dev.is_some(), "dev populated on unix");
        assert!(entry.ino.is_some(), "ino populated on unix");
        assert!(entry.ctime.is_some(), "ctime populated on unix");
        // ctime is full nanos-since-epoch, NOT whole seconds: a 2026 file has a
        // ctime far larger than the whole-second value (~1.7e9), so it must be
        // > 1e18 (≈ 1.7e9 * 1e9). This guards finding-1: whole-second truncation
        // would defeat inode-reuse disambiguation within one wall-clock second.
        assert!(
            entry.ctime.unwrap() > 1_000_000_000_000_000_000,
            "ctime carries full nanosecond resolution, not whole seconds"
        );

        // ScanResult carries the series schema + a non-empty scan_id.
        assert_eq!(result.schema, crate::core::series::SERIES_SCHEMA);
        assert!(!result.scan_id.is_empty(), "scan_id is generated");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // =======================================================================
    // Incremental scanner (`tick`) tests — the correctness proofs.
    //
    // Every test targets a throwaway tempdir for BOTH the scanned tree and the
    // series base dir, so the real `~/.diskspace` is never touched. We inject a
    // fixed `now` via `tick_in` so the daily-true-up clock is deterministic.
    // =======================================================================

    /// A throwaway dir under the OS temp dir, cleaned up on drop. Holds both the
    /// series base (`base`) and the scanned tree (`root`).
    struct TickTmp {
        root: PathBuf,
    }
    impl TickTmp {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "diskspace-tick-test-{}-{}-{}",
                tag,
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self { root: p }
        }
        /// The series/state base dir (a sibling subdir so it isn't itself scanned).
        fn base(&self) -> PathBuf {
            let b = self.root.join(".dsbase");
            std::fs::create_dir_all(&b).unwrap();
            b
        }
        /// The scanned tree root (a subdir, so `.dsbase` is outside it).
        fn tree(&self) -> PathBuf {
            let t = self.root.join("tree");
            std::fs::create_dir_all(&t).unwrap();
            t
        }
    }
    impl Drop for TickTmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    fn stat_ino_dev_ctime(path: &Path) -> (u64, u64, i64, i64) {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::symlink_metadata(path).unwrap();
        (md.dev(), md.ino(), md.ctime(), md.ctime_nsec())
    }

    #[cfg(unix)]
    fn on_disk_bytes(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::symlink_metadata(path).unwrap();
        md.blocks() * 512
    }

    fn write_bytes(path: &Path, n: usize) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(&vec![b'x'; n]).unwrap();
        f.flush().unwrap();
    }

    /// Tier B catches in-place file GROWTH that Tier A misses. We register a file,
    /// then grow it WITHOUT touching the parent directory's mtime (an in-place
    /// append doesn't bump the parent's mtime). We seed `dir_mtimes` with the
    /// parent's CURRENT mtime so Tier A's fast path fires (sees "no churn") and
    /// skips the subtree — proving the growth is invisible to A but caught by B's
    /// direct re-stat.
    #[cfg(unix)]
    #[test]
    fn in_place_growth_missed_by_tier_a_caught_by_tier_b() {
        let tmp = TickTmp::new("inplace");
        let base = tmp.base();
        let tree = tmp.tree();

        // Create a registered file, ~8 KiB so it occupies real blocks.
        let f = tree.join("big.bin");
        write_bytes(&f, 8 * 1024);
        let (dev, ino, ctime, ctime_nsec) = stat_ino_dev_ctime(&f);
        let bytes0 = on_disk_bytes(&f);

        // Seed prior state: registry holds the file at its initial size, and the
        // dir-mtime cache holds the tree's CURRENT mtime (so Tier A sees no churn
        // and skips the subtree). last_full_walk = now so NO daily true-up fires.
        let now = Utc::now();
        let tree_mtime = dir_mtime_secs(&tree).unwrap();
        let mut dir_mtimes = HashMap::new();
        // Cache the tree at its live mtime with the current subtree bytes, so
        // Tier A's fast path reuses it and never descends into the subtree.
        dir_mtimes.insert(tree.clone(), (tree_mtime, bytes0));
        let prior = TickState {
            schema: TICK_STATE_SCHEMA,
            last_full_walk: now, // within 24h → no true-up
            dir_mtimes,
            registry: vec![RegistryEntry {
                dev,
                ino,
                ctime,
                ctime_nsec,
                path: f.clone(),
                bytes: bytes0,
                last_stat: now,
            }],
            last_df_free: 0,
        };

        // Grow the file in place: append ~120 KiB. This does NOT change the parent
        // directory's mtime (no dir entry was added/removed), so Tier A is blind.
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut g = std::fs::OpenOptions::new()
                .append(true)
                .mode(0o644)
                .open(&f)
                .unwrap();
            g.write_all(&vec![b'y'; 120 * 1024]).unwrap();
            g.flush().unwrap();
        }
        let bytes1 = on_disk_bytes(&f);
        assert!(bytes1 > bytes0, "file actually grew on disk");

        let out = tick_in(&base, &tree, &[], &prior, now).unwrap();
        assert!(!out.widened_to_full, "no full walk within 24h");

        // Tier A must NOT have emitted an Incremental observation for the (still
        // mtime-unchanged) tree directory — the growth is invisible to it.
        let incr_for_tree = out
            .observations
            .iter()
            .any(|o| o.source == Source::Incremental && o.path == tree);
        assert!(
            !incr_for_tree,
            "Tier A is blind to in-place growth (parent mtime unchanged)"
        );

        // Tier B MUST have emitted a Restat for the grown file at its new size.
        let restat = out
            .observations
            .iter()
            .find(|o| o.source == Source::Restat && o.path == f)
            .expect("Tier B re-stat caught the grown file");
        assert_eq!(
            restat.bytes, bytes1,
            "Restat reports the grown on-disk size"
        );
        match &restat.key {
            ObsKey::Inode { dev: d, ino: i } => assert_eq!((*d, *i), (dev, ino)),
            other => panic!("expected inode key, got {other:?}"),
        }

        // And it round-trips through the series store at this base.
        let persisted = crate::core::series::read_all_in_pub(&base).unwrap();
        assert!(persisted
            .iter()
            .any(|o| o.source == Source::Restat && o.bytes == bytes1));
    }

    /// Tier A re-walks a subtree whose directory mtime changed (a new file was
    /// added, bumping the parent's mtime), emitting an Incremental observation.
    #[cfg(unix)]
    #[test]
    fn structural_churn_triggers_tier_a_incremental() {
        let tmp = TickTmp::new("churn");
        let base = tmp.base();
        let tree = tmp.tree();

        // Initial content: one file. Snapshot the dir's mtime+bytes for the cache.
        write_bytes(&tree.join("a.bin"), 4096);
        let mtime_before = dir_mtime_secs(&tree).unwrap();
        let bytes_before = {
            // subtree bytes = the one file
            on_disk_bytes(&tree.join("a.bin"))
        };

        let now = Utc::now();
        // Seed the cache with the tree's PRE-churn mtime. We deliberately store a
        // stale (pre-churn) mtime so that, regardless of timer granularity, the
        // post-churn live mtime differs and Tier A is FORCED to re-walk. We use
        // (mtime_before - 100) to guarantee inequality even within one second.
        let mut dir_mtimes = HashMap::new();
        dir_mtimes.insert(tree.clone(), (mtime_before - 100, bytes_before));
        let prior = TickState {
            schema: TICK_STATE_SCHEMA,
            last_full_walk: now,
            dir_mtimes,
            registry: Vec::new(),
            last_df_free: 0,
        };

        // Structural churn: add a NEW file. This bumps the tree dir's mtime.
        write_bytes(&tree.join("b.bin"), 60 * 1024);

        let out = tick_in(&base, &tree, &[], &prior, now).unwrap();
        assert!(!out.widened_to_full);

        let incr = out
            .observations
            .iter()
            .find(|o| o.source == Source::Incremental && o.path == tree)
            .expect("Tier A re-walked the churned subtree");
        // The subtree now sums BOTH files' on-disk bytes.
        let expected = on_disk_bytes(&tree.join("a.bin")) + on_disk_bytes(&tree.join("b.bin"));
        assert_eq!(
            incr.bytes, expected,
            "Incremental reports re-summed subtree"
        );
        assert!(
            incr.bytes > bytes_before,
            "subtree grew because of the new file"
        );
    }

    /// A registry entry whose file has vanished emits a Tombstone, and the entry
    /// is dropped from the next registry.
    #[cfg(unix)]
    #[test]
    fn vanished_registry_entry_emits_tombstone() {
        let tmp = TickTmp::new("vanish");
        let base = tmp.base();
        let tree = tmp.tree();

        let f = tree.join("doomed.bin");
        write_bytes(&f, 16 * 1024);
        let (dev, ino, ctime, ctime_nsec) = stat_ino_dev_ctime(&f);
        let bytes0 = on_disk_bytes(&f);

        let now = Utc::now();
        // Cache the tree as unchanged so Tier A is a no-op; the action is all in B.
        let mut dir_mtimes = HashMap::new();
        dir_mtimes.insert(tree.clone(), (dir_mtime_secs(&tree).unwrap(), bytes0));
        let prior = TickState {
            schema: TICK_STATE_SCHEMA,
            last_full_walk: now,
            dir_mtimes,
            registry: vec![RegistryEntry {
                dev,
                ino,
                ctime,
                ctime_nsec,
                path: f.clone(),
                bytes: bytes0,
                last_stat: now,
            }],
            last_df_free: 0,
        };

        // Delete the registered file.
        std::fs::remove_file(&f).unwrap();

        let out = tick_in(&base, &tree, &[], &prior, now).unwrap();

        let tomb = out
            .observations
            .iter()
            .find(|o| o.source == Source::Tombstone && o.path == f)
            .expect("vanished registry entry emits a tombstone");
        assert_eq!(tomb.bytes, 0, "tombstone carries zero bytes");
        match &tomb.key {
            ObsKey::Inode { dev: d, ino: i } => assert_eq!((*d, *i), (dev, ino)),
            other => panic!("tombstone keyed by inode, got {other:?}"),
        }
        assert!(
            out.next_state.registry.is_empty(),
            "vanished entry dropped from the next registry"
        );
    }

    /// Daily true-up: when `last_full_walk` is > 24h ago the tick performs a FULL
    /// walk, emits `Source::Full` observations, rebuilds the registry, and resets
    /// `last_full_walk` to `now`. Within 24h it does NOT.
    #[cfg(unix)]
    #[test]
    fn daily_true_up_runs_full_walk_and_resets_clock() {
        let tmp = TickTmp::new("trueup");
        let base = tmp.base();
        let tree = tmp.tree();

        // A file matched by a rule so `scan()` keeps it (and we get a Full obs).
        let f = tree.join("artifact.bin");
        write_bytes(&f, 32 * 1024);
        let rule = Rule {
            id: "t".into(),
            category: "dev-artifact".into(),
            path_pattern: format!("{}/*", tree.display()),
            domain: None,
            base_confidence: 0.9,
            reason: "test".into(),
            exclude_if_recent_access_days: None,
            exclude_if_recent_modified_days: None,
            consequences: None,
            reference_url: None,
        };

        let now = Utc::now();

        // -- Case 1: WITHIN 24h → no true-up. --------------------------------
        let recent = TickState {
            schema: TICK_STATE_SCHEMA,
            last_full_walk: now - Duration::hours(1),
            dir_mtimes: HashMap::new(),
            registry: Vec::new(),
            last_df_free: 0,
        };
        let out_recent = tick_in(&base, &tree, std::slice::from_ref(&rule), &recent, now).unwrap();
        assert!(
            !out_recent.widened_to_full,
            "within 24h must NOT widen to a full walk"
        );
        assert!(
            !out_recent
                .observations
                .iter()
                .any(|o| o.source == Source::Full),
            "no Full observations within 24h"
        );
        // Clock unchanged.
        assert_eq!(out_recent.next_state.last_full_walk, recent.last_full_walk);

        // -- Case 2: > 24h ago → true-up fires. ------------------------------
        let stale = TickState {
            schema: TICK_STATE_SCHEMA,
            last_full_walk: now - Duration::hours(25),
            dir_mtimes: HashMap::new(),
            registry: Vec::new(),
            last_df_free: 0,
        };
        let out = tick_in(&base, &tree, &[rule], &stale, now).unwrap();
        assert!(out.widened_to_full, "> 24h triggers a full walk");
        let full = out
            .observations
            .iter()
            .find(|o| o.source == Source::Full && o.path == f)
            .expect("full walk emits a Full observation for the matched file");
        assert!(full.bytes > 0);
        // Registry rebuilt from the full walk (the matched file is registrable).
        assert!(
            out.next_state.registry.iter().any(|r| r.path == f),
            "true-up rebuilt the registry from the full scan"
        );
        // Clock reset to `now`.
        assert_eq!(
            out.next_state.last_full_walk, now,
            "true-up resets last_full_walk to now"
        );
    }

    /// df advisory: when the whole-volume df drop vastly exceeds the bytes we
    /// accounted for, `advisory` is Some(..) — but `widened_to_full` stays FALSE.
    /// df NEVER widens a scan.
    #[cfg(unix)]
    #[test]
    fn df_divergence_sets_advisory_but_never_widens() {
        let tmp = TickTmp::new("dfadvisory");
        let base = tmp.base();
        let tree = tmp.tree();

        // A small, unchanged tree → near-zero accounted delta.
        write_bytes(&tree.join("a.bin"), 4096);
        let now = Utc::now();
        let mut dir_mtimes = HashMap::new();
        dir_mtimes.insert(
            tree.clone(),
            (
                dir_mtime_secs(&tree).unwrap(),
                on_disk_bytes(&tree.join("a.bin")),
            ),
        );

        // Seed last_df_free far ABOVE the real current free so the df helper reads
        // a current value much smaller than prior → a huge apparent "drop" with no
        // matching accounted bytes. We add 8 GiB to whatever the live free is.
        let live_free = crate::core::history::free_bytes(&tree).unwrap_or(0);
        let prior = TickState {
            schema: TICK_STATE_SCHEMA,
            last_full_walk: now, // within 24h → incremental path (where df advisory lives)
            dir_mtimes,
            registry: Vec::new(),
            last_df_free: live_free + 8 * 1024 * 1024 * 1024, // 8 GiB higher
        };

        let out = tick_in(&base, &tree, &[], &prior, now).unwrap();
        assert!(
            out.advisory.is_some(),
            "a large unexplained df drop sets the advisory note"
        );
        assert!(
            !out.widened_to_full,
            "df divergence must NEVER widen the scan to a full walk"
        );
        // The advisory text is explicit that it does not widen.
        assert!(out.advisory.unwrap().to_lowercase().contains("does"));
    }

    /// TickState round-trips through the atomic save/load (temp + rename).
    #[test]
    fn tick_state_round_trips_atomically() {
        let tmp = TickTmp::new("roundtrip");
        let base = tmp.base();

        let now = Utc::now();
        let mut dir_mtimes = HashMap::new();
        dir_mtimes.insert(PathBuf::from("/tree/sub"), (1_700_000_000i64, 4096u64));
        let state = TickState {
            schema: TICK_STATE_SCHEMA,
            last_full_walk: now,
            dir_mtimes,
            registry: vec![RegistryEntry {
                dev: 16777220,
                ino: 99,
                ctime: 1_700_000_000,
                ctime_nsec: 123,
                path: PathBuf::from("/tree/big.bin"),
                bytes: 1234567,
                last_stat: now,
            }],
            last_df_free: 9_000_000_000,
        };

        save_tick_state_in(&base, &state).unwrap();
        // The temp file must not linger as the canonical path.
        assert!(tick_state_path_in(&base).exists());
        assert!(!tick_state_path_in(&base)
            .with_extension("json.tmp")
            .exists());

        let back = load_tick_state_in(&base);
        assert_eq!(back.schema, state.schema);
        assert_eq!(back.last_full_walk, state.last_full_walk);
        assert_eq!(back.last_df_free, state.last_df_free);
        assert_eq!(back.dir_mtimes, state.dir_mtimes);
        assert_eq!(back.registry.len(), 1);
        assert_eq!(back.registry[0].dev, 16777220);
        assert_eq!(back.registry[0].ino, 99);
        assert_eq!(back.registry[0].bytes, 1234567);
        assert_eq!(back.registry[0].path, PathBuf::from("/tree/big.bin"));

        // A missing file loads as default (which is "due for a full walk").
        let fresh = load_tick_state_in(&tmp.root.join("nonexistent-base"));
        assert_eq!(fresh.schema, TICK_STATE_SCHEMA);
        assert!(fresh.registry.is_empty());
        assert!(fresh.dir_mtimes.is_empty());
    }

    // -----------------------------------------------------------------------
    // Finding 3: a single change nested under multiple changed ancestor dirs
    // must be counted in `accounted_delta` EXACTLY ONCE, not once per ancestor.
    // We call `tier_a_churn_walk` directly so we observe its returned delta with
    // no df noise. A fresh (no-prior-cache) walk's delta must equal the tree's
    // true total on-disk bytes — never a multiple of it.
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn nested_changed_dirs_count_delta_once() {
        let tmp = TickTmp::new("nested");
        let tree = tmp.tree();

        // Build a 3-level nest with one file at the bottom: tree/a/b/file.bin.
        let a = tree.join("a");
        let b = a.join("b");
        std::fs::create_dir_all(&b).unwrap();
        let file = b.join("file.bin");
        write_bytes(&file, 80 * 1024);
        let file_bytes = on_disk_bytes(&file);
        assert!(file_bytes > 0);

        let now = Utc::now();
        // Empty prior cache + empty registry → every dir is "first-seen / changed"
        // (prior_bytes = 0), so all three ancestors (tree, a, b) are walked and
        // each emits an Incremental. The OLD code added (subtree - prior) at EACH
        // of the three frames → file_bytes counted ~3×. The fixed code returns the
        // single root-level delta = file_bytes.
        let prior = TickState {
            schema: TICK_STATE_SCHEMA,
            last_full_walk: now,
            dir_mtimes: HashMap::new(),
            registry: Vec::new(),
            last_df_free: 0,
        };
        let registered: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
        let mut next_dir_mtimes = prior.dir_mtimes.clone();
        let mut obs = Vec::new();
        let delta = tier_a_churn_walk(
            &tree,
            &prior,
            &registered,
            &mut next_dir_mtimes,
            &mut obs,
            "scan-test",
            now,
        );

        // All three changed dirs emitted an Incremental observation (the per-dir
        // observations are intentionally retained — only the delta is de-duped).
        let incr_dirs = obs
            .iter()
            .filter(|o| o.source == Source::Incremental)
            .count();
        assert!(
            incr_dirs >= 3,
            "tree, a, and b are all changed dirs → >= 3 Incremental observations, got {incr_dirs}"
        );

        // The crux: the delta is the file's bytes counted ONCE, not ~3× (which is
        // what the nested-ancestor double-count produced).
        assert_eq!(
            delta, file_bytes as i64,
            "a single nested change is accounted exactly once across all changed ancestors"
        );
    }

    // -----------------------------------------------------------------------
    // Finding 4: a registered file living inside a Tier-A re-walked subtree must
    // be counted ONCE (by Tier B's Restat), not also by Tier A's subtree delta.
    // We grow a registered file AND bump its parent dir's mtime (so Tier A
    // re-walks it). Tier A's returned delta must EXCLUDE the registered file's
    // growth; Tier B then owns it. End to end through `tick_in`, the accounted
    // delta (observed via the df advisory denominator) counts the growth once.
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn registered_file_in_rewalked_subtree_excluded_from_tier_a_delta() {
        let tmp = TickTmp::new("regoverlap");
        let tree = tmp.tree();

        // A registered file inside the tree.
        let f = tree.join("reg.bin");
        write_bytes(&f, 8 * 1024);
        let (dev, ino, ctime, ctime_nsec) = stat_ino_dev_ctime(&f);
        let bytes0 = on_disk_bytes(&f);

        let now = Utc::now();
        // Prior cache: tree at a STALE mtime so Tier A is forced to re-walk it
        // (the registered file's subtree is NOT skipped). Registry holds the file
        // at its initial size.
        let stale_mtime = dir_mtime_secs(&tree).unwrap() - 100;
        let mut dir_mtimes = HashMap::new();
        dir_mtimes.insert(tree.clone(), (stale_mtime, bytes0));
        let prior = TickState {
            schema: TICK_STATE_SCHEMA,
            last_full_walk: now,
            dir_mtimes,
            registry: vec![RegistryEntry {
                dev,
                ino,
                ctime,
                ctime_nsec,
                path: f.clone(),
                bytes: bytes0,
                last_stat: now,
            }],
            last_df_free: 0,
        };

        // Grow the registered file in place.
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut g = std::fs::OpenOptions::new()
                .append(true)
                .mode(0o644)
                .open(&f)
                .unwrap();
            g.write_all(&vec![b'y'; 200 * 1024]).unwrap();
            g.flush().unwrap();
        }
        let bytes1 = on_disk_bytes(&f);
        assert!(bytes1 > bytes0, "registered file grew on disk");

        // --- Tier A directly: its delta must EXCLUDE the registered file. -----
        let registered: std::collections::HashSet<(u64, u64)> =
            prior.registry.iter().map(|r| (r.dev, r.ino)).collect();
        let mut next_dir_mtimes = prior.dir_mtimes.clone();
        let mut obs_a = Vec::new();
        let tier_a_delta = tier_a_churn_walk(
            &tree,
            &prior,
            &registered,
            &mut next_dir_mtimes,
            &mut obs_a,
            "scan-test",
            now,
        );
        assert_eq!(
            tier_a_delta, 0,
            "Tier A delta excludes the registered inode (Tier B owns it) → net zero \
             when the only change is the registered file's in-place growth"
        );

        // --- Full tick: Tier B owns the delta exactly once. -------------------
        let base = tmp.base();
        let out = tick_in(&base, &tree, &[], &prior, now).unwrap();
        // Tier B emitted the Restat at the grown size.
        let restat = out
            .observations
            .iter()
            .find(|o| o.source == Source::Restat && o.path == f)
            .expect("Tier B re-stat caught the registered file");
        assert_eq!(restat.bytes, bytes1, "Restat reports the grown size");
        assert!(!out.widened_to_full, "no full walk within 24h");
    }
}

//! Advisory measurement analyzer — the P1 "metrics" layer.
//!
//! This module is **purely advisory**. It reads three append-only logs
//! (`df_series.jsonl`, `series.jsonl`, `history.jsonl`) and derives soft signals:
//! burn-rate / days-to-full, post-deletion regrowth slope, staleness, and a
//! source-weighted confidence. None of these may EVER feed an actuation decision
//! in P1.
//!
//! ## Scope fence (type / mechanical enforcement)
//!
//! The hard safety gate is [`crate::commands::check::pressure_test`] and it is
//! **metrics-blind by construction**: its signature takes NO [`Metrics`], and
//! neither `check.rs` nor [`crate::core::candidate::Candidate::score`] import
//! this module. That separation is the load-bearing safety property of P1 (a
//! df-delta or a regrowth slope must never be able to widen a scan or force an
//! actuation).
//!
//! Because a comment is not an enforcement mechanism, the test module below adds
//! a **mechanical guard**: it `include_str!`s `check.rs` and `candidate.rs` and
//! asserts neither source text references `metrics`. A future refactor that wires
//! metrics into the gate — directly or transitively through these files — fails
//! CI. The fence is one-directional on purpose: metrics MAY import series /
//! history / candidate *types* (to read logs and join on prior actions), but the
//! gate MUST NOT import metrics. Do not invert this dependency.
//!
//! Like `series.rs`, the public API lands before its callers (the recorder /
//! agent-surface wiring is a follow-up), so the dead-code allow mirrors the
//! existing convention.
#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use fs4::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::core::history::{self, ActionKind};
use crate::core::series::{self, Observation, Source};
use crate::profile;

/// Minimum number of contributing samples before confidence is "full". Below
/// this, `metric_confidence` is linearly damped by `n / MIN_SAMPLES` so a single
/// lonely sample never reads as authoritative. Also the floor for emitting a
/// burn-rate at all (a regression needs at least two points; we want a little
/// more before trusting a slope).
pub(crate) const MIN_SAMPLES: usize = 3;

/// Source weights for the confidence blend. A full walk is ground truth (1.0); a
/// targeted re-stat is nearly as trustworthy (0.8); an incremental subtree walk
/// can miss siblings, so it is discounted (0.6). Tombstones carry no byte signal
/// and are excluded from the blend entirely.
pub(crate) const WEIGHT_FULL: f32 = 1.0;
pub(crate) const WEIGHT_RESTAT: f32 = 0.8;
pub(crate) const WEIGHT_INCREMENTAL: f32 = 0.6;

/// Minimum time span (in DAYS) a sample window must cover before we emit a slope
/// (burn-rate or regrowth). The watch recorder ticks every 5 minutes — far more
/// often than daily — so a handful of samples can span only minutes. Extrapolating
/// a days-to-full from a sub-day cluster yields a wildly amplified, nonsensical
/// slope (a tiny x-variance in the denominator blows the slope up ~10^5x and
/// reports "full in 0 days"). Requiring at least half a day of span before
/// trusting a trend is the scale-correct degeneracy guard; `f64::EPSILON` is not
/// (it only catches the exactly-identical-timestamp case). See findings 1 & 2.
pub(crate) const MIN_SPAN_DAYS: f64 = 0.5;

/// Relative-variance floor for the OLS denominator. Even above `MIN_SPAN_DAYS`,
/// near-collinear-in-x clusters can leave `sum((x-mean_x)^2)` vanishingly small
/// relative to the data scale; dividing by it amplifies noise. We reject a slope
/// when `sum_xx_centered <= MIN_REL_VARIANCE * n * x_scale^2` — a relative, not
/// absolute, epsilon so the guard tracks the actual x magnitudes.
pub(crate) const MIN_REL_VARIANCE: f64 = 1e-9;

// ---------------------------------------------------------------------------
// df_series — whole-volume free/total samples for burn-rate
// ---------------------------------------------------------------------------

/// One whole-volume `df` sample. `free_bytes` / `total_bytes` are for the ENTIRE
/// volume (not a subtree) — this feeds ONLY the burn-rate / days-to-full signal.
/// Per the locked invariant, a df delta is never coupled to a scan-widen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DfSample {
    pub ts: DateTime<Utc>,
    pub free_bytes: u64,
    pub total_bytes: u64,
}

/// `~/.diskspace/df_series.jsonl` — the append-only whole-volume df log.
pub fn df_series_path() -> PathBuf {
    profile::data_dir().join("df_series.jsonl")
}

fn df_series_path_in(base: &Path) -> PathBuf {
    base.join("df_series.jsonl")
}

/// Append one df sample under ONE exclusive lock (mirrors `series::append_batch`
/// locking style). Best-effort callers should swallow the error; the recorder
/// agent writes here on each watch tick.
pub fn append_df_sample(sample: &DfSample) -> Result<()> {
    append_df_sample_in(&profile::data_dir(), sample)
}

fn append_df_sample_in(base: &Path, sample: &DfSample) -> Result<()> {
    let path = df_series_path_in(base);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Serialize before taking the lock so a bad value never holds the lock or
    // leaves a half-written line.
    let line = serde_json::to_string(sample)?;
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    FileExt::lock(&file)?;
    let write_res = (|| -> std::io::Result<()> {
        let mut w = BufWriter::new(&file);
        w.write_all(line.as_bytes())?;
        w.write_all(b"\n")?;
        w.flush()?;
        Ok(())
    })();
    let unlock_res = FileExt::unlock(&file);
    write_res?;
    unlock_res?;
    Ok(())
}

/// Read every df sample, file order (oldest-first). Blank/torn lines are skipped.
pub fn read_df_series() -> Result<Vec<DfSample>> {
    read_df_series_in(&profile::data_dir())
}

fn read_df_series_in(base: &Path) -> Result<Vec<DfSample>> {
    let path = df_series_path_in(base);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)?;
    Ok(content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<DfSample>(l).ok())
        .collect())
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Advisory measurements for a single path. Every field is `Option`/soft: a
/// `None` means "not enough data", never "zero". Consumers (agent-surface) must
/// treat this as advice, never as a gate input.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Metrics {
    /// Whole-volume free-space burn rate from `df_series` (least-squares slope of
    /// free bytes over time). **Positive = filling** (free space shrinking),
    /// negative = reclaiming. `None` until at least [`MIN_SAMPLES`] df samples
    /// with a non-degenerate time span exist.
    pub burn_rate_bytes_per_day: Option<f64>,
    /// Days until the volume fills at the current burn rate:
    /// `current_free / burn_rate` — emitted ONLY when filling (`burn_rate > 0`).
    /// When reclaiming (slope <= 0) this is `None`, never a negative number.
    pub days_to_full: Option<u32>,
    /// Post-deletion regrowth: after a prior Reclaim/Airlock at or under `path`,
    /// the rate (bytes/day) at which `series` bytes grew back. `None` until a
    /// post-deletion observation window exists.
    pub regrowth_slope_bytes_per_day: Option<f64>,
    /// Days since the most recent (non-tombstone) `series` observation for the
    /// path. `None` if the path has never been observed.
    pub staleness_days: Option<i64>,
    /// Source-weighted mean of the contributing `series` samples' weights
    /// (Full=1.0, Restat=0.8, Incremental=0.6; Tombstone excluded), damped by
    /// `min(1, n / MIN_SAMPLES)`. `0.0` when no contributing samples exist.
    pub metric_confidence: f32,
}

/// Compute advisory metrics for `path`. **Pure**: reads `df_series`, `series`,
/// and `history` only; performs no writes and makes no actuation decision.
///
/// `prof` is accepted for parity with the rest of the command surface and for
/// future policy-aware weighting; the P1 computation does not yet branch on it.
pub fn compute_metrics(path: &Path, prof: &profile::Profile) -> Result<Metrics> {
    compute_metrics_in(&profile::data_dir(), path, prof, Utc::now())
}

/// Test/seam entry point: base dir + clock injected so tests use a tempdir and a
/// fixed `now` and never touch the real `~/.diskspace`.
fn compute_metrics_in(
    base: &Path,
    path: &Path,
    _prof: &profile::Profile,
    now: DateTime<Utc>,
) -> Result<Metrics> {
    let df = read_df_series_in(base)?;
    let series = series::read_all_in_pub(base)?;
    let hist = history::read_all_in_pub(base)?;

    let (burn_rate, days_to_full) = burn_rate_and_days_to_full(&df);
    let regrowth = regrowth_slope(path, &series, &hist);
    let staleness = staleness_days(path, &series, now);
    let confidence = metric_confidence(path, &series);

    Ok(Metrics {
        burn_rate_bytes_per_day: burn_rate,
        days_to_full,
        regrowth_slope_bytes_per_day: regrowth,
        staleness_days: staleness,
        metric_confidence: confidence,
    })
}

// ---------------------------------------------------------------------------
// Burn rate / days-to-full
// ---------------------------------------------------------------------------

/// Numerically stable ordinary-least-squares slope of `ys` over `xs` using the
/// CENTERED covariance form: `slope = Σ((x-x̄)(y-ȳ)) / Σ((x-x̄)²)`.
///
/// This is a drop-in for the raw normal equations
/// `(n·Σxy − Σx·Σy) / (n·Σxx − (Σx)²)` but avoids their catastrophic subtractive
/// cancellation: `y` here is raw free/subtree bytes (~10¹¹ on a 100 GiB+ volume),
/// so `n·Σxy` and `Σx·Σy` are each ~10¹²–10¹³ and the slope is their tiny
/// difference — f64's 52-bit mantissa loses most of the real day-to-day delta
/// (deltas ~10⁹ against a ~10¹¹ baseline) on noisy data. Centering subtracts the
/// ~10¹¹ baseline (x̄, ȳ) BEFORE multiplying, so every product is O(delta) and the
/// meaningful bits survive. See finding 1.
///
/// Returns `None` when the window is degenerate in x: fewer than two points, a
/// span below [`MIN_SPAN_DAYS`], or an x-variance below the relative floor
/// [`MIN_REL_VARIANCE`] (finding 2 — `f64::EPSILON` is the wrong scale because x
/// is in days and sub-day clusters leave a tiny-but-far-above-EPSILON variance
/// that amplifies the slope ~10⁵×).
fn stable_ols_slope(xs: &[f64], ys: &[f64]) -> Option<f64> {
    let n = xs.len();
    if n < 2 || n != ys.len() {
        return None;
    }
    // Guard the actual time SPAN first: a sub-day cluster of samples must never
    // produce a slope (and thus a "full in 0 days" extrapolation). xs are finite
    // (ms-derived), so a plain `<` comparison is well-defined here.
    let x_min = xs.iter().cloned().fold(f64::INFINITY, f64::min);
    let x_max = xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let span = x_max - x_min;
    if span < MIN_SPAN_DAYS {
        return None;
    }

    let nf = n as f64;
    let mean_x = xs.iter().sum::<f64>() / nf;
    let mean_y = ys.iter().sum::<f64>() / nf;

    let mut sxx = 0.0;
    let mut sxy = 0.0;
    for (x, y) in xs.iter().zip(ys) {
        let dx = x - mean_x;
        sxx += dx * dx;
        sxy += dx * (y - mean_y);
    }

    // Relative-variance guard: reject when the centered x-variance is negligible
    // relative to the data's x scale (a clustered-timestamp window). `x_scale` is
    // the larger of the span and |mean_x| so the floor tracks the real magnitudes
    // and never collapses to an absolute (mis-scaled) epsilon.
    let x_scale = span.max(mean_x.abs()).max(1.0);
    if sxx <= MIN_REL_VARIANCE * nf * x_scale * x_scale {
        return None;
    }

    Some(sxy / sxx)
}

/// Least-squares slope of `free_bytes` over time (bytes/day) plus a days-to-full
/// estimate. Returns `(burn_rate, days_to_full)`:
///
///   * `burn_rate` is the NEGATED slope of free bytes, so **positive means the
///     volume is filling** (free space declining) and negative means reclaiming.
///   * `days_to_full = current_free / burn_rate`, emitted ONLY when
///     `burn_rate > 0` (filling). A reclaiming or flat trend yields `None` for
///     days-to-full — never a negative or absurd number.
///
/// `None` for both when there are fewer than [`MIN_SAMPLES`] samples or the time
/// span is degenerate (all samples at one instant).
fn burn_rate_and_days_to_full(df: &[DfSample]) -> (Option<f64>, Option<u32>) {
    if df.len() < MIN_SAMPLES {
        return (None, None);
    }

    // x = days since the first sample; y = free bytes. Least-squares slope dy/dx
    // via the numerically stable centered form (see `stable_ols_slope`).
    let t0 = df[0].ts;
    let xs: Vec<f64> = df
        .iter()
        .map(|s| (s.ts - t0).num_milliseconds() as f64 / 86_400_000.0)
        .collect();
    let ys: Vec<f64> = df.iter().map(|s| s.free_bytes as f64).collect();

    // Degenerate window (sub-day span, negligible x-variance, etc.) → no slope.
    let slope_free = match stable_ols_slope(&xs, &ys) {
        Some(s) => s, // d(free)/d(day)
        None => return (None, None),
    };

    // Burn rate is the rate free space DISAPPEARS, so negate the free-space slope.
    let burn_rate = -slope_free;

    // Current free = the most recent sample's free bytes.
    let current_free = df.last().map(|s| s.free_bytes as f64).unwrap_or(0.0);

    let days = if burn_rate > 0.0 {
        // Filling: project to empty. Saturate into u32; clamp at least 0.
        let d = current_free / burn_rate;
        if d.is_finite() && d >= 0.0 {
            Some(d.round().min(u32::MAX as f64) as u32)
        } else {
            None
        }
    } else {
        // Reclaiming or flat — never a negative days-to-full.
        None
    };

    (Some(burn_rate), days)
}

// ---------------------------------------------------------------------------
// Regrowth slope (history × series join)
// ---------------------------------------------------------------------------

/// Post-deletion regrowth rate (bytes/day) for `path`.
///
/// Join: find the most recent prior `Reclaim`/`Airlock` history entry at or under
/// `path`. Then, over the `series` observations for the same path subtree that
/// land STRICTLY AFTER that deletion, fit the byte growth and return bytes/day.
///
/// Matching is by path prefix (the deletion path is an ancestor-or-equal of the
/// observation path), which covers both inode-keyed and path-keyed observations.
/// Tombstones are ignored. Returns `None` until at least two post-deletion
/// observations spanning a non-zero duration exist (no window => no slope).
fn regrowth_slope(path: &Path, series: &[Observation], hist: &[history::Entry]) -> Option<f64> {
    // Most recent Reclaim/Airlock at or under `path`.
    let deletion_ts = hist
        .iter()
        .filter(|e| matches!(e.command, ActionKind::Reclaim | ActionKind::Airlock))
        .filter(|e| path_covers(path, &e.path) || path_covers(&e.path, path))
        .map(|e| e.ts)
        .max()?;

    // Post-deletion, non-tombstone observations under `path`, in time order.
    let mut pts: Vec<(DateTime<Utc>, f64)> = series
        .iter()
        .filter(|o| o.source != Source::Tombstone)
        .filter(|o| o.ts > deletion_ts)
        .filter(|o| path_covers(path, &o.path))
        .map(|o| (o.ts, o.bytes as f64))
        .collect();
    pts.sort_by_key(|(ts, _)| *ts);

    if pts.len() < 2 {
        return None;
    }

    let t0 = pts[0].0;
    let xs: Vec<f64> = pts
        .iter()
        .map(|(ts, _)| (*ts - t0).num_milliseconds() as f64 / 86_400_000.0)
        .collect();
    let ys: Vec<f64> = pts.iter().map(|(_, b)| *b).collect();

    // Same numerically stable centered OLS as burn-rate: raw bytes (~10¹¹) would
    // otherwise lose the real growth delta to cancellation, and a sub-day cluster
    // would amplify the slope. `None` on a degenerate (too-short / no-variance)
    // window — no window, no slope.
    stable_ols_slope(&xs, &ys)
}

/// True when `ancestor` is a path-prefix of (or equal to) `descendant`.
fn path_covers(ancestor: &Path, descendant: &Path) -> bool {
    descendant == ancestor || descendant.starts_with(ancestor)
}

// ---------------------------------------------------------------------------
// Staleness
// ---------------------------------------------------------------------------

/// Whole days since the most recent non-tombstone `series` observation for
/// `path`. `None` if the path has never been observed.
fn staleness_days(path: &Path, series: &[Observation], now: DateTime<Utc>) -> Option<i64> {
    let last_ts = series
        .iter()
        .filter(|o| o.source != Source::Tombstone)
        .filter(|o| o.path == path)
        .map(|o| o.ts)
        .max()?;
    Some((now - last_ts).num_days())
}

// ---------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------

/// Source-weighted mean of the contributing samples' weights, damped by sample
/// count. Tombstones are excluded (no byte signal). Returns `0.0` when there are
/// no contributing samples.
pub(crate) fn metric_confidence(path: &Path, series: &[Observation]) -> f32 {
    let weights: Vec<f32> = series
        .iter()
        .filter(|o| o.path == path)
        .filter_map(|o| match o.source {
            Source::Full => Some(WEIGHT_FULL),
            Source::Restat => Some(WEIGHT_RESTAT),
            Source::Incremental => Some(WEIGHT_INCREMENTAL),
            Source::Tombstone => None,
        })
        .collect();

    let n = weights.len();
    if n == 0 {
        return 0.0;
    }
    let mean: f32 = weights.iter().sum::<f32>() / n as f32;
    // Damp by min(1, n / MIN_SAMPLES): a single high-source sample shouldn't read
    // as fully confident.
    let damp = (n as f32 / MIN_SAMPLES as f32).min(1.0);
    mean * damp
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::history::{ActionKind, Entry};
    use crate::core::series::{ObsKey, Observation, Source};
    use chrono::{Duration, TimeZone};
    use std::path::PathBuf;

    /// Throwaway base dir under the OS temp dir, cleaned up on drop. Passed to the
    /// `*_in` seams so tests never touch the real `~/.diskspace`.
    struct TempBase {
        path: PathBuf,
    }
    impl TempBase {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let uniq = format!(
                "diskspace-metrics-test-{}-{}-{}",
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

    fn ts(y: i32, mo: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, 0, 0, 0).unwrap()
    }

    fn df(when: DateTime<Utc>, free: u64, total: u64) -> DfSample {
        DfSample {
            ts: when,
            free_bytes: free,
            total_bytes: total,
        }
    }

    fn series_obs(path: &str, bytes: u64, when: DateTime<Utc>, src: Source) -> Observation {
        Observation::new(
            ObsKey::Path(PathBuf::from(path)),
            PathBuf::from(path),
            bytes,
            src,
            "scan-test",
            when,
            None,
        )
    }

    fn hist_entry(cmd: ActionKind, path: &str, when: DateTime<Utc>) -> Entry {
        Entry {
            ts: when,
            command: cmd,
            candidate_id: None,
            rule_id: None,
            path: PathBuf::from(path),
            size_bytes: 0,
            df_before: None,
            df_after: None,
            actually_freed: None,
            reversible: false,
            undo_cmd: None,
            rule_confidence: None,
            context: serde_json::Map::new(),
        }
    }

    // -- burn rate / days-to-full -------------------------------------------

    #[test]
    fn burn_rate_matches_seeded_linear_df_series() {
        // Free space drops by exactly 1 GiB/day for 5 days (filling).
        let gib = 1_073_741_824u64;
        let total = 500 * gib;
        let start_free = 100 * gib;
        let mut samples = Vec::new();
        for d in 0..5 {
            samples.push(df(
                ts(2026, 6, 1) + Duration::days(d),
                start_free - (d as u64) * gib,
                total,
            ));
        }
        let (burn, days) = burn_rate_and_days_to_full(&samples);
        let burn = burn.expect("burn rate present");
        // Slope of free is -1 GiB/day → burn rate is +1 GiB/day.
        let expected = gib as f64;
        assert!(
            (burn - expected).abs() < expected * 1e-6,
            "burn rate ≈ 1 GiB/day, got {burn}"
        );
        // current_free at day 4 = 96 GiB; 96 GiB / 1 GiB/day = 96 days.
        assert_eq!(days, Some(96), "days-to-full = current_free / burn_rate");
    }

    #[test]
    fn reclaiming_series_yields_no_days_to_full() {
        // Free space GROWS 2 GiB/day (reclaiming) → burn rate negative, days None.
        let gib = 1_073_741_824u64;
        let total = 500 * gib;
        let start_free = 50 * gib;
        let mut samples = Vec::new();
        for d in 0..4 {
            samples.push(df(
                ts(2026, 6, 1) + Duration::days(d),
                start_free + (d as u64) * 2 * gib,
                total,
            ));
        }
        let (burn, days) = burn_rate_and_days_to_full(&samples);
        let burn = burn.expect("burn rate present");
        assert!(burn < 0.0, "reclaiming → negative burn rate, got {burn}");
        assert_eq!(days, None, "reclaiming must NEVER yield a days-to-full");
    }

    #[test]
    fn too_few_df_samples_yields_none() {
        let gib = 1_073_741_824u64;
        let samples = vec![
            df(ts(2026, 6, 1), 10 * gib, 100 * gib),
            df(ts(2026, 6, 2), 9 * gib, 100 * gib),
        ];
        assert_eq!(burn_rate_and_days_to_full(&samples), (None, None));
    }

    #[test]
    fn degenerate_df_span_yields_none() {
        // All three samples at the same instant — no time span, no slope.
        let gib = 1_073_741_824u64;
        let when = ts(2026, 6, 1);
        let samples = vec![
            df(when, 10 * gib, 100 * gib),
            df(when, 9 * gib, 100 * gib),
            df(when, 8 * gib, 100 * gib),
        ];
        assert_eq!(burn_rate_and_days_to_full(&samples), (None, None));
    }

    // -- finding 2: sub-day clusters must NOT extrapolate a days-to-full --------

    #[test]
    fn subday_cluster_yields_no_slope() {
        // Three samples a few MINUTES apart (recorder ticks every 5 min). The raw
        // normal equations would see a denom ~1e-5 (far above f64::EPSILON), pass
        // the old guard, and amplify the slope ~1e5×, reporting a huge burn rate
        // and "full in 0 days". The MIN_SPAN_DAYS guard rejects the window.
        let gib = 1_073_741_824u64;
        let total = 500 * gib;
        let base = ts(2026, 6, 1);
        let samples = vec![
            df(base, 100 * gib, total),
            df(base + Duration::minutes(5), 100 * gib - 4096, total),
            df(base + Duration::minutes(10), 100 * gib - 8192, total),
        ];
        // Span is 10 minutes ≈ 0.007 days, well under MIN_SPAN_DAYS (0.5).
        let (burn, days) = burn_rate_and_days_to_full(&samples);
        assert_eq!(burn, None, "sub-day window must not emit a burn rate");
        assert_eq!(
            days, None,
            "sub-day window must not extrapolate days-to-full"
        );
    }

    #[test]
    fn span_just_over_half_day_emits_slope() {
        // A window that clears MIN_SPAN_DAYS by a hair still produces a sane slope
        // (the guard is a floor, not an over-eager reject). 13h span, filling.
        let gib = 1_073_741_824u64;
        let total = 500 * gib;
        let base = ts(2026, 6, 1);
        let samples = vec![
            df(base, 100 * gib, total),
            df(base + Duration::hours(6), 100 * gib - gib, total),
            df(base + Duration::hours(13), 100 * gib - 2 * gib, total),
        ];
        let (burn, _days) = burn_rate_and_days_to_full(&samples);
        let burn = burn.expect("a >0.5-day span emits a burn rate");
        assert!(
            burn > 0.0,
            "free space declining → positive burn rate, got {burn}"
        );
    }

    // -- finding 1: numerically stable slope on a NOISY near-flat series --------

    #[test]
    fn burn_rate_stable_on_noisy_large_baseline() {
        // The hard case the raw normal equations fail: a ~100 GiB baseline (y~1e11)
        // with a small TRUE downward trend (≈ -0.5 GiB/day) plus day-to-day NOISE
        // of ±1 GiB. The raw form's `n·Σxy − Σx·Σy` is a tiny difference of ~1e13
        // terms and loses the trend to cancellation; the centered form recovers it.
        let gib = 1_073_741_824u64;
        let total = 500 * gib;
        let start = 100 * gib;
        // Deterministic pseudo-noise so the test is reproducible (no rng dep).
        let noise = [0.6, -0.4, 0.9, -0.7, 0.3, -0.9, 0.5, -0.2, 0.8, -0.6];
        let mut samples = Vec::new();
        for d in 0..10i64 {
            // True free = start - 0.5 GiB/day; add ±~1 GiB of noise.
            let trend = (d as f64) * 0.5 * gib as f64;
            let jitter = noise[d as usize] * gib as f64;
            let free = (start as f64 - trend + jitter).round() as u64;
            samples.push(df(ts(2026, 6, 1) + Duration::days(d), free, total));
        }
        let (burn, days) = burn_rate_and_days_to_full(&samples);
        let burn = burn.expect("burn rate present on a 10-day noisy series");
        // The true burn rate is +0.5 GiB/day. With cancellation the raw form can
        // flip sign or be off by an order of magnitude; the stable form must land
        // within ~40% (the noise is large relative to the trend).
        let expected = 0.5 * gib as f64;
        assert!(
            burn > 0.0,
            "must recover the FILLING sign despite noise, got {burn}"
        );
        assert!(
            (burn - expected).abs() < expected * 0.4,
            "stable slope recovers ≈0.5 GiB/day trend through noise, got {} GiB/day",
            burn / gib as f64
        );
        assert!(days.is_some(), "filling → a days-to-full is emitted");
    }

    // -- regrowth slope ------------------------------------------------------

    #[test]
    fn regrowth_slope_on_airlock_then_growth() {
        let path = PathBuf::from("/proj/node_modules");
        // Airlock on day 1; then the cache regrows 100 MB/day for 4 observations.
        let mb = 1_000_000u64;
        let hist = vec![hist_entry(
            ActionKind::Airlock,
            "/proj/node_modules",
            ts(2026, 6, 1),
        )];
        let mut series = Vec::new();
        for d in 0..4 {
            series.push(series_obs(
                "/proj/node_modules",
                (d as u64) * 100 * mb,
                ts(2026, 6, 2) + Duration::days(d),
                Source::Full,
            ));
        }
        // A pre-deletion observation that must be IGNORED (huge, before airlock).
        series.push(series_obs(
            "/proj/node_modules",
            999_999 * mb,
            ts(2026, 5, 1),
            Source::Full,
        ));

        let slope = regrowth_slope(&path, &series, &hist).expect("regrowth slope present");
        let expected = 100.0 * mb as f64; // 100 MB/day
        assert!(
            (slope - expected).abs() < expected * 1e-6,
            "regrowth ≈ 100 MB/day, got {slope}"
        );
    }

    #[test]
    fn regrowth_none_without_post_deletion_window() {
        let path = PathBuf::from("/proj/cache");
        // Reclaim on day 5; only ONE post-deletion observation → no window.
        let hist = vec![hist_entry(
            ActionKind::Reclaim,
            "/proj/cache",
            ts(2026, 6, 5),
        )];
        let series = vec![
            series_obs("/proj/cache", 10, ts(2026, 6, 1), Source::Full), // pre-deletion
            series_obs("/proj/cache", 20, ts(2026, 6, 6), Source::Full), // single post
        ];
        assert_eq!(regrowth_slope(&path, &series, &hist), None);
    }

    #[test]
    fn regrowth_none_without_prior_deletion() {
        let path = PathBuf::from("/proj/cache");
        let hist: Vec<Entry> = vec![];
        let series = vec![
            series_obs("/proj/cache", 10, ts(2026, 6, 1), Source::Full),
            series_obs("/proj/cache", 20, ts(2026, 6, 2), Source::Full),
        ];
        assert_eq!(regrowth_slope(&path, &series, &hist), None);
    }

    #[test]
    fn regrowth_matches_child_path_under_deleted_dir() {
        // Deletion recorded on the parent dir; regrowth observed on a child path.
        let path = PathBuf::from("/proj/cache");
        let mb = 1_000_000u64;
        let hist = vec![hist_entry(
            ActionKind::Reclaim,
            "/proj/cache",
            ts(2026, 6, 1),
        )];
        let mut series = Vec::new();
        for d in 0..3 {
            series.push(series_obs(
                "/proj/cache/sub/blob.bin",
                (d as u64) * 50 * mb,
                ts(2026, 6, 2) + Duration::days(d),
                Source::Full,
            ));
        }
        let slope = regrowth_slope(&path, &series, &hist).expect("child regrowth present");
        let expected = 50.0 * mb as f64;
        assert!((slope - expected).abs() < expected * 1e-6, "got {slope}");
    }

    // -- staleness -----------------------------------------------------------

    #[test]
    fn staleness_is_days_since_last_observation() {
        let path = PathBuf::from("/p");
        let series = vec![
            series_obs("/p", 1, ts(2026, 6, 1), Source::Full),
            series_obs("/p", 2, ts(2026, 6, 5), Source::Full),
            // tombstone is ignored even though it is newest
            series_obs("/p", 0, ts(2026, 6, 10), Source::Tombstone),
        ];
        let now = ts(2026, 6, 12);
        assert_eq!(staleness_days(&path, &series, now), Some(7));
    }

    #[test]
    fn staleness_none_when_never_observed() {
        let series = vec![series_obs("/other", 1, ts(2026, 6, 1), Source::Full)];
        assert_eq!(
            staleness_days(&PathBuf::from("/p"), &series, ts(2026, 6, 2)),
            None
        );
    }

    // -- confidence weighting ------------------------------------------------

    #[test]
    fn confidence_weights_full_vs_restat_vs_incremental() {
        let path = PathBuf::from("/p");
        // One of each source (3 samples == MIN_SAMPLES, so damp == 1.0). Mean of
        // 1.0, 0.8, 0.6 = 0.8.
        let series = vec![
            series_obs("/p", 1, ts(2026, 6, 1), Source::Full),
            series_obs("/p", 2, ts(2026, 6, 2), Source::Restat),
            series_obs("/p", 3, ts(2026, 6, 3), Source::Incremental),
        ];
        let c = metric_confidence(&path, &series);
        assert!((c - 0.8).abs() < 1e-6, "mean(1.0,0.8,0.6)=0.8, got {c}");
    }

    #[test]
    fn confidence_damped_below_min_samples() {
        let path = PathBuf::from("/p");
        // A single Full sample: mean 1.0 but damp = 1/3 → 0.3333.
        let series = vec![series_obs("/p", 1, ts(2026, 6, 1), Source::Full)];
        let c = metric_confidence(&path, &series);
        assert!(
            (c - (1.0 / 3.0)).abs() < 1e-6,
            "single sample damped by 1/MIN_SAMPLES, got {c}"
        );
    }

    #[test]
    fn confidence_excludes_tombstones_and_other_paths() {
        let path = PathBuf::from("/p");
        let series = vec![
            series_obs("/p", 1, ts(2026, 6, 1), Source::Full),
            series_obs("/p", 0, ts(2026, 6, 2), Source::Tombstone), // excluded
            series_obs("/other", 5, ts(2026, 6, 3), Source::Full),  // wrong path
        ];
        // Only the single Full /p sample counts → mean 1.0, damp 1/3.
        let c = metric_confidence(&path, &series);
        assert!((c - (1.0 / 3.0)).abs() < 1e-6, "got {c}");
    }

    #[test]
    fn confidence_zero_when_no_samples() {
        assert_eq!(metric_confidence(&PathBuf::from("/p"), &[]), 0.0);
    }

    // -- df_series round-trip ------------------------------------------------

    #[test]
    fn df_sample_append_then_read_roundtrips() {
        let base = TempBase::new("df-roundtrip");
        let s1 = df(ts(2026, 6, 1), 100, 500);
        let s2 = df(ts(2026, 6, 2), 90, 500);
        append_df_sample_in(base.path(), &s1).unwrap();
        append_df_sample_in(base.path(), &s2).unwrap();
        let got = read_df_series_in(base.path()).unwrap();
        assert_eq!(got, vec![s1, s2], "df samples round-trip in file order");
    }

    // -- end-to-end compute via the tempdir seam -----------------------------

    #[test]
    fn compute_metrics_in_assembles_all_fields() {
        let base = TempBase::new("compute");
        let gib = 1_073_741_824u64;
        let total = 500 * gib;
        // df: filling 1 GiB/day for 4 days.
        for d in 0..4 {
            append_df_sample_in(
                base.path(),
                &df(
                    ts(2026, 6, 1) + Duration::days(d),
                    (100 - d as u64) * gib,
                    total,
                ),
            )
            .unwrap();
        }
        // series under /p: an airlock then regrowth.
        let mb = 1_000_000u64;
        let mut obs = Vec::new();
        for d in 0..3 {
            obs.push(series_obs(
                "/p",
                (d as u64) * 10 * mb,
                ts(2026, 6, 5) + Duration::days(d),
                Source::Full,
            ));
        }
        series::append_batch_in_pub(base.path(), &obs).unwrap();
        // history: an airlock on /p before the regrowth window.
        history::append_inner_to_pub(
            base.path(),
            &hist_entry(ActionKind::Airlock, "/p", ts(2026, 6, 4)),
        )
        .unwrap();

        let prof = profile::Profile::default();
        let now = ts(2026, 6, 10);
        let m = compute_metrics_in(base.path(), &PathBuf::from("/p"), &prof, now).unwrap();

        assert!(m.burn_rate_bytes_per_day.is_some(), "burn rate computed");
        assert!(m.days_to_full.is_some(), "days-to-full computed (filling)");
        assert!(
            m.regrowth_slope_bytes_per_day.is_some(),
            "regrowth computed from airlock + post growth"
        );
        assert_eq!(m.staleness_days, Some(3), "last obs day 7 vs now day 10");
        assert!(m.metric_confidence > 0.0, "confidence from 3 Full samples");
    }

    // -----------------------------------------------------------------------
    // SCOPE FENCE — mechanical guard.
    //
    // The hard safety gate (`check.rs::pressure_test`) and `candidate::score`
    // are metrics-BLIND by design. These tests read those source files verbatim
    // and assert they do not reference `metrics`. A future refactor that wires
    // metrics into the gate — even transitively through these files — turns the
    // build red here, BEFORE it can couple an advisory signal to actuation.
    //
    // We intentionally do NOT use trybuild (brittle, toolchain-version
    // sensitive). A substring scan of the committed source is robust and obvious.
    // -----------------------------------------------------------------------

    #[test]
    fn scope_fence_check_rs_does_not_reference_metrics() {
        let src = include_str!("../commands/check.rs");
        assert!(
            !src.contains("metrics"),
            "SCOPE FENCE VIOLATION: src/commands/check.rs references `metrics`. \
             The pressure-test gate MUST stay metrics-blind — advisory signals \
             must never feed an actuation decision. Remove the metrics coupling."
        );
    }

    #[test]
    fn scope_fence_candidate_rs_does_not_reference_metrics() {
        let src = include_str!("candidate.rs");
        assert!(
            !src.contains("metrics"),
            "SCOPE FENCE VIOLATION: src/core/candidate.rs references `metrics`. \
             Candidate::score() MUST NOT depend on advisory metrics. Remove the \
             coupling so scoring stays measurement-blind."
        );
    }
}

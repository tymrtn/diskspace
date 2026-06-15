//! `diskspace watch` — installable launchd monitor.
//!
//! Subcommands:
//!   * install   — write `~/Library/LaunchAgents/com.tymrtn.diskspace.watch.plist` and load it
//!   * uninstall — unload and remove the plist
//!   * status    — show whether the agent is installed, running, last result
//!   * run       — one check tick; called by launchd every 5 minutes
//!
//! Behavior on a `run` tick:
//!   * Read free / total bytes for $HOME's filesystem.
//!   * If pct_free <  5%  → urgent  notification, recommend `diskspace doctor`.
//!   * If pct_free < 10% → soft    notification, recommend `diskspace detect`.
//!   * Otherwise → ok.
//!
//! Notification dedup: state file at `~/.diskspace/watch_state.json` tracks
//! the last-notified level. We re-notify only when the level changes (so the
//! user doesn't get pinged every 5 minutes if their disk stays at 7% free).

use anyhow::{Context as _, Result};
use console::Style;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::bundle;
use crate::core::metrics::{self, DfSample};
use crate::core::rules;
use crate::core::scanner;
use crate::output::Context;

const PLIST_LABEL: &str = "com.tymrtn.diskspace.watch";
const CHECK_INTERVAL_SECONDS: u32 = 300; // 5 min

/// Soft target: nudge below this. User said "10%, target not hard."
const SOFT_PCT_FREE: f32 = 10.0;

/// Urgent threshold: doctor-worthy.
const URGENT_PCT_FREE: f32 = 5.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Level {
    Ok,
    Soft,
    Urgent,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct WatchState {
    last_level: Option<Level>,
    last_ts: Option<chrono::DateTime<chrono::Utc>>,
    last_pct_free: Option<f32>,
    last_free_bytes: Option<u64>,
    last_total_bytes: Option<u64>,
}

pub fn install(ctx: &Context) -> Result<()> {
    let plist_path = launch_agent_plist_path()?;
    // Build (or refresh) the .app bundle so macOS Background Items has metadata
    // and an icon to display. The launchd plist points at the bundle's binary.
    let bin = bundle::ensure_bundle().context("creating DiskspaceWatch.app bundle")?;
    let log_dir = state_dir()?;
    fs::create_dir_all(&log_dir)?;
    let stdout_log = log_dir.join("watch.stdout.log");
    let stderr_log = log_dir.join("watch.stderr.log");

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>watch</string>
        <string>run</string>
    </array>
    <key>StartInterval</key>
    <integer>{interval}</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
        label = PLIST_LABEL,
        bin = bin.display(),
        interval = CHECK_INTERVAL_SECONDS,
        stdout = stdout_log.display(),
        stderr = stderr_log.display(),
    );

    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&plist_path, plist).context("writing LaunchAgent plist")?;

    // Unload any prior copy (ignore errors — first install will fail this), then load.
    let _ = Command::new("launchctl")
        .args(["unload", "-w"])
        .arg(&plist_path)
        .output();
    let load = Command::new("launchctl")
        .args(["load", "-w"])
        .arg(&plist_path)
        .output()
        .context("launchctl load failed")?;

    if !load.status.success() {
        let stderr = String::from_utf8_lossy(&load.stderr);
        anyhow::bail!("launchctl load failed: {}", stderr.trim());
    }

    if ctx.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "installed": true,
                "label": PLIST_LABEL,
                "plist": plist_path,
                "interval_seconds": CHECK_INTERVAL_SECONDS,
                "soft_pct_free": SOFT_PCT_FREE,
                "urgent_pct_free": URGENT_PCT_FREE,
            }))?
        );
    } else {
        let green = Style::new().green().bold();
        let dim = Style::new().dim();
        println!();
        println!("  {}  diskspace watch installed", ctx.style("✓", &green));
        println!(
            "     {}",
            ctx.style(
                &format!(
                    "checks every {}s — soft nudge at {}% free, urgent at {}%",
                    CHECK_INTERVAL_SECONDS, SOFT_PCT_FREE, URGENT_PCT_FREE
                ),
                &dim
            )
        );
        println!(
            "     {}",
            ctx.style(&plist_path.display().to_string(), &dim)
        );
        println!();
        println!(
            "  Run `diskspace watch status` any time, or `diskspace watch uninstall` to remove."
        );
        println!();
    }
    Ok(())
}

pub fn uninstall(ctx: &Context) -> Result<()> {
    let plist_path = launch_agent_plist_path()?;
    if !plist_path.exists() {
        if ctx.json {
            println!(r#"{{"installed":false,"message":"not installed"}}"#);
        } else {
            println!("\n  diskspace watch is not installed.\n");
        }
        return Ok(());
    }
    let _ = Command::new("launchctl")
        .args(["unload", "-w"])
        .arg(&plist_path)
        .output();
    fs::remove_file(&plist_path)?;
    // Also remove the .app bundle (the metadata wrapper); state files stay.
    let _ = bundle::remove_bundle();
    if ctx.json {
        println!(r#"{{"uninstalled":true}}"#);
    } else {
        let yellow = Style::new().yellow();
        println!();
        println!("  {}  diskspace watch uninstalled", ctx.style("○", &yellow));
        println!();
    }
    Ok(())
}

pub fn status(ctx: &Context) -> Result<()> {
    let plist_path = launch_agent_plist_path()?;
    let installed = plist_path.exists();
    let loaded = if installed {
        Command::new("launchctl")
            .arg("list")
            .output()
            .ok()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.contains(PLIST_LABEL))
            })
            .unwrap_or(false)
    } else {
        false
    };

    let state = load_state().unwrap_or_default();

    if ctx.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "installed": installed,
                "loaded": loaded,
                "plist": plist_path,
                "interval_seconds": CHECK_INTERVAL_SECONDS,
                "soft_pct_free": SOFT_PCT_FREE,
                "urgent_pct_free": URGENT_PCT_FREE,
                "last": {
                    "level": state.last_level,
                    "ts": state.last_ts,
                    "pct_free": state.last_pct_free,
                    "free_bytes": state.last_free_bytes,
                    "total_bytes": state.last_total_bytes,
                }
            }))?
        );
        return Ok(());
    }

    let bold = Style::new().bold();
    let dim = Style::new().dim();
    let green = Style::new().green().bold();
    let yellow = Style::new().yellow().bold();
    let red = Style::new().red().bold();

    println!();
    println!("  {}  diskspace watch", ctx.style("·", &dim));
    println!(
        "    {:<14}  {}",
        ctx.style("installed", &bold),
        if installed {
            ctx.style("yes", &green)
        } else {
            ctx.style("no", &dim)
        }
    );
    println!(
        "    {:<14}  {}",
        ctx.style("loaded", &bold),
        if loaded {
            ctx.style("yes", &green)
        } else {
            ctx.style("no", &dim)
        }
    );
    println!(
        "    {:<14}  every {}s ({}% soft / {}% urgent)",
        ctx.style("interval", &bold),
        CHECK_INTERVAL_SECONDS,
        SOFT_PCT_FREE,
        URGENT_PCT_FREE
    );

    if let (Some(pct), Some(level), Some(ts)) =
        (state.last_pct_free, state.last_level, state.last_ts)
    {
        let level_styled = match level {
            Level::Ok => ctx.style("ok", &green),
            Level::Soft => ctx.style("soft", &yellow),
            Level::Urgent => ctx.style("urgent", &red),
        };
        println!();
        println!(
            "    {:<14}  {} ({:.1}% free)",
            ctx.style("last check", &bold),
            level_styled,
            pct
        );
        println!(
            "    {:<14}  {}",
            ctx.style("", &bold),
            ctx.style(&ts.format("%Y-%m-%d %H:%M UTC").to_string(), &dim)
        );
    } else {
        println!();
        println!(
            "    {:<14}  {}",
            ctx.style("last check", &bold),
            ctx.style("none yet", &dim)
        );
    }
    println!();
    Ok(())
}

pub fn run(ctx: &Context) -> Result<()> {
    let home = home_dir()?;
    let (free_bytes, total_bytes) = df_free_and_total(&home).context("reading df")?;
    let pct_free = if total_bytes > 0 {
        (free_bytes as f64 / total_bytes as f64 * 100.0) as f32
    } else {
        100.0
    };

    // --- Measurement recorder (additive, best-effort, advisory-only) --------
    //
    // After the df read we record this tick into the P1 measurement layer:
    //   * scanner::tick — emits per-entry Observations (Incremental / Restat /
    //     Tombstone, or a daily Full true-up) and the next TickState.
    //   * series::append_batch — persists those observations under one lock.
    //   * append one df sample to df_series.jsonl (whole-volume burn-rate signal).
    //   * persist the next TickState atomically.
    //
    // This is strictly additive to the df-level/notify/save_state flow below and
    // takes NO action. A scan or write error here must NEVER crash `watch run`
    // (mirrors history's best-effort posture), so the whole thing is swallowed
    // with a log line. The returned advisory (if any) is surfaced in output but
    // never acted upon — df can never widen a scan (locked invariant).
    let advisory = record_tick(&home, free_bytes, total_bytes);

    let level = if pct_free < URGENT_PCT_FREE {
        Level::Urgent
    } else if pct_free < SOFT_PCT_FREE {
        Level::Soft
    } else {
        Level::Ok
    };

    let prior = load_state().unwrap_or_default();
    let prior_level = prior.last_level;

    let new_state = WatchState {
        last_level: Some(level),
        last_ts: Some(chrono::Utc::now()),
        last_pct_free: Some(pct_free),
        last_free_bytes: Some(free_bytes),
        last_total_bytes: Some(total_bytes),
    };
    save_state(&new_state).ok();

    let should_notify = prior_level != Some(level)
        && match level {
            Level::Ok => prior_level.is_some() && prior_level != Some(Level::Ok),
            _ => true,
        };

    if should_notify {
        notify(level, free_bytes, pct_free);
    }

    if ctx.json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "level": level,
                "pct_free": pct_free,
                "free_bytes": free_bytes,
                "total_bytes": total_bytes,
                "notified": should_notify,
                "advisory": advisory,
            }))?
        );
    } else if !ctx.quiet {
        let dim = Style::new().dim();
        println!(
            "  watch: {} — {:.1}% free ({} / {}){}",
            match level {
                Level::Ok => "ok",
                Level::Soft => "soft",
                Level::Urgent => "urgent",
            },
            pct_free,
            crate::output::format_bytes(free_bytes),
            crate::output::format_bytes(total_bytes),
            ctx.style(if should_notify { "  · notified" } else { "" }, &dim),
        );
        if let Some(note) = &advisory {
            println!("  {}", ctx.style(note, &dim));
        }
    }
    Ok(())
}

/// Record this watch tick into the P1 measurement layer. Returns the tick's
/// advisory note (if any) so the caller can surface it — but the caller takes NO
/// action on it (advisory only; df can never widen a scan).
///
/// Best-effort throughout: every sub-step that can fail (rule load, scan, series
/// append, df-sample append, tick-state persist) is swallowed with a log line so
/// a measurement error can never crash `watch run`. Mirrors `history::append`'s
/// posture. Production state lands under `~/.diskspace` via the `profile`-keyed
/// helpers (which resolve from `$HOME`).
fn record_tick(home: &Path, free_bytes: u64, total_bytes: u64) -> Option<String> {
    // Load the rule set the same way `scan` / `detect` do.
    let rules = match rules::load_builtin() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("(watch: recorder skipped — failed to load rules: {})", e);
            return None;
        }
    };

    // Load prior tick state (default if absent → "due for a full walk").
    let state = scanner::load_tick_state();

    // Run the incremental measurement step. NOTE: `tick` ALREADY appends its
    // observations to `series.jsonl` internally, under one batch lock (see
    // `scanner::tick_in` → `series_append_batch`). We therefore do NOT call
    // `series::append_batch(&outcome.observations)` again here — that would
    // double-write every observation and corrupt the burn-rate / regrowth
    // analysis. The observations are returned only so callers/tests can inspect
    // them; the durable write is owned by `tick`.
    let outcome = match scanner::tick(home, &rules, &state) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("(watch: recorder tick failed: {})", e);
            return None;
        }
    };

    // Append one whole-volume df sample (burn-rate signal). Best-effort.
    let sample = DfSample {
        ts: chrono::Utc::now(),
        free_bytes,
        total_bytes,
    };
    if let Err(e) = metrics::append_df_sample(&sample) {
        eprintln!("(watch: recorder failed to append df sample: {})", e);
    }

    // Persist the next tick state atomically (temp + rename). Best-effort.
    if let Err(e) = scanner::save_tick_state(&outcome.next_state) {
        eprintln!("(watch: recorder failed to persist tick state: {})", e);
    }

    outcome.advisory
}

fn notify(level: Level, free_bytes: u64, pct_free: f32) {
    let (title, body) = match level {
        Level::Urgent => (
            "diskspace — disk is full".to_string(),
            format!(
                "Only {:.1}% free ({}). Run `diskspace doctor` to free space safely.",
                pct_free,
                crate::output::format_bytes(free_bytes)
            ),
        ),
        Level::Soft => (
            "diskspace — disk getting low".to_string(),
            format!(
                "{:.1}% free ({}). Run `diskspace detect` to see what's cleanable.",
                pct_free,
                crate::output::format_bytes(free_bytes)
            ),
        ),
        Level::Ok => (
            "diskspace — disk recovered".to_string(),
            format!(
                "Back above the 10% target ({:.1}% free, {}). Nothing to do.",
                pct_free,
                crate::output::format_bytes(free_bytes)
            ),
        ),
    };

    // macOS user notification via osascript. Keep quiet on failure — best-effort.
    let escaped_title = title.replace('"', "'");
    let escaped_body = body.replace('"', "'");
    let script = format!(
        r#"display notification "{}" with title "{}""#,
        escaped_body, escaped_title
    );
    let _ = Command::new("osascript").arg("-e").arg(script).output();
}

fn launch_agent_plist_path() -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{}.plist", PLIST_LABEL)))
}

fn state_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(".diskspace"))
}

fn state_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("watch_state.json"))
}

fn load_state() -> Result<WatchState> {
    let path = state_file()?;
    load_state_from(&path)
}

/// Load state from `path`, tolerating a missing or garbage file (returns
/// [`WatchState::default`]). A stray `.json.tmp` from an interrupted
/// [`save_state_to`] is irrelevant here — we only ever read the renamed target.
fn load_state_from(path: &Path) -> Result<WatchState> {
    if !path.exists() {
        return Ok(WatchState::default());
    }
    let s = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&s).unwrap_or_default())
}

fn save_state(state: &WatchState) -> Result<()> {
    let dir = state_dir()?;
    fs::create_dir_all(&dir)?;
    let path = state_file()?;
    save_state_to(&path, state)
}

/// Atomically persist `state` to `path`: serialize, write+flush a sibling
/// `.json.tmp`, then `fs::rename` it over the target. Rename is atomic on the
/// same filesystem (always `~/.diskspace` here), so a crash or concurrent
/// reader never observes a torn/half-written state file.
fn save_state_to(path: &Path, state: &WatchState) -> Result<()> {
    let s = serde_json::to_string_pretty(state)?;
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write as _;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(s.as_bytes())?;
        f.flush()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn home_dir() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .context("HOME not set")
}

/// Reads `df -k <path>` and returns (free_bytes, total_bytes).
fn df_free_and_total(path: &Path) -> Result<(u64, u64)> {
    let output = Command::new("df").arg("-k").arg(path).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("df returned no data row"))?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    // macOS df -k: Filesystem  1024-blocks  Used  Available  Capacity  ...
    let total_kb: u64 = fields
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("df: missing total"))?
        .parse()?;
    let avail_kb: u64 = fields
        .get(3)
        .ok_or_else(|| anyhow::anyhow!("df: missing avail"))?
        .parse()?;
    Ok((avail_kb * 1024, total_kb * 1024))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempBase {
        path: PathBuf,
    }
    impl TempBase {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let uniq = format!(
                "diskspace-watch-test-{}-{}-{}",
                tag,
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            );
            p.push(uniq);
            fs::create_dir_all(&p).unwrap();
            Self { path: p }
        }
        fn state_file(&self) -> PathBuf {
            self.path.join("watch_state.json")
        }
    }
    impl Drop for TempBase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn sample_state() -> WatchState {
        WatchState {
            last_level: Some(Level::Soft),
            last_ts: Some(chrono::Utc::now()),
            last_pct_free: Some(7.5),
            last_free_bytes: Some(1234),
            last_total_bytes: Some(98765),
        }
    }

    #[test]
    fn save_then_load_roundtrips() {
        let base = TempBase::new("roundtrip");
        let path = base.state_file();
        let state = sample_state();
        save_state_to(&path, &state).unwrap();

        let loaded = load_state_from(&path).unwrap();
        assert_eq!(loaded.last_level, state.last_level);
        assert_eq!(loaded.last_pct_free, state.last_pct_free);
        assert_eq!(loaded.last_free_bytes, state.last_free_bytes);
        assert_eq!(loaded.last_total_bytes, state.last_total_bytes);
    }

    /// A stray/garbage `.json.tmp` left by an interrupted save must NOT corrupt
    /// the real state file: load reads only the renamed target, and a fresh
    /// atomic save renames a complete temp over it. Rename semantics mean the
    /// reader never sees a half-written file.
    #[test]
    fn interrupted_temp_does_not_corrupt_real_state() {
        let base = TempBase::new("interrupted");
        let path = base.state_file();

        // 1. A good, complete state file exists.
        let good = sample_state();
        save_state_to(&path, &good).unwrap();

        // 2. Simulate an interrupted save: a garbage half-written temp is left
        //    behind. It is a sibling, never renamed over the target.
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, b"{ this is not valid json, torn mid-wri").unwrap();

        // 3. The real state file is still intact and parses correctly — the
        //    garbage temp is irrelevant to the reader.
        let loaded = load_state_from(&path).unwrap();
        assert_eq!(
            loaded.last_free_bytes, good.last_free_bytes,
            "real state survived the interrupted temp"
        );

        // 4. A subsequent atomic save overwrites the target via rename and the
        //    new value is observed (no corruption from the stale temp).
        let mut next = sample_state();
        next.last_free_bytes = Some(42);
        save_state_to(&path, &next).unwrap();
        let reloaded = load_state_from(&path).unwrap();
        assert_eq!(reloaded.last_free_bytes, Some(42));
    }

    // =======================================================================
    // Recorder wiring — integration-style test against a tempdir $HOME.
    //
    // `record_tick` drives the PRODUCTION measurement helpers, all of which
    // resolve their on-disk location from `profile::data_dir()` → `$HOME`. By
    // pointing `$HOME` at a throwaway tempdir we exercise the real append path
    // (scanner::tick → series::append_batch, metrics::append_df_sample,
    // scanner::save_tick_state) WITHOUT ever touching the real `~/.diskspace`.
    //
    // `$HOME` is process-global, so this test serializes itself via a static
    // mutex and restores the prior value on the way out. No other test in this
    // crate reads `$HOME` concurrently (series/scanner/metrics tests target an
    // explicit `base` tempdir, not `$HOME`).
    // =======================================================================

    use std::sync::Mutex;
    static HOME_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard: swap `$HOME` to `new_home` for the test, restore on drop.
    struct HomeGuard {
        prior: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl HomeGuard {
        fn set(new_home: &Path) -> Self {
            // Poisoning is fine — we only guard a unit `()`; recover the guard.
            let lock = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prior = std::env::var("HOME").ok();
            std::env::set_var("HOME", new_home);
            Self { prior, _lock: lock }
        }
    }
    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    /// Seed a small tree under `home` so the recorder's scan/tick has something
    /// real to measure. We create a `node_modules` directory (matched by the
    /// builtin `**/node_modules` rule) with a couple of files, so the daily
    /// true-up's `scan()` keeps it and emits a `Source::Full` observation.
    fn seed_tree(home: &Path) {
        let nm = home.join("proj").join("node_modules");
        fs::create_dir_all(&nm).unwrap();
        for (name, n) in [("a.bin", 8 * 1024usize), ("b.bin", 16 * 1024)] {
            let mut f = fs::File::create(nm.join(name)).unwrap();
            use std::io::Write as _;
            f.write_all(&vec![b'x'; n]).unwrap();
            f.flush().unwrap();
        }
    }

    /// The recorder appends to `series.jsonl` + `df_series.jsonl` and writes
    /// `tick_state.json`, and a second run reuses the prior state (incremental).
    #[test]
    fn recorder_appends_series_df_and_persists_tick_state() {
        let base = TempBase::new("recorder");
        let home = base.path.clone();
        seed_tree(&home);

        let _guard = HomeGuard::set(&home);

        // `profile::data_dir()` now resolves under the tempdir HOME.
        let data_dir = crate::profile::data_dir();
        let series = data_dir.join("series.jsonl");
        let df_series = data_dir.join("df_series.jsonl");
        let tick_state = data_dir.join("tick_state.json");

        // Nothing recorded yet.
        assert!(!series.exists(), "no series before first tick");
        assert!(!df_series.exists(), "no df_series before first tick");
        assert!(!tick_state.exists(), "no tick_state before first tick");

        // --- First run: default tick state (epoch) → daily true-up (full walk).
        let _ = record_tick(&home, 100 * 1024 * 1024 * 1024, 500 * 1024 * 1024 * 1024);

        assert!(series.exists(), "series.jsonl created on first tick");
        assert!(df_series.exists(), "df_series.jsonl created on first tick");
        assert!(tick_state.exists(), "tick_state.json written on first tick");

        let series_len_1 = fs::read_to_string(&series).unwrap().lines().count();
        let df_len_1 = fs::read_to_string(&df_series).unwrap().lines().count();
        assert!(series_len_1 > 0, "series got at least one observation");
        assert_eq!(df_len_1, 1, "exactly one df sample appended per tick");

        // The first tick was a full true-up: last_full_walk is now (not epoch).
        let state_1 = scanner::load_tick_state();
        let epoch = chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap();
        assert!(
            state_1.last_full_walk > epoch,
            "first tick ran the daily true-up and advanced last_full_walk off the epoch sentinel"
        );

        // --- Second run: reuses prior state → within 24h → incremental path.
        let _ = record_tick(&home, 99 * 1024 * 1024 * 1024, 500 * 1024 * 1024 * 1024);

        let df_len_2 = fs::read_to_string(&df_series).unwrap().lines().count();
        assert_eq!(df_len_2, 2, "second tick appended a second df sample");

        // df_series is append-only — the first sample is still present.
        let df_samples: Vec<crate::core::metrics::DfSample> =
            crate::core::metrics::read_df_series().unwrap();
        assert_eq!(
            df_samples.len(),
            2,
            "both df samples persisted, append-only"
        );
        assert_eq!(df_samples[0].free_bytes, 100 * 1024 * 1024 * 1024);
        assert_eq!(df_samples[1].free_bytes, 99 * 1024 * 1024 * 1024);

        // The second run reused the prior state: it stayed within 24h, so it did
        // NOT run another full walk — last_full_walk is UNCHANGED from run 1.
        let state_2 = scanner::load_tick_state();
        assert_eq!(
            state_2.last_full_walk, state_1.last_full_walk,
            "second tick reused prior state (incremental — no new full walk within 24h)"
        );

        // series.jsonl is append-only: the second tick never truncated it.
        let series_len_2 = fs::read_to_string(&series).unwrap().lines().count();
        assert!(
            series_len_2 >= series_len_1,
            "series.jsonl is append-only across ticks (never truncated)"
        );

        // Every persisted series line parses (no torn/interleaved writes).
        let obs = crate::core::series::read_all().unwrap();
        assert!(
            !obs.is_empty(),
            "series observations round-trip via the store"
        );
    }
}

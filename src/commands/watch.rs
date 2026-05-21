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
    let bin = std::env::current_exe().context("could not resolve diskspace binary path")?;
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
    }
    Ok(())
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
    if !path.exists() {
        return Ok(WatchState::default());
    }
    let s = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&s).unwrap_or_default())
}

fn save_state(state: &WatchState) -> Result<()> {
    let dir = state_dir()?;
    fs::create_dir_all(&dir)?;
    let path = state_file()?;
    let s = serde_json::to_string_pretty(state)?;
    fs::write(&path, s)?;
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

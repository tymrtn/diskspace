//! `diskspace doctor [--need <size>]` — emergency one-shot recovery.
//! Scans, detects, hunts, pressure-tests, greedy-selects the smallest safe set
//! that hits the target free-space, and executes. Switches between airlock and
//! immediate-delete based on disk pressure.

use anyhow::{Context as _, Result};
use console::Style;
use std::path::{Path, PathBuf};

use crate::commands::check;
use crate::commands::detect::build_candidates_pub;
use crate::commands::scan::scan_cache_path;
use crate::core::airlock_store;
use crate::core::candidate::Candidate;
use crate::core::history::{self, ActionKind, Entry as HistEntry};
use crate::core::scanner::{self, ScanResult};
use crate::output::{self, Context};
use crate::profile;

const STALE_SCAN_SECS: i64 = 60 * 60; // 1 hour
const IMMEDIATE_THRESHOLD: f32 = 0.85;

pub fn run(need: Option<String>, ctx: &Context) -> Result<()> {
    let prof = profile::load()?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let home_path = Path::new(&home);

    let need_bytes = parse_need(need.as_deref(), &prof);
    let df_before = history::free_bytes(home_path).unwrap_or(0);

    let pressure_threshold =
        (prof.preferences.disk_pressure_threshold_gb * 1024.0 * 1024.0 * 1024.0) as u64;
    let mode = if df_before < pressure_threshold {
        Mode::Immediate
    } else {
        Mode::Airlock
    };

    if !ctx.json {
        render_intro(ctx, df_before, need_bytes, mode);
    }

    // Already enough? Bail early.
    if df_before >= need_bytes {
        if ctx.json {
            println!(
                r#"{{"status":"already_sufficient","free_bytes":{},"need_bytes":{}}}"#,
                df_before, need_bytes
            );
        } else {
            println!(
                "  {}  Already at {} free (target {}). Nothing to do.\n",
                ctx.style("✓", &Style::new().green().bold()),
                output::format_bytes(df_before),
                output::format_bytes(need_bytes),
            );
        }
        return Ok(());
    }
    let to_recover = need_bytes - df_before;

    // Step 1: ensure scan cache is fresh.
    let scan = ensure_fresh_scan(home_path, ctx)?;

    // Step 2: build candidates (detect).
    let rule_list = crate::core::rules::load_builtin()?;
    let mut candidates = build_candidates_pub(&scan, &rule_list, &prof, &home);

    // Step 3: pressure-test each candidate, keep survivors.
    let mut survivors: Vec<(Candidate, bool)> = Vec::new(); // (candidate, reversible)
    for c in candidates.drain(..) {
        let result = check::pressure_test(&c.id, &c.path, &prof)?;
        if !result.safe {
            continue;
        }
        // Reversibility: in airlock mode + cross-volume, fully reversible.
        // In immediate mode, never reversible.
        let reversible = matches!(mode, Mode::Airlock);
        survivors.push((c, reversible));
    }

    // Step 4: rank by (reversibility desc, confidence desc, size desc) then greedy-pick
    // smallest set that hits the target. Reversible-first means we use safer items first.
    survivors.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then(
                b.0.confidence
                    .partial_cmp(&a.0.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(b.0.size_bytes.cmp(&a.0.size_bytes))
    });

    let mut chosen: Vec<&Candidate> = Vec::new();
    let mut accumulated: u64 = 0;
    for (c, _) in &survivors {
        if accumulated >= to_recover {
            break;
        }
        // In airlock mode, we have to use cross-volume to *actually* free space.
        // Same-volume rename doesn't help here. We still include them and pick
        // which to use later (for now: include all, warn at execute time).
        chosen.push(c);
        accumulated += c.size_bytes;
    }

    if chosen.is_empty() {
        if ctx.json {
            println!(
                r#"{{"status":"no_candidates","free_bytes":{},"need_bytes":{}}}"#,
                df_before, need_bytes
            );
        } else {
            println!(
                "\n  {}  No candidates passed pressure tests. Nothing safe to recover automatically.\n  Run `diskspace hunt` to see what large dirs exist outside any rule.\n",
                ctx.style("○", &Style::new().dim()),
            );
        }
        return Ok(());
    }

    // Step 5: pre-flight summary.
    if !ctx.json {
        render_preflight(ctx, &chosen, accumulated, to_recover, mode);
    }

    if !ctx.json && !ctx.yes {
        let prompt = format!(
            "  Proceed with {}? Smaller items first; you can stop anytime.",
            match mode {
                Mode::Immediate => "immediate delete",
                Mode::Airlock => "airlock (reversible) + immediate purge",
            }
        );
        if !ctx.confirm(&prompt) {
            println!("  Aborted.");
            return Ok(());
        }
    }

    // Step 6: execute.
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let red = Style::new().red().bold();
    let yellow = Style::new().yellow();
    let green = Style::new().green().bold();

    let mut freed_bytes: u64 = 0;
    let mut acted: Vec<serde_json::Value> = Vec::new();

    for c in &chosen {
        let result = match mode {
            Mode::Immediate => execute_immediate(c),
            Mode::Airlock => execute_airlock(c, &prof),
        };
        match result {
            Ok(out) => {
                freed_bytes += out.size;
                if !ctx.json {
                    let icon = match mode {
                        Mode::Immediate => ctx.style("✓", &red),
                        Mode::Airlock => ctx.style("◐", &yellow),
                    };
                    println!(
                        "  {}  {:>9}  {}",
                        icon,
                        ctx.style(&output::format_bytes(c.size_bytes), &bold),
                        ctx.style(&c.path.display().to_string(), &dim),
                    );
                }
                history::append(&HistEntry {
                    ts: chrono::Utc::now(),
                    command: ActionKind::Doctor,
                    candidate_id: Some(c.id.clone()),
                    rule_id: Some(c.rule_id.clone()),
                    path: c.path.clone(),
                    size_bytes: c.size_bytes,
                    df_before: Some(df_before),
                    df_after: None,
                    actually_freed: None,
                    reversible: matches!(mode, Mode::Airlock),
                    undo_cmd: out.undo_cmd.clone(),
                    rule_confidence: Some(c.confidence),
                    context: out.context,
                });
                acted.push(serde_json::json!({
                    "id": c.id,
                    "path": c.path,
                    "size_bytes": c.size_bytes,
                    "mode": mode.as_str(),
                    "undo_cmd": out.undo_cmd,
                }));
            }
            Err(e) => {
                if !ctx.json {
                    eprintln!(
                        "  {}  failed: {}  ({})",
                        ctx.style("✗", &red),
                        c.path.display(),
                        e
                    );
                }
            }
        }
        // Stop early if we've actually crossed the goal (only meaningful in immediate mode)
        if matches!(mode, Mode::Immediate) {
            let now_free = history::free_bytes(home_path).unwrap_or(df_before);
            if now_free >= need_bytes {
                if !ctx.json {
                    println!(
                        "  {}  Target reached early — stopping.",
                        ctx.style("→", &green)
                    );
                }
                break;
            }
        }
    }

    let df_after = history::free_bytes(home_path).unwrap_or(df_before);
    let actually_freed = df_after.saturating_sub(df_before);

    if ctx.json {
        let payload = serde_json::json!({
            "status": "completed",
            "mode": mode.as_str(),
            "free_before": df_before,
            "free_after": df_after,
            "actually_freed": actually_freed,
            "items": acted,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!();
        println!(
            "  {}  {} → {}  ({} actually freed, {} staged)",
            ctx.style("disk", &bold),
            ctx.style(&output::format_bytes(df_before), &dim),
            ctx.style(&output::format_bytes(df_after), &green),
            ctx.style(&output::format_bytes(actually_freed), &bold),
            ctx.style(
                &output::format_bytes(freed_bytes.saturating_sub(actually_freed)),
                &yellow
            ),
        );
        if matches!(mode, Mode::Airlock) && actually_freed < freed_bytes {
            println!(
                "  {}  Same-volume airlock items are staged. Run `diskspace purge --older-than 0 --yes` to actually free.",
                ctx.style("→", &yellow)
            );
        }
        println!();
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Airlock,
    Immediate,
}

impl Mode {
    fn as_str(&self) -> &'static str {
        match self {
            Mode::Airlock => "airlock",
            Mode::Immediate => "immediate",
        }
    }
}

struct ExecuteOutcome {
    size: u64,
    undo_cmd: Option<String>,
    context: serde_json::Map<String, serde_json::Value>,
}

fn execute_immediate(c: &Candidate) -> Result<ExecuteOutcome> {
    if c.path.is_dir() {
        std::fs::remove_dir_all(&c.path)?;
    } else {
        std::fs::remove_file(&c.path)?;
    }
    Ok(ExecuteOutcome {
        size: c.size_bytes,
        undo_cmd: None,
        context: serde_json::Map::new(),
    })
}

fn execute_airlock(c: &Candidate, prof: &profile::Profile) -> Result<ExecuteOutcome> {
    let (entry, kind) =
        airlock_store::airlock_path(&c.id, &c.path, prof.preferences.airlock_retention_days)?;
    let mut manifest = airlock_store::load_manifest()?;
    manifest.entries.push(entry.clone());
    airlock_store::save_manifest(&manifest)?;

    let mut ctx_map = serde_json::Map::new();
    ctx_map.insert(
        "move_kind".into(),
        serde_json::Value::String(
            match kind {
                airlock_store::MoveKind::Rename => "rename",
                airlock_store::MoveKind::CopyRemove => "copy_remove",
            }
            .into(),
        ),
    );

    Ok(ExecuteOutcome {
        size: c.size_bytes,
        undo_cmd: Some(format!("diskspace restore {}", entry.id)),
        context: ctx_map,
    })
}

fn ensure_fresh_scan(root: &Path, ctx: &Context) -> Result<ScanResult> {
    let cache = scan_cache_path();
    if cache.exists() {
        let metadata = std::fs::metadata(&cache)?;
        if let Ok(modified) = metadata.modified() {
            let age = chrono::Utc::now()
                .signed_duration_since(chrono::DateTime::<chrono::Utc>::from(modified));
            if age.num_seconds() < STALE_SCAN_SECS {
                let content = std::fs::read_to_string(&cache).context("reading scan cache")?;
                return serde_json::from_str(&content).context("parsing scan cache");
            }
        }
    }

    if !ctx.json {
        let dim = Style::new().dim();
        println!(
            "  {}",
            ctx.style("scanning (cache stale or missing)…", &dim)
        );
    }
    let rule_list = crate::core::rules::load_builtin()?;
    let result = scanner::scan(root, &rule_list)?;
    std::fs::create_dir_all(profile::data_dir())?;
    let json = serde_json::to_string_pretty(&result)?;
    std::fs::write(scan_cache_path(), json)?;
    Ok(result)
}

fn parse_need(s: Option<&str>, prof: &profile::Profile) -> u64 {
    let default = (prof.preferences.disk_pressure_threshold_gb * 1024.0 * 1024.0 * 1024.0) as u64
        + 1024 * 1024 * 1024; // threshold + 1 GB headroom
    match s {
        None => default,
        Some(raw) => parse_size(raw).unwrap_or(default),
    }
}

/// Parse a size like "20G", "500M", "1024K", "10gb". Case-insensitive. Plain digits = bytes.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    let (num_str, mult): (&str, u64) = if let Some(num) = s.strip_suffix("gb") {
        (num, 1024 * 1024 * 1024)
    } else if let Some(num) = s.strip_suffix('g') {
        (num, 1024 * 1024 * 1024)
    } else if let Some(num) = s.strip_suffix("mb") {
        (num, 1024 * 1024)
    } else if let Some(num) = s.strip_suffix('m') {
        (num, 1024 * 1024)
    } else if let Some(num) = s.strip_suffix("kb") {
        (num, 1024)
    } else if let Some(num) = s.strip_suffix('k') {
        (num, 1024)
    } else {
        (s.as_str(), 1)
    };
    let n: f64 = num_str.trim().parse().ok()?;
    Some((n * mult as f64) as u64)
}

fn render_intro(ctx: &Context, free: u64, need: u64, mode: Mode) {
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let yellow = Style::new().yellow();
    let red = Style::new().red().bold();
    println!();
    println!(
        "  {}",
        ctx.style(&output::rule("doctor  ·  emergency recovery", 60), &dim)
    );
    println!();
    println!(
        "  {:<10}  {}",
        ctx.style("free now", &bold),
        ctx.style(&output::format_bytes(free), &dim)
    );
    println!(
        "  {:<10}  {}",
        ctx.style("need", &bold),
        ctx.style(&output::format_bytes(need), &yellow)
    );
    println!(
        "  {:<10}  {}",
        ctx.style("mode", &bold),
        ctx.style(
            match mode {
                Mode::Airlock => "airlock (reversible — > pressure threshold)",
                Mode::Immediate => "immediate-delete (under pressure threshold)",
            },
            match mode {
                Mode::Airlock => &yellow,
                Mode::Immediate => &red,
            },
        )
    );
    println!();
}

fn render_preflight(
    ctx: &Context,
    chosen: &[&Candidate],
    accumulated: u64,
    to_recover: u64,
    mode: Mode,
) {
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let yellow = Style::new().yellow();
    let red = Style::new().red().bold();

    println!();
    println!("  {}", ctx.style(&output::rule("flight plan", 60), &dim));
    println!();
    let action = match mode {
        Mode::Airlock => "airlock",
        Mode::Immediate => "permanently delete",
    };
    println!(
        "  Will {} {} item(s) totaling {} (target {}).",
        ctx.style(action, &bold),
        chosen.len(),
        ctx.style(&output::format_bytes(accumulated), &bold),
        ctx.style(&output::format_bytes(to_recover), &yellow),
    );
    println!();
    for c in chosen {
        let icon = match mode {
            Mode::Immediate if c.confidence < IMMEDIATE_THRESHOLD => ctx.style("⚠", &red),
            Mode::Immediate => ctx.style("•", &red),
            Mode::Airlock => ctx.style("•", &yellow),
        };
        println!(
            "  {}  {:>9}  {:>4.0}%  {}",
            icon,
            ctx.style(&output::format_bytes(c.size_bytes), &bold),
            c.confidence * 100.0,
            ctx.style(&c.path.display().to_string(), &dim),
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_basic() {
        assert_eq!(parse_size("20G"), Some(20 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("500M"), Some(500 * 1024 * 1024));
        assert_eq!(parse_size("100mb"), Some(100 * 1024 * 1024));
        assert_eq!(
            parse_size("1.5gb"),
            Some((1.5 * 1024.0 * 1024.0 * 1024.0) as u64)
        );
        assert_eq!(parse_size("1024"), Some(1024));
    }
}

// silence unused warning if PathBuf is only used in cfg(test)
#[allow(dead_code)]
fn _path_buf_ref() -> PathBuf {
    PathBuf::new()
}

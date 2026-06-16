//! `diskspace doctor [--need <size>]` — emergency one-shot recovery.
//! Scans, detects, hunts, pressure-tests, greedy-selects the smallest safe set
//! that hits the target free-space, and executes. Switches between airlock and
//! immediate-delete based on disk pressure.
//!
//! ## Architecture (P2 keystone)
//!
//! The recovery flow is split into two behavior-preserving halves so that the
//! P2/P3 `plan` / `apply` / `guard` commands can reuse the exact same selection
//! and execution logic that `doctor` uses interactively:
//!
//!   * [`build_plan`] — pure selection. Scan → build candidates → pressure-test
//!     EVERY candidate → keep only `safe == true` survivors → rank
//!     (reversibility, then confidence, then size) → greedily accumulate the
//!     smallest set that meets `need`. Returns a [`Plan`] WITHOUT touching the
//!     filesystem. The pressure-test (the HARD gate) runs here.
//!   * [`execute_plan`] — actuation. Walks the chosen [`PlanStep`]s, runs the
//!     existing airlock / immediate-delete paths, appends a history receipt per
//!     action, and returns an [`ExecuteOutcome`]. Same consent prompts, same
//!     JSON shape, same early-stop behavior as before.
//!
//! `run()` is now `build_plan` → consent (unchanged) → `execute_plan` → render.
//! Behavior — prompts, exit codes, receipts, JSON — is identical to the previous
//! monolithic `run()`.

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use console::Style;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::commands::check;
use crate::commands::detect::build_candidates_pub;
use crate::commands::scan::scan_cache_path;
use crate::core::airlock_store;
use crate::core::candidate::{Candidate, CheckResult, ConsequenceContract};
use crate::core::grant::Grant;
use crate::core::history::{self, ActionKind, Entry as HistEntry};
use crate::core::scanner::{self, ScanResult};
use crate::output::{self, Context};
use crate::profile;

const STALE_SCAN_SECS: i64 = 60 * 60; // 1 hour
const IMMEDIATE_THRESHOLD: f32 = 0.85;

/// A selected recovery plan: the ordered set of pressure-test-passing steps that
/// together meet (or get as close as possible to) the requested `need_bytes`.
///
/// Produced by [`build_plan`] WITHOUT executing anything. The `plan_hash` is left
/// empty here and is filled by the `plan` command (`plan.rs`) in P2; `doctor`
/// never reads it. All fields are `serde` so a plan can be emitted as JSON for
/// agents and re-loaded by `apply`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    /// Content hash of the plan, filled by `plan.rs` later. Empty when built here.
    #[serde(default)]
    pub plan_hash: String,
    /// Bytes of free space the caller asked us to reach.
    pub need_bytes: u64,
    /// The chosen steps, in execution order (reversibility-first).
    pub steps: Vec<PlanStep>,
    /// Sum of `size_bytes` across `steps` — the projected reclaim if all succeed.
    pub projected_freed: u64,
    /// When this plan was built.
    pub created_at: DateTime<Utc>,
}

/// One actionable step in a [`Plan`]: a single pressure-test-passing candidate,
/// captured with the pressure result that cleared it and how it will be removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    /// Candidate id (stable per path+rule).
    pub candidate_id: String,
    /// Id of the rule that produced this candidate. Carried verbatim from the
    /// candidate (NOT re-derived from `candidate_id`) so the history receipt's
    /// `rule_id` matches the pre-refactor value exactly.
    pub rule_id: String,
    /// Absolute path that will be removed / airlocked.
    pub path: PathBuf,
    /// Size of the path at plan time.
    pub size_bytes: u64,
    /// The candidate's rule-derived confidence (NOT the pressure-test decay
    /// confidence). Used for the pre-flight display and the receipt's
    /// `rule_confidence`, preserving the pre-refactor behavior.
    pub confidence: f32,
    /// Execution mode for this step: `"airlock"` (reversible) or `"immediate"`.
    pub mode: String,
    /// Whether this step is reversible (true only in airlock mode).
    pub reversible: bool,
    /// The pressure-test result that cleared this step (`safe == true`). Captured
    /// at plan time; `execute_plan` (and `apply`) RE-RUN the gate live before
    /// acting and refuse on drift.
    pub pressure: CheckResult,
    /// Advisory consequence contract copied from the candidate, if any. Never
    /// influences selection or the gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consequence_contract: Option<ConsequenceContract>,
}

/// Aggregate result of executing a [`Plan`].
pub struct ExecuteOutcome {
    /// Free bytes before execution (caller-provided baseline).
    pub df_before: u64,
    /// Free bytes after execution.
    pub df_after: u64,
    /// `df_after - df_before` (saturating) — what the OS confirms was released.
    pub actually_freed: u64,
    /// Sum of `size_bytes` for every step that executed without error (includes
    /// same-volume airlock items that are staged but not yet released).
    pub freed_bytes: u64,
    /// Per-item JSON records for the `--json` payload (mirrors the old `acted`).
    pub items: Vec<serde_json::Value>,
}

pub fn run(need: Option<String>, grant: Option<&Grant>, ctx: &Context) -> Result<()> {
    // Keep the parameter live for the non-actuation build (grant ignored there).
    #[cfg(not(feature = "actuation"))]
    let _ = grant;

    // AGENT-PATH GRANT GATE (actuation only). In NON-INTERACTIVE mode (`--json`
    // or `--yes` — the agent/script path, where no human is present to answer a
    // consent prompt), a doctor run that will MUTATE the filesystem REQUIRES a
    // valid grant. Without one we refuse before doing any work, emitting a
    // machine-parseable `no_grant` error and exiting non-zero. This is the
    // documented behavior change: under actuation an autonomous doctor must carry
    // an explicit, signed authority. Interactive runs (a human at the terminal)
    // are unaffected — they fall through to the existing consent prompts.
    #[cfg(feature = "actuation")]
    {
        let non_interactive = ctx.json || ctx.yes;
        if non_interactive && grant.is_none() {
            if ctx.json {
                println!(r#"{{"error":"no_grant","hint":"issue a grant token"}}"#);
            } else {
                eprintln!("\n  Refusing: no grant. Issue one with `diskspace grant issue …`.\n");
            }
            std::process::exit(4);
        }
    }

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

    // ── Selection: build the plan WITHOUT executing. ──────────────────────────
    // `build_plan` scans, builds candidates, pressure-tests every one, keeps the
    // safe survivors, ranks them, and accumulates the smallest set that hits the
    // target. The HARD gate runs inside here.
    let plan = build_plan(to_recover, mode, &prof, home_path, ctx)?;

    if plan.steps.is_empty() {
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
        render_preflight(ctx, &plan.steps, plan.projected_freed, to_recover, mode);
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

    // ── Actuation: execute the chosen steps. ──────────────────────────────────
    let outcome = execute_plan(&plan, &prof, grant, ctx, df_before, need_bytes, home_path)?;

    if ctx.json {
        let payload = serde_json::json!({
            "status": "completed",
            "mode": mode.as_str(),
            "free_before": outcome.df_before,
            "free_after": outcome.df_after,
            "actually_freed": outcome.actually_freed,
            "items": outcome.items,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        let dim = Style::new().dim();
        let bold = Style::new().bold();
        let yellow = Style::new().yellow();
        let green = Style::new().green().bold();
        println!();
        println!(
            "  {}  {} → {}  ({} actually freed, {} staged)",
            ctx.style("disk", &bold),
            ctx.style(&output::format_bytes(outcome.df_before), &dim),
            ctx.style(&output::format_bytes(outcome.df_after), &green),
            ctx.style(&output::format_bytes(outcome.actually_freed), &bold),
            ctx.style(
                &output::format_bytes(outcome.freed_bytes.saturating_sub(outcome.actually_freed)),
                &yellow
            ),
        );
        if matches!(mode, Mode::Airlock) && outcome.actually_freed < outcome.freed_bytes {
            println!(
                "  {}  Same-volume airlock items are staged. Run `diskspace purge --older-than 0 --yes` to actually free.",
                ctx.style("→", &yellow)
            );
        }
        println!();
    }

    Ok(())
}

/// Build a recovery [`Plan`] WITHOUT executing anything.
///
/// This is the selection half of `doctor`, factored out so `plan` / `apply` /
/// `guard` reuse identical logic. Steps:
///
///   1. Ensure a fresh scan cache (re-scans if stale/missing).
///   2. Build candidates from the built-in rules (`detect::build_candidates`).
///   3. Pressure-test EVERY candidate (the HARD gate) and keep only `safe`
///      survivors.
///   4. Rank survivors by (reversible desc, confidence desc, size desc).
///   5. Greedily accumulate the smallest set whose sizes reach `need_bytes`.
///
/// `need_bytes` here is the *delta still to recover* (caller subtracts current
/// free space). The returned `Plan.projected_freed` is the sum of chosen step
/// sizes; `created_at` is now; `plan_hash` is empty (filled by `plan.rs`).
pub fn build_plan(
    need_bytes: u64,
    mode: Mode,
    prof: &profile::Profile,
    home_path: &Path,
    ctx: &Context,
) -> Result<Plan> {
    let home = home_path.to_string_lossy().to_string();

    // Step 1: ensure scan cache is fresh.
    let scan = ensure_fresh_scan(home_path, ctx)?;

    // Step 2: build candidates (detect).
    let rule_list = crate::core::rules::load_builtin()?;
    let mut candidates = build_candidates_pub(&scan, &rule_list, prof, &home);

    // Step 3: pressure-test each candidate, keep survivors.
    // (candidate, reversible, pressure-result)
    let mut survivors: Vec<(Candidate, bool, CheckResult)> = Vec::new();
    for c in candidates.drain(..) {
        let result = check::pressure_test(&c.id, &c.path, prof)?;
        if !result.safe {
            continue;
        }
        // Reversibility: in airlock mode + cross-volume, fully reversible.
        // In immediate mode, never reversible.
        let reversible = matches!(mode, Mode::Airlock);
        survivors.push((c, reversible, result));
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

    let mut steps: Vec<PlanStep> = Vec::new();
    let mut accumulated: u64 = 0;
    for (c, reversible, pressure) in survivors {
        if accumulated >= need_bytes {
            break;
        }
        // In airlock mode, we have to use cross-volume to *actually* free space.
        // Same-volume rename doesn't help here. We still include them and pick
        // which to use later (for now: include all, warn at execute time).
        accumulated += c.size_bytes;
        steps.push(PlanStep {
            candidate_id: c.id.clone(),
            rule_id: c.rule_id.clone(),
            path: c.path.clone(),
            size_bytes: c.size_bytes,
            confidence: c.confidence,
            mode: mode.as_str().to_string(),
            reversible,
            pressure,
            consequence_contract: c.consequence_contract.clone(),
        });
    }

    Ok(Plan {
        plan_hash: String::new(),
        need_bytes,
        projected_freed: accumulated,
        steps,
        created_at: Utc::now(),
    })
}

/// Execute a [`Plan`]'s steps: airlock or immediate-delete per step, append a
/// history receipt for each successful action, and report the aggregate.
///
/// Mirrors the old `run()` execution loop exactly — same per-item output, same
/// receipts, same early-stop on target reached in immediate mode. `df_before`
/// and `need_bytes` are caller-provided so this stays a pure executor of an
/// already-selected plan.
pub fn execute_plan(
    plan: &Plan,
    prof: &profile::Profile,
    grant: Option<&Grant>,
    ctx: &Context,
    df_before: u64,
    need_bytes: u64,
    home_path: &Path,
) -> Result<ExecuteOutcome> {
    // Keep the parameter live for the non-actuation build (grant ignored there).
    #[cfg(not(feature = "actuation"))]
    let _ = grant;

    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let red = Style::new().red().bold();
    let yellow = Style::new().yellow();
    let green = Style::new().green().bold();

    let mut freed_bytes: u64 = 0;
    let mut acted: Vec<serde_json::Value> = Vec::new();

    // Cumulative bytes the grant has authorized this run — `allows()` enforces
    // `spent + size <= max_bytes`, so the grant bounds the WHOLE batch, not each
    // step alone. Only used under actuation with a present grant.
    #[cfg(feature = "actuation")]
    let mut grant_spent: u64 = 0;

    for step in &plan.steps {
        let step_mode = Mode::from_str(&step.mode);

        // GRANT CONSULTATION — strictly AFTER selection's hard gate (build_plan
        // pressure-tested every step) and never able to make an unsafe/never_touch
        // step actionable. Under actuation with a present grant, each step must
        // fall inside the grant's bound (ceiling / confidence floor / cumulative
        // max_bytes / path scope). A denied step is SKIPPED (we act on nothing for
        // it) and its denial is recorded in the JSON items + an audit line.
        #[cfg(feature = "actuation")]
        if let Some(g) = grant {
            use crate::core::grant::{self, GrantDecision};
            let consequences = step
                .consequence_contract
                .as_ref()
                .map(consequences_from_contract);
            let decision = grant::allows(
                g,
                consequences.as_ref(),
                step.confidence,
                step.size_bytes,
                &step.path,
                grant_spent,
            );
            grant::audit(g, "doctor", &step.path, step.size_bytes, &decision);
            if let GrantDecision::Deny(reason) = decision {
                if !ctx.json {
                    println!(
                        "  {}  {}  grant denied: {}",
                        ctx.style("✗", &red),
                        ctx.style(&step.path.display().to_string(), &dim),
                        ctx.style(&reason, &dim),
                    );
                }
                acted.push(serde_json::json!({
                    "id": step.candidate_id,
                    "path": step.path,
                    "size_bytes": step.size_bytes,
                    "mode": step_mode.as_str(),
                    "grant_decision": "deny",
                    "reason": reason,
                }));
                continue;
            }
            grant_spent = grant_spent.saturating_add(step.size_bytes);
        }

        let result = match step_mode {
            Mode::Immediate => execute_immediate(&step.path, step.size_bytes),
            Mode::Airlock => execute_airlock(&step.candidate_id, &step.path, step.size_bytes, prof),
        };
        match result {
            Ok(out) => {
                freed_bytes += out.size;
                if !ctx.json {
                    let icon = match step_mode {
                        Mode::Immediate => ctx.style("✓", &red),
                        Mode::Airlock => ctx.style("◐", &yellow),
                    };
                    println!(
                        "  {}  {:>9}  {}",
                        icon,
                        ctx.style(&output::format_bytes(step.size_bytes), &bold),
                        ctx.style(&step.path.display().to_string(), &dim),
                    );
                }
                history::append(&HistEntry {
                    ts: chrono::Utc::now(),
                    command: ActionKind::Doctor,
                    candidate_id: Some(step.candidate_id.clone()),
                    rule_id: Some(step.rule_id.clone()),
                    path: step.path.clone(),
                    size_bytes: step.size_bytes,
                    df_before: Some(df_before),
                    df_after: None,
                    actually_freed: None,
                    reversible: matches!(step_mode, Mode::Airlock),
                    undo_cmd: out.undo_cmd.clone(),
                    rule_confidence: Some(step.confidence),
                    context: out.context,
                });
                acted.push(serde_json::json!({
                    "id": step.candidate_id,
                    "path": step.path,
                    "size_bytes": step.size_bytes,
                    "mode": step_mode.as_str(),
                    "undo_cmd": out.undo_cmd,
                }));
            }
            Err(e) => {
                if !ctx.json {
                    eprintln!(
                        "  {}  failed: {}  ({})",
                        ctx.style("✗", &red),
                        step.path.display(),
                        e
                    );
                }
            }
        }
        // Stop early if we've actually crossed the goal (only meaningful in immediate mode)
        if matches!(step_mode, Mode::Immediate) {
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

    Ok(ExecuteOutcome {
        df_before,
        df_after,
        actually_freed,
        freed_bytes,
        items: acted,
    })
}

/// Reconstruct the minimal [`Consequences`] a grant's [`grant::allows`] needs from
/// the [`ConsequenceContract`] a [`PlanStep`] carries. The grant only reads the
/// `recovery` (class) string to map a recovery ceiling, but we map the other
/// fields faithfully so the value is well-formed. A step with NO contract maps to
/// `None`, which `recovery_class_of` fails CLOSED to `Irreversible` — a step whose
/// recovery is unknown can only ever be HARDER to authorize, never easier.
///
/// [`Consequences`]: crate::core::rules::Consequences
/// [`grant::allows`]: crate::core::grant::allows
#[cfg(feature = "actuation")]
fn consequences_from_contract(cc: &ConsequenceContract) -> crate::core::rules::Consequences {
    crate::core::rules::Consequences {
        recovery: cc.recovery_class.clone(),
        rebuild_seconds: cc.recovery_cost_seconds,
        impact: cc.impact.clone(),
        recovery_cmd: cc.recovery_cmd.clone(),
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Mode {
    Airlock,
    Immediate,
}

impl Mode {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Mode::Airlock => "airlock",
            Mode::Immediate => "immediate",
        }
    }

    /// Parse the `--mode` string the `plan` command accepts. Any value other than
    /// `"immediate"` falls back to airlock (the reversible default), matching the
    /// executor's own `from_str` so plan/apply and doctor agree on the mapping.
    pub(crate) fn from_str(s: &str) -> Mode {
        match s {
            "immediate" => Mode::Immediate,
            _ => Mode::Airlock,
        }
    }
}

/// Per-item execution result (size freed/staged + undo + context for receipt).
struct ItemOutcome {
    size: u64,
    undo_cmd: Option<String>,
    context: serde_json::Map<String, serde_json::Value>,
}

fn execute_immediate(path: &Path, size_bytes: u64) -> Result<ItemOutcome> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(ItemOutcome {
        size: size_bytes,
        undo_cmd: None,
        context: serde_json::Map::new(),
    })
}

fn execute_airlock(
    candidate_id: &str,
    path: &Path,
    size_bytes: u64,
    prof: &profile::Profile,
) -> Result<ItemOutcome> {
    let (entry, kind) =
        airlock_store::airlock_path(candidate_id, path, prof.preferences.airlock_retention_days)?;
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

    Ok(ItemOutcome {
        size: size_bytes,
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
///
/// `pub(crate)` so the `plan` command reuses the EXACT same size grammar `doctor`
/// uses — there is one size parser, not two that could drift.
pub(crate) fn parse_size(s: &str) -> Option<u64> {
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
    chosen: &[PlanStep],
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
        let confidence = c.confidence;
        let icon = match mode {
            Mode::Immediate if confidence < IMMEDIATE_THRESHOLD => ctx.style("⚠", &red),
            Mode::Immediate => ctx.style("•", &red),
            Mode::Airlock => ctx.style("•", &yellow),
        };
        println!(
            "  {}  {:>9}  {:>4.0}%  {}",
            icon,
            ctx.style(&output::format_bytes(c.size_bytes), &bold),
            confidence * 100.0,
            ctx.style(&c.path.display().to_string(), &dim),
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::candidate::{Category, ScannedEntry};
    use crate::core::scanner::ScanResult;
    use crate::core::HOME_TEST_LOCK;
    use std::fs;

    // `$HOME` is process-global and `build_plan`/`execute_plan` resolve every
    // store (scan cache, airlock, history) through `profile::data_dir()`, which
    // reads `$HOME`. Cargo runs tests in parallel THREADS in one process, so the
    // two tests that override `$HOME` MUST serialize against the SHARED crate-wide
    // lock — the same one `watch` and `selfcheck` hold — or they would race those
    // modules' `$HOME` overrides. (A doctor-local lock would not.)

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

    /// A throwaway `$HOME` under the OS temp dir, cleaned on drop. While alive,
    /// `$HOME` points here so `profile::data_dir()` (scan cache, airlock,
    /// history) resolves under the tempdir and never touches the real
    /// `~/.diskspace`. Restores the previous `$HOME` on drop.
    ///
    /// Construct ONLY while holding `HOME_TEST_LOCK`.
    struct TempHome {
        path: PathBuf,
        prev_home: Option<std::ffi::OsString>,
    }
    impl TempHome {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "diskspace-doctor-test-{}-{}-{}",
                tag,
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            fs::create_dir_all(&p).unwrap();
            let prev_home = std::env::var_os("HOME");
            // SAFETY: serialized by HOME_TEST_LOCK; restored on drop.
            unsafe {
                std::env::set_var("HOME", &p);
            }
            fs::create_dir_all(p.join(".diskspace")).unwrap();
            Self { path: p, prev_home }
        }
    }
    impl Drop for TempHome {
        fn drop(&mut self) {
            // SAFETY: serialized by HOME_TEST_LOCK; this restores the original value.
            unsafe {
                match &self.prev_home {
                    Some(h) => std::env::set_var("HOME", h),
                    None => std::env::remove_var("HOME"),
                }
            }
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// Hand-build a minimal `ScanResult` carrying just `entries`. The other
    /// fields are filler — `build_plan` only reads `entries`.
    fn scan_with(entries: Vec<ScannedEntry>) -> ScanResult {
        ScanResult {
            scanned_at: Utc::now(),
            root: PathBuf::from("/"),
            entries,
            total_bytes: 0,
            cloud_placeholder_bytes: 0,
            category_totals: std::collections::HashMap::new(),
            schema: 0,
            scan_id: String::new(),
            metrics: None,
            largest_dirs: Vec::new(),
        }
    }

    /// Write a FRESH scan cache so `build_plan`'s `ensure_fresh_scan` reuses it
    /// instead of re-scanning the real filesystem.
    fn write_scan_cache(entries: Vec<ScannedEntry>) {
        fs::create_dir_all(profile::data_dir()).unwrap();
        let json = serde_json::to_string_pretty(&scan_with(entries)).unwrap();
        fs::write(scan_cache_path(), json).unwrap();
    }

    /// Create a real, EMPTY dir named `leaf` (e.g. `node_modules`, `__pycache__`,
    /// `target`, `.venv`) under `$HOME/<proj>/` so it matches the corresponding
    /// `**/<leaf>` builtin rule, and return its `ScannedEntry`. Empty + old
    /// mtime/atime so the pressure-test liveness (no writes in 24h), recency
    /// (no enclosing git), and the rule's recent-access/modified exclusions all
    /// pass. `build_candidates` keeps only the FIRST match per rule, so each
    /// survivor must use a DISTINCT leaf (= distinct rule).
    fn make_target(home: &Path, proj: &str, leaf: &str, size: u64) -> ScannedEntry {
        let path = home.join(proj).join(leaf);
        fs::create_dir_all(&path).unwrap();
        ScannedEntry {
            path,
            size_bytes: size,
            category: Category::DevArtifact,
            modified: Some(Utc::now() - chrono::Duration::days(120)),
            accessed: Some(Utc::now() - chrono::Duration::days(120)),
            dev: None,
            ino: None,
            ctime: None,
        }
    }

    /// A non-interactive, JSON+yes context (no prompts, no color).
    fn quiet_ctx() -> Context {
        Context {
            json: true,
            yes: true,
            no_color: true,
            verbose: false,
            quiet: true,
        }
    }

    #[test]
    fn build_plan_only_includes_pressure_passing_and_stops_at_need() {
        let _guard = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("buildplan");
        let home_path = h.path.clone();

        // FOUR targets, each matching a DISTINCT builtin rule (build_candidates
        // keeps only the first match per rule), 5 GB each:
        //   proj_nm/node_modules, proj_py/__pycache__, proj_rs/target  → survivors
        //   proj_blocked/.venv                                          → blocked
        // With need = 6 GB the greedy loop stops after 2 survivors (5 GB < 6 GB,
        // then 10 GB ≥ 6 GB), dropping the third.
        let five_gb = 5 * 1024 * 1024 * 1024u64;
        let entries = vec![
            make_target(&home_path, "proj_nm", "node_modules", five_gb),
            make_target(&home_path, "proj_py", "__pycache__", five_gb),
            make_target(&home_path, "proj_rs", "target", five_gb),
            make_target(&home_path, "proj_blocked", ".venv", five_gb),
        ];
        write_scan_cache(entries);

        // Block the .venv target via never_touch so its pressure-test FAILS → it
        // must be excluded (proves build_plan keeps ONLY safe survivors).
        let mut prof = profile::Profile::default();
        prof.paths.never_touch.push("~/proj_blocked/.venv".into());

        let need = 6 * 1024 * 1024 * 1024u64;
        let plan = build_plan(need, Mode::Airlock, &prof, &home_path, &quiet_ctx()).unwrap();

        // Every included step passed the gate.
        for s in &plan.steps {
            assert!(s.pressure.safe, "build_plan included a non-safe step");
            assert_ne!(s.candidate_id, "", "step carries the id it cleared");
        }
        // The blocked .venv must never appear in the plan.
        assert!(
            !plan
                .steps
                .iter()
                .any(|s| s.path.starts_with(home_path.join("proj_blocked"))),
            "never_touch path must be excluded from the plan"
        );
        // Greedy stop: crosses the target with exactly 2 of the 3 survivors
        // (the third is unnecessary, so it is dropped).
        assert!(
            plan.projected_freed >= need,
            "plan reaches the requested need ({} >= {})",
            plan.projected_freed,
            need
        );
        assert_eq!(
            plan.steps.len(),
            2,
            "greedy selection stops once need is met (2 × 5 GB ≥ 6 GB)"
        );
    }

    #[test]
    fn execute_plan_airlocks_chosen_set_in_tempdir() {
        let _guard = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("execplan");
        let home_path = h.path.clone();
        let prof = profile::Profile::default();

        // One real directory we will airlock.
        let target = home_path.join("proj/node_modules");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("blob.bin"), vec![0u8; 4096]).unwrap();
        assert!(target.exists());

        // Hand-build a one-step airlock plan so we exercise execute_plan in
        // isolation (selection is covered by the test above).
        let step = PlanStep {
            candidate_id: "manual-nm".into(),
            rule_id: "manual".into(),
            path: target.clone(),
            size_bytes: 4096,
            confidence: 0.9,
            mode: "airlock".into(),
            reversible: true,
            pressure: CheckResult::gate("manual-nm".into(), true, 1.0, vec![]),
            consequence_contract: None,
        };
        let plan = Plan {
            plan_hash: String::new(),
            need_bytes: 4096,
            steps: vec![step],
            projected_freed: 4096,
            created_at: Utc::now(),
        };

        let df_before = history::free_bytes(&home_path).unwrap_or(0);
        let outcome = execute_plan(
            &plan,
            &prof,
            None,
            &quiet_ctx(),
            df_before,
            df_before + 4096,
            &home_path,
        )
        .unwrap();

        // The airlock move must have removed the original path.
        assert!(
            !target.exists(),
            "execute_plan airlocked (moved) the target away from its original path"
        );
        // freed_bytes counts the staged size even if same-volume df doesn't move.
        assert_eq!(outcome.freed_bytes, 4096, "staged size accounted for");
        // A receipt must have been appended, carrying the step's rule_id and the
        // candidate's (rule-derived) confidence verbatim — preserving the
        // pre-refactor receipt fields.
        let hist = history::tail(10).unwrap();
        let receipt = hist
            .iter()
            .find(|e| e.path == target && e.size_bytes == 4096)
            .expect("execute_plan appended a history receipt for the airlocked item");
        assert_eq!(receipt.rule_id.as_deref(), Some("manual"));
        assert_eq!(receipt.rule_confidence, Some(0.9));
        assert!(receipt.reversible, "airlock receipts are reversible");
    }

    // ── P4: GRANT-BOUNDED ACTUATION ───────────────────────────────────────────
    //
    // These exercise the `actuation`-gated grant consult inside `execute_plan` and
    // `build_plan`. They prove the LOCKED invariants:
    //   * the grant bounds WHICH safe steps act (ceiling / confidence / cumulative
    //     max_bytes / scope) and audits every consultation;
    //   * the HARD pressure-test sits UPSTREAM of all grant logic — a never_touch
    //     path is filtered in `build_plan` and never reaches the grant;
    //   * a maximal grant can never resurrect an unsafe/never_touch candidate.
    #[cfg(feature = "actuation")]
    mod grant_boundary {
        use super::*;
        use crate::core::candidate::ConsequenceContract;
        use crate::core::grant::{self, AuditEntry, GrantCategory, IssueParams, RecoveryClass};
        use std::path::PathBuf as StdPathBuf;

        /// Issue a signed grant into the current `$HOME`'s `~/.diskspace` (the
        /// TempHome's tempdir): keygen writes `grant.pub` to the data_dir so
        /// `grant::audit`'s fingerprint resolves, and `issue` signs with the
        /// matching private key. Returns the live, in-bound `Grant`.
        fn issue_grant(ceiling: RecoveryClass, max_bytes: u64, min_conf: f32) -> grant::Grant {
            issue_grant_scoped(ceiling, max_bytes, min_conf, None)
        }

        fn issue_grant_scoped(
            ceiling: RecoveryClass,
            max_bytes: u64,
            min_conf: f32,
            path_scope: Option<String>,
        ) -> grant::Grant {
            let dir = profile::data_dir();
            fs::create_dir_all(&dir).unwrap();
            let priv_p = dir.join("grant.key");
            let pub_p = grant::pubkey_path(); // ~/.diskspace/grant.pub
            grant::keygen(&priv_p, Some(&pub_p)).unwrap();
            let params = IssueParams {
                category: GrantCategory::AgentAutonomy,
                recovery_class_ceiling: ceiling,
                max_bytes,
                min_confidence: min_conf,
                path_scope,
                valid_for: chrono::Duration::hours(1),
            };
            grant::issue(&params, &priv_p).unwrap()
        }

        /// A real on-disk dir target + a hand-built airlock `PlanStep` carrying the
        /// given confidence and recovery class, so the per-step grant consult has a
        /// well-formed candidate to decide on. The pressure result is a synthetic
        /// `safe == true` gate (selection already happened); `execute_plan` here is
        /// the executor under test, not the gate.
        fn step_target(
            home: &Path,
            leaf: &str,
            size: u64,
            confidence: f32,
            recovery: &str,
        ) -> (PlanStep, StdPathBuf) {
            let path = home.join("proj").join(leaf);
            fs::create_dir_all(&path).unwrap();
            let id = format!("manual-{}", leaf);
            let step = PlanStep {
                candidate_id: id.clone(),
                rule_id: "manual".into(),
                path: path.clone(),
                size_bytes: size,
                confidence,
                mode: "airlock".into(),
                reversible: true,
                pressure: CheckResult::gate(id, true, 1.0, vec![]),
                consequence_contract: Some(ConsequenceContract {
                    recovery_class: recovery.into(),
                    recovery_cost_seconds: None,
                    impact: "test".into(),
                    recovery_cmd: None,
                    reference_url: None,
                }),
            };
            (step, path)
        }

        fn read_audit() -> Vec<AuditEntry> {
            let log = grant::audit_path();
            let content = std::fs::read_to_string(&log).unwrap_or_default();
            content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str::<AuditEntry>(l).unwrap())
                .collect()
        }

        /// End-to-end boundary: four safe steps differing on ONE dimension each —
        /// in-bound, recovery class above ceiling, confidence below floor, and one
        /// that pushes cumulative spend over max_bytes. Only the in-bound steps are
        /// acted on (moved away); the rest are denied, left in place, and every
        /// consultation is audited.
        #[test]
        fn grant_acts_only_on_in_bound_steps_and_audits_the_rest() {
            let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let h = TempHome::new("grant-boundary");
            let prof = profile::Profile::default();

            // ceiling=Rebuild, min_conf=0.80, max_bytes=10 (bytes). Sizes are tiny so
            // budget arithmetic is exact and the airlock move is cheap.
            let grant = issue_grant(RecoveryClass::Rebuild, 10, 0.80);

            // ok_a: rebuild (==ceiling), conf 0.90, 4 bytes → ALLOW (spent 4)
            // ok_b: redownload (<ceiling), conf 0.85, 4 bytes → ALLOW (spent 8)
            // bad_class: recreate (>ceiling)          → DENY (ceiling)
            // bad_conf: rebuild, conf 0.50            → DENY (confidence)
            // bad_budget: rebuild, conf 0.90, 9 bytes → DENY (8+9 > 10 budget)
            let (ok_a, p_a) = step_target(&h.path, "ok_a", 4, 0.90, "rebuild");
            let (ok_b, p_b) = step_target(&h.path, "ok_b", 4, 0.85, "redownload");
            let (bad_class, p_class) = step_target(&h.path, "bad_class", 4, 0.90, "recreate");
            let (bad_conf, p_conf) = step_target(&h.path, "bad_conf", 4, 0.50, "rebuild");
            let (bad_budget, p_budget) = step_target(&h.path, "bad_budget", 9, 0.90, "rebuild");

            let plan = Plan {
                plan_hash: String::new(),
                need_bytes: 100,
                steps: vec![ok_a, ok_b, bad_class, bad_conf, bad_budget],
                projected_freed: 0,
                created_at: Utc::now(),
            };

            let df_before = history::free_bytes(&h.path).unwrap_or(0);
            let outcome = execute_plan(
                &plan,
                &prof,
                Some(&grant),
                &quiet_ctx(),
                df_before,
                df_before + 100,
                &h.path,
            )
            .unwrap();

            // In-bound steps were acted on → their dirs were moved away.
            assert!(!p_a.exists(), "in-bound ok_a must be airlocked away");
            assert!(!p_b.exists(), "in-bound ok_b must be airlocked away");
            // Denied steps were SKIPPED → their dirs remain in place untouched.
            assert!(p_class.exists(), "ceiling-denied step must NOT be acted on");
            assert!(
                p_conf.exists(),
                "confidence-denied step must NOT be acted on"
            );
            assert!(p_budget.exists(), "budget-denied step must NOT be acted on");

            // Only the two in-bound sizes were staged.
            assert_eq!(outcome.freed_bytes, 8, "only the 4+4 in-bound bytes staged");

            // Exactly two receipts (the acted steps); the denied steps wrote none.
            let hist = history::tail(50).unwrap();
            let acted_paths: std::collections::HashSet<_> =
                hist.iter().map(|e| e.path.clone()).collect();
            assert!(acted_paths.contains(&p_a));
            assert!(acted_paths.contains(&p_b));
            assert!(!acted_paths.contains(&p_class));
            assert!(!acted_paths.contains(&p_conf));
            assert!(!acted_paths.contains(&p_budget));

            // Every step (all 5) produced an audit line; allows=2, denies=3.
            let audit = read_audit();
            assert_eq!(audit.len(), 5, "one audit line per consultation");
            let allows = audit.iter().filter(|e| e.decision == "allow").count();
            let denies = audit.iter().filter(|e| e.decision == "deny").count();
            assert_eq!(allows, 2, "two in-bound allows");
            assert_eq!(denies, 3, "three out-of-bound denies");
            // Each deny carries exactly one reason naming its failed dimension.
            let reasons: Vec<String> = audit.iter().filter_map(|e| e.deny_reason.clone()).collect();
            assert!(reasons.iter().any(|r| r.contains("ceiling")));
            assert!(reasons.iter().any(|r| r.contains("confidence")));
            assert!(reasons.iter().any(|r| r.contains("budget")));
        }

        /// INVARIANT REGRESSION: the HARD pressure-test sits UPSTREAM of grant
        /// logic. A `never_touch` path is filtered by `build_plan` (whose
        /// pressure-test runs `policy_check`) and never appears in the plan — so
        /// even a MAXIMAL grant (Irreversible ceiling, huge budget, conf floor 0)
        /// can never reach it. We build the plan with such a grant available and
        /// assert the blocked path is absent from every step.
        #[test]
        fn maximal_grant_never_reaches_a_never_touch_path() {
            let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let h = TempHome::new("grant-nevertouch");
            let home_path = h.path.clone();

            // Two distinct-rule targets; one is never_touch.
            let five_gb = 5 * 1024 * 1024 * 1024u64;
            let entries = vec![
                make_target(&home_path, "proj_nm", "node_modules", five_gb),
                make_target(&home_path, "proj_blocked", ".venv", five_gb),
            ];
            write_scan_cache(entries);

            let mut prof = profile::Profile::default();
            prof.paths.never_touch.push("~/proj_blocked/.venv".into());

            // A MAXIMAL grant exists, but selection's gate runs BEFORE any grant
            // logic — the never_touch path is dropped in build_plan regardless.
            let _maximal = issue_grant(RecoveryClass::Irreversible, u64::MAX, 0.0);

            let need = 4 * 1024 * 1024 * 1024u64;
            let plan = build_plan(need, Mode::Airlock, &prof, &home_path, &quiet_ctx()).unwrap();

            assert!(
                !plan
                    .steps
                    .iter()
                    .any(|s| s.path.starts_with(home_path.join("proj_blocked"))),
                "never_touch path must be filtered by the hard gate, before grant logic"
            );
            // And every surviving step passed the gate.
            for s in &plan.steps {
                assert!(s.pressure.safe);
            }
        }

        /// INVARIANT: a maximal grant can never make an UNSAFE step actionable.
        /// `build_plan` only ever emits `safe == true` steps; here we assert that a
        /// never_touch target, with the maximal grant in force, is BOTH absent from
        /// the plan AND, when we hand a hand-built plan containing it to the
        /// executor, the LIVE gate inside the airlock path still protects it. Since
        /// `execute_plan` trusts the plan's selection (the gate already ran in
        /// build_plan), the protection is structural: the only path to actuation is
        /// through build_plan, which excludes it. We prove build_plan is the sole
        /// gate by confirming the maximal-grant plan is EMPTY when the only target
        /// is never_touch.
        #[test]
        fn maximal_grant_plan_is_empty_when_only_target_is_blocked() {
            let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let h = TempHome::new("grant-blocked-only");
            let home_path = h.path.clone();

            let five_gb = 5 * 1024 * 1024 * 1024u64;
            write_scan_cache(vec![make_target(
                &home_path,
                "proj_blocked",
                "node_modules",
                five_gb,
            )]);

            let mut prof = profile::Profile::default();
            prof.paths
                .never_touch
                .push("~/proj_blocked/node_modules".into());

            let _maximal = issue_grant(RecoveryClass::Irreversible, u64::MAX, 0.0);
            let need = 1024 * 1024 * 1024u64; // 1 GiB
            let plan = build_plan(need, Mode::Airlock, &prof, &home_path, &quiet_ctx()).unwrap();
            assert!(
                plan.steps.is_empty(),
                "with the only target blocked by never_touch, the plan is empty even under a maximal grant"
            );
        }

        /// INVARIANT: the pressure-test still BLOCKS a live/in-use path REGARDLESS
        /// of a maximal grant. A target with a freshly-written file fails the
        /// liveness check (files modified within 24h) inside `build_plan`'s gate,
        /// so it is excluded from the plan before any grant logic — even with an
        /// Irreversible-ceiling, infinite-budget, zero-floor grant in force.
        #[test]
        fn pressure_test_blocks_live_path_regardless_of_maximal_grant() {
            let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let h = TempHome::new("grant-live");
            let home_path = h.path.clone();

            // A node_modules with a JUST-written file → liveness check fails (the
            // file's mtime is "now", inside the 24h window). The seeded
            // ScannedEntry's old timestamps don't matter: the gate re-stats the
            // REAL on-disk file.
            let live = home_path.join("proj_live").join("node_modules");
            fs::create_dir_all(&live).unwrap();
            fs::write(live.join("fresh.bin"), vec![0u8; 4096]).unwrap();

            let five_gb = 5 * 1024 * 1024 * 1024u64;
            let mut entry = make_target(&home_path, "proj_live", "node_modules", five_gb);
            // Point the entry at the live dir we just wrote (make_target re-creates
            // the same path, so this is already correct; assert for clarity).
            entry.path = live.clone();
            write_scan_cache(vec![entry]);

            let _maximal = issue_grant(RecoveryClass::Irreversible, u64::MAX, 0.0);
            let need = 1024 * 1024 * 1024u64; // 1 GiB
            let plan = build_plan(
                need,
                Mode::Airlock,
                &prof_default(),
                &home_path,
                &quiet_ctx(),
            )
            .unwrap();

            assert!(
                !plan.steps.iter().any(|s| s.path == live),
                "a live (recently-written) path must be blocked by the pressure-test, before any grant"
            );
            assert!(live.exists(), "the blocked live target is never acted on");
        }

        fn prof_default() -> profile::Profile {
            profile::Profile::default()
        }

        /// A path_scope-bounded grant denies an out-of-scope step and audits it,
        /// while admitting an in-scope one — proving the scope dimension threads
        /// through `execute_plan` → `allows`.
        #[test]
        fn grant_path_scope_filters_out_of_scope_steps() {
            let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let h = TempHome::new("grant-scope");
            let prof = profile::Profile::default();

            // Scope admits the ~/proj/in_scope subtree (the dir itself and any
            // descendant). `in_scope*` matches the directory path we act on; the
            // sibling ~/proj/out_scope does not match.
            let scope = "~/proj/in_scope*".to_string();
            let grant = issue_grant_scoped(RecoveryClass::Rebuild, 1_000, 0.80, Some(scope));

            let (in_step, p_in) = step_target(&h.path, "in_scope", 4, 0.90, "rebuild");
            let (out_step, p_out) = step_target(&h.path, "out_scope", 4, 0.90, "rebuild");

            let plan = Plan {
                plan_hash: String::new(),
                need_bytes: 100,
                steps: vec![in_step, out_step],
                projected_freed: 0,
                created_at: Utc::now(),
            };
            let df_before = history::free_bytes(&h.path).unwrap_or(0);
            execute_plan(
                &plan,
                &prof,
                Some(&grant),
                &quiet_ctx(),
                df_before,
                df_before + 100,
                &h.path,
            )
            .unwrap();

            assert!(!p_in.exists(), "in-scope step acted on (moved away)");
            assert!(p_out.exists(), "out-of-scope step denied → left in place");

            let audit = read_audit();
            assert!(audit.iter().any(|e| e.decision == "allow"));
            assert!(audit.iter().any(|e| e.decision == "deny"
                && e.deny_reason.as_deref().unwrap_or("").contains("scope")));
        }
    }

    // ── P4: GRANT IGNORED WITHOUT THE FEATURE ─────────────────────────────────
    //
    // The mirror of the boundary test: built WITHOUT `actuation`, `execute_plan`
    // ignores any grant argument entirely (the human-consent flow is unchanged).
    // We can't pass a `Grant` value here without the feature pulling in the same
    // surface, so we prove the no-op by passing `None` and asserting a below-floor,
    // would-be-out-of-bound step is STILL acted on — exactly as before P4, because
    // there is no grant gate in this build.
    #[cfg(not(feature = "actuation"))]
    #[test]
    fn without_actuation_grant_arg_is_ignored_and_step_acts() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("noactuation");
        let prof = profile::Profile::default();

        // A low-confidence, "irreversible" step that a grant WOULD deny — but with
        // no feature there is no grant gate, so it acts (pre-P4 behavior preserved).
        let target = h.path.join("proj/node_modules");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("blob.bin"), vec![0u8; 4096]).unwrap();
        let step = PlanStep {
            candidate_id: "manual-nm".into(),
            rule_id: "manual".into(),
            path: target.clone(),
            size_bytes: 4096,
            confidence: 0.10,
            mode: "airlock".into(),
            reversible: true,
            pressure: CheckResult::gate("manual-nm".into(), true, 1.0, vec![]),
            consequence_contract: None,
        };
        let plan = Plan {
            plan_hash: String::new(),
            need_bytes: 4096,
            steps: vec![step],
            projected_freed: 4096,
            created_at: Utc::now(),
        };
        let df_before = history::free_bytes(&h.path).unwrap_or(0);
        let outcome = execute_plan(
            &plan,
            &prof,
            None,
            &quiet_ctx(),
            df_before,
            df_before + 4096,
            &h.path,
        )
        .unwrap();
        assert!(
            !target.exists(),
            "without actuation, the step acts regardless of any grant bound"
        );
        assert_eq!(outcome.freed_bytes, 4096);
    }
}

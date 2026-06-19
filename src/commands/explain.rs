//! `diskspace inspect <path>` (was `explain`) — given any path, find the matching
//! rule (or report none), show consequences, run the pressure test live, and
//! recommend a command. The trust front-door: users audit before they delete.

use anyhow::Result;
use console::Style;
use std::path::{Path, PathBuf};

use crate::commands::check;
use crate::core::airlock_store;
use crate::core::candidate::CheckResult;
use crate::core::rules::{self, Rule};
use crate::core::scanner::expand_home;
use crate::output::{self, Context};
use crate::profile;

/// Confidence floor at/above which `--immediate` (permanent delete, skip airlock)
/// is recommended; below it we recommend the reversible airlock path. Shared with
/// `detect` so it can emit a `recommended_command` per candidate via the reusable
/// [`recommended_command`] helper.
pub const IMMEDIATE_THRESHOLD: f32 = 0.85;

pub fn run(target: &str, ctx: &Context) -> Result<()> {
    let prof = profile::load()?;
    let rule_list = rules::load_builtin()?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let path = expand_target(target, &home);

    if !path.exists() {
        if ctx.json {
            eprintln!(
                r#"{{"error":"path_not_found","path":"{}"}}"#,
                path.display()
            );
        } else {
            eprintln!("\n  Path does not exist: {}\n", path.display());
        }
        std::process::exit(1);
    }

    // Find the most-specific matching rule (longest prefix wins for non-glob;
    // first match for globs).
    let matched = find_rule(&path, &rule_list, &home);

    // Compute size on disk.
    let size = airlock_store::dir_size(&path);

    // Run the live pressure test even if there's no matching rule — users still
    // care about open file handles and recent activity.
    let pressure = check::pressure_test("(explain)", &path, &prof)?;

    if ctx.json {
        // Agent-surface enrichment for the JSON consumer (single source of truth
        // in `agent_surface`). Purely advisory — computed AFTER the pressure test
        // and never feeding `pressure.safe` or the recommendation.
        let reference_url = matched.map(|r| {
            crate::commands::agent_surface::reference_url(&r.id, r.reference_url.as_deref())
        });
        let consequence_contract = matched.and_then(|r| {
            r.consequences.as_ref().map(|cons| {
                crate::commands::agent_surface::contract_from_consequences(
                    cons,
                    &r.id,
                    r.reference_url.as_deref(),
                )
            })
        });
        let metrics = crate::core::metrics::compute_metrics(&path, &prof).ok();

        let payload = serde_json::json!({
            "path": path,
            "size_bytes": size,
            "rule": matched.map(|r| serde_json::json!({
                "id": r.id,
                "category": r.category,
                "confidence": r.base_confidence,
                "domain": r.domain,
                "reason": r.reason,
                "consequences": r.consequences,
            })),
            "pressure": pressure,
            "consequence_contract": consequence_contract,
            "metrics": metrics,
            "reference_url": reference_url,
            "recommended_command": recommended_command(&path, matched, &pressure),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    render_human(ctx, &path, size, matched, &pressure);
    Ok(())
}

fn render_human(
    ctx: &Context,
    path: &Path,
    size: u64,
    matched: Option<&Rule>,
    pressure: &CheckResult,
) {
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let yellow = Style::new().yellow();
    let green = Style::new().green().bold();
    let red = Style::new().red().bold();
    let cyan = Style::new().cyan().bold();

    println!();
    println!("  {}", ctx.style(&output::rule("inspect", 60), &dim));
    println!();
    println!(
        "  {}  {}",
        ctx.style("path", &bold),
        ctx.style(&path.display().to_string(), &dim)
    );
    println!(
        "  {}  {}",
        ctx.style("size", &bold),
        ctx.style(&output::format_bytes(size), &yellow)
    );
    println!();

    // ── rule match ─────────────────────────────────────
    println!("  {}", ctx.style(&output::rule("rule", 60), &dim));
    println!();
    match matched {
        Some(r) => {
            println!(
                "  {:<14}  {}",
                ctx.style("id", &bold),
                ctx.style(&r.id, &cyan)
            );
            println!(
                "  {:<14}  {}",
                ctx.style("category", &bold),
                ctx.style(&r.category, &dim)
            );
            println!(
                "  {:<14}  {}  {}",
                ctx.style("confidence", &bold),
                ctx.style(&output::confidence_bar(r.base_confidence, 10), &yellow),
                ctx.style(&r.reason, &dim),
            );
            if let Some(d) = &r.domain {
                println!(
                    "  {:<14}  {}",
                    ctx.style("domain", &bold),
                    ctx.style(d, &dim)
                );
            }
            if let Some(cons) = &r.consequences {
                println!();
                println!(
                    "  {}",
                    ctx.style(&output::rule("if you delete this", 60), &dim)
                );
                println!();
                println!(
                    "  {:<10}  {}",
                    ctx.style("recovery", &bold),
                    ctx.style(
                        &format_recovery(&cons.recovery, cons.rebuild_seconds),
                        &yellow
                    )
                );
                println!(
                    "  {:<10}  {}",
                    ctx.style("impact", &bold),
                    ctx.style(&cons.impact, &dim)
                );
                if let Some(cmd) = &cons.recovery_cmd {
                    println!(
                        "  {:<10}  {}",
                        ctx.style("recover", &bold),
                        ctx.style(cmd, &dim)
                    );
                }
            }
        }
        None => {
            println!(
                "  {}  {}",
                ctx.style("○", &dim),
                ctx.style(
                    "no rule matches this path — diskspace does not know what it is",
                    &dim
                )
            );
            println!();
            println!(
                "  {}",
                ctx.style(
                    "If you'd like a rule for it (so other users benefit), open a 10-line YAML PR:",
                    &dim
                )
            );
            println!(
                "  {}",
                ctx.style("https://github.com/tymrtn/diskspace", &dim)
            );
        }
    }

    // ── live pressure test ─────────────────────────────
    println!();
    println!("  {}", ctx.style(&output::rule("pressure test", 60), &dim));
    println!();
    for step in &pressure.steps {
        let icon = if step.passed {
            ctx.style("✓", &green)
        } else {
            ctx.style("✗", &red)
        };
        println!(
            "  {}  {:<18}  {}",
            icon,
            ctx.style(&step.name, &bold),
            ctx.style(&step.note, &dim)
        );
    }

    // ── recommendation ─────────────────────────────────
    println!();
    println!("  {}", ctx.style(&output::rule("recommendation", 60), &dim));
    println!();
    let rec = recommended_command(path, matched, pressure);
    println!("  {}  {}", ctx.style("→", &cyan), ctx.style(&rec, &bold));
    println!();
}

/// Recommend a concrete next command for a path, given whether a rule matched and
/// the LIVE pressure-test verdict. Reusable from `detect` (one `recommended_command`
/// per candidate) as well as `explain`.
///
/// Decision order — pressure FIRST so a clean pressure-test can carry an unruled
/// path, instead of dead-ending on "no rule covers this":
///   1. pressure NOT safe          -> block / refuse (never recommend a delete)
///   2. pressure safe + rule match  -> confidence-based reclaim vs. airlock
///   3. pressure safe + NO rule      -> airlock-by-path (fully reversible)
///
/// `airlock` already accepts a PATH target (not just a candidate id), so the
/// no-rule branch can safely recommend `diskspace airlock <path>` — every airlock
/// is staged to the reversible airlock and restorable.
pub fn recommended_command(path: &Path, matched: Option<&Rule>, pressure: &CheckResult) -> String {
    // `explain` ranks off the rule's STATIC base confidence — there is no
    // per-call decay in the explain path — so it passes `base_confidence`
    // through unchanged.
    recommended_command_for(path, matched.map(|r| r.base_confidence), pressure)
}

/// Confidence-aware core of [`recommended_command`]. Callers pass the EFFECTIVE
/// confidence to compare against [`IMMEDIATE_THRESHOLD`], rather than always
/// reading the rule's static `base_confidence`.
///
/// `detect` decays a recency-touched regenerable candidate's confidence (#6:
/// `base × RECENCY_DECAY`). If the recommendation kept branching on the rule's
/// static `base_confidence`, a candidate serialized with a DECAYED confidence
/// (e.g. 0.54) could still be told to `--immediate` permanently delete — flatly
/// contradicting its own demoted `confidence` field. So `detect` passes
/// `Some(c.confidence)` here, and a decayed candidate correctly falls to the
/// reversible airlock branch. `confidence: None` means "no rule matched" and
/// routes to the airlock-by-path fallback.
pub fn recommended_command_for(
    path: &Path,
    confidence: Option<f32>,
    pressure: &CheckResult,
) -> String {
    if !pressure.safe {
        return format!(
            "Do not delete — pressure test failed. See `diskspace inspect {}` for the failing check.",
            path.display()
        );
    }
    match confidence {
        Some(c) if c >= IMMEDIATE_THRESHOLD => format!(
            "Reclaim: `diskspace airlock <id> --immediate --yes`  (confidence {:.0}%, safe to delete permanently)",
            c * 100.0
        ),
        Some(c) => format!(
            "Airlock (reversible): `diskspace airlock <id>`  (confidence {:.0}% — below 0.85 threshold for permanent delete)",
            c * 100.0
        ),
        None => format!(
            "Reversible: `diskspace airlock {}`  (no rule matched, but the pressure-test is clean — fully reversible)",
            path.display()
        ),
    }
}

fn format_recovery(recovery: &str, seconds: Option<u32>) -> String {
    let dur = match seconds {
        Some(s) if s < 60 => format!(" · ~{}s", s),
        Some(s) if s < 3600 => format!(" · ~{} min", s / 60),
        Some(s) => format!(" · ~{} hr", s / 3600),
        None => String::new(),
    };
    format!("{}{}", recovery, dur)
}

/// Resolve a user-supplied path, expanding ~ and supporting absolute or relative paths.
fn expand_target(target: &str, home: &str) -> PathBuf {
    if let Some(rest) = target.strip_prefix("~/") {
        PathBuf::from(home).join(rest)
    } else if target == "~" {
        PathBuf::from(home)
    } else {
        PathBuf::from(target)
    }
}

fn find_rule<'a>(path: &Path, rules: &'a [Rule], home: &str) -> Option<&'a Rule> {
    let home_path = PathBuf::from(home);
    rules.iter().find(|r| {
        let resolved = expand_home(&r.path_pattern, &home_path);
        match glob::Pattern::new(&resolved) {
            Ok(p) => p.matches_path(path),
            Err(_) => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::candidate::{CheckResult, CheckStep};
    use crate::core::rules::Rule;

    fn step(name: &str, passed: bool) -> CheckStep {
        CheckStep {
            name: name.into(),
            passed,
            note: String::new(),
        }
    }

    /// A pressure result whose `safe` matches the supplied flag (FIX #4 branches
    /// on `pressure.safe`, never on the step list).
    fn pressure(safe: bool) -> CheckResult {
        CheckResult::gate("(test)".into(), safe, 1.0, vec![step("re-stat", safe)])
    }

    fn rule_with_confidence(id: &str, conf: f32) -> Rule {
        Rule {
            id: id.into(),
            category: "dev-artifact".into(),
            path_pattern: "**/whatever".into(),
            domain: None,
            base_confidence: conf,
            reason: "test".into(),
            exclude_if_recent_access_days: None,
            exclude_if_recent_modified_days: None,
            consequences: None,
            reference_url: None,
        }
    }

    /// A scratch tempdir for the path argument. The helper only formats the path;
    /// it never touches the filesystem. We still use a real, unique path so the
    /// airlock-by-path string is the genuine one a user would copy-paste.
    fn temp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "diskspace-explain-test-{}-{}-{}",
            tag,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        p
    }

    #[test]
    fn unruled_but_pressure_safe_recommends_airlock_by_path() {
        // FIX #4: the biggest safe wins (large dirs with no rule) must no longer
        // dead-end on "no rule covers this — can't recommend". A clean pressure
        // test carries them to an airlock-by-PATH recommendation.
        let path = temp_path("unruled-safe");
        let rec = recommended_command(&path, None, &pressure(true));
        assert!(
            rec.contains(&format!("diskspace airlock {}", path.display())),
            "must recommend airlock-by-path, got: {rec}"
        );
        assert!(
            rec.contains("no rule matched") && rec.contains("reversible"),
            "must explain it's the pressure-safe reversible fallback, got: {rec}"
        );
        assert!(
            !rec.contains("can't recommend") && !rec.contains("du -sh"),
            "must NOT dead-end on the old no-recommendation string, got: {rec}"
        );
    }

    #[test]
    fn rule_matched_high_confidence_keeps_immediate_recommendation() {
        // At/above IMMEDIATE_THRESHOLD the ruled recommendation is unchanged.
        let path = temp_path("ruled-high");
        let rule = rule_with_confidence("derived_data", IMMEDIATE_THRESHOLD);
        let rec = recommended_command(&path, Some(&rule), &pressure(true));
        assert!(
            rec.contains("--immediate") && rec.contains("Reclaim"),
            "high-confidence ruled path keeps the immediate reclaim recommendation, got: {rec}"
        );
    }

    #[test]
    fn rule_matched_below_threshold_keeps_airlock_by_id_recommendation() {
        // Below the threshold the ruled recommendation stays the reversible
        // airlock-by-ID form (NOT the no-rule by-path fallback).
        let path = temp_path("ruled-low");
        let rule = rule_with_confidence("node_modules", IMMEDIATE_THRESHOLD - 0.1);
        let rec = recommended_command(&path, Some(&rule), &pressure(true));
        assert!(
            rec.contains("Airlock (reversible)") && rec.contains("airlock <id>"),
            "below-threshold ruled path keeps airlock-by-id, got: {rec}"
        );
    }

    #[test]
    fn pressure_failure_returns_block_message_regardless_of_rule() {
        // When pressure is NOT safe we refuse — for both ruled and unruled paths,
        // never recommending a delete.
        let path = temp_path("unsafe");
        let ruled = rule_with_confidence("derived_data", 0.95);

        let rec_unruled = recommended_command(&path, None, &pressure(false));
        let rec_ruled = recommended_command(&path, Some(&ruled), &pressure(false));

        for rec in [&rec_unruled, &rec_ruled] {
            assert!(
                rec.contains("Do not delete") && rec.contains("pressure test failed"),
                "pressure failure must block, got: {rec}"
            );
            assert!(
                !rec.contains("airlock"),
                "block message must not recommend an airlock, got: {rec}"
            );
        }
    }

    #[test]
    fn helper_is_callable_from_outside_explain() {
        // The helper (and IMMEDIATE_THRESHOLD) are `pub` so `detect` can emit one
        // recommended_command per candidate (Pass-1 #3). Reference both through
        // their crate paths to prove the visibility from outside this module.
        let path = temp_path("external");
        let pr = pressure(true);
        let rec = crate::commands::explain::recommended_command(&path, None, &pr);
        assert!(!rec.is_empty());
        // The threshold is also reachable as a pub const.
        let _threshold: f32 = crate::commands::explain::IMMEDIATE_THRESHOLD;
        assert!((0.0..=1.0).contains(&_threshold));
    }
}

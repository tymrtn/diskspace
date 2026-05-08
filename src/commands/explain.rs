//! `diskspace explain <path>` — given any path, find the matching rule (or report
//! none), show consequences, run the pressure test live, and recommend a command.
//! The trust front-door: users audit before they delete.

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

const IMMEDIATE_THRESHOLD: f32 = 0.85;

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
    println!("  {}", ctx.style(&output::rule("explain", 60), &dim));
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

fn recommended_command(path: &Path, matched: Option<&Rule>, pressure: &CheckResult) -> String {
    if !pressure.safe {
        return format!(
            "Do not delete — pressure test failed. See `diskspace explain {}` for the failing check.",
            path.display()
        );
    }
    match matched {
        None => format!(
            "Inspect manually: `du -sh {}/*` to drill in. No rule covers this — diskspace can't recommend a safe command.",
            path.display()
        ),
        Some(r) if r.base_confidence >= IMMEDIATE_THRESHOLD => format!(
            "Reclaim: `diskspace airlock <id> --immediate --yes`  (confidence {:.0}%, safe to delete permanently)",
            r.base_confidence * 100.0
        ),
        Some(r) => format!(
            "Airlock (reversible): `diskspace airlock <id>`  (confidence {:.0}% — below 0.85 threshold for permanent delete)",
            r.base_confidence * 100.0
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

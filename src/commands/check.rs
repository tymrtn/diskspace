use anyhow::{Context as _, Result};
use console::Style;
use std::path::Path;

use crate::commands::detect::build_candidates_pub;
use crate::commands::scan::scan_cache_path;
use crate::core::candidate::{CheckResult, CheckStep};
use crate::core::scanner::ScanResult;
use crate::output::{self, Context};
use crate::profile;

pub fn run(candidate_id: &str, ctx: &Context) -> Result<()> {
    let cache = scan_cache_path();
    if !cache.exists() {
        bail_no_scan(ctx);
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(&cache).context("reading scan cache")?;
    let scan: ScanResult = serde_json::from_str(&content).context("parsing scan cache")?;
    let rules = crate::core::rules::load_builtin()?;
    let prof = profile::load()?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());

    let candidates = build_candidates_pub(&scan, &rules, &prof, &home);
    let candidate = match candidates.iter().find(|c| c.id == candidate_id) {
        Some(c) => c.clone(),
        None => {
            if ctx.json {
                eprintln!(
                    r#"{{"error":"candidate not found","id":"{}","hint":"run diskspace detect"}}"#,
                    candidate_id
                );
            } else {
                eprintln!(
                    "\n  Candidate '{}' not found. Run `diskspace detect` first.\n",
                    candidate_id
                );
            }
            std::process::exit(1);
        }
    };

    let mut result = pressure_test(candidate_id, &candidate.path, &prof)?;
    result.consequences = candidate.consequences.clone();

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        if !result.safe {
            std::process::exit(2);
        }
        return Ok(());
    }

    render_result(&result, ctx);

    if !result.safe {
        std::process::exit(2);
    }
    Ok(())
}

pub fn pressure_test(
    candidate_id: &str,
    path: &Path,
    prof: &profile::Profile,
) -> Result<CheckResult> {
    let steps: Vec<CheckStep> = vec![
        restat_check(path),
        liveness_check(path),
        policy_check(path, prof),
        recency_check(path),
    ];

    let safe = steps.iter().all(|s| s.passed);
    // Confidence decays for each soft failure
    let confidence = steps
        .iter()
        .fold(1.0f32, |acc, s| if s.passed { acc } else { acc * 0.5 });

    Ok(CheckResult {
        candidate_id: candidate_id.to_string(),
        safe,
        confidence,
        steps,
        consequences: None,
    })
}

pub fn render_check_result_pub(result: &CheckResult, ctx: &Context) {
    render_result(result, ctx);
}

fn render_result(result: &CheckResult, ctx: &Context) {
    let bold = Style::new().bold();
    let dim = Style::new().dim();
    let green = Style::new().green().bold();
    let red = Style::new().red().bold();
    let yellow = Style::new().yellow();

    println!();
    println!(
        "  {}",
        ctx.style(
            &output::rule(&format!("check  ·  {}", result.candidate_id), 56),
            &dim
        )
    );
    println!();

    for step in &result.steps {
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

    println!();

    if result.safe {
        let bar = output::confidence_bar(result.confidence, 10);
        println!(
            "  {}  {}  safe to airlock",
            ctx.style("→", &green),
            ctx.style(&bar, &yellow),
        );
    } else {
        println!("  {}  not safe — see failures above", ctx.style("✗", &red),);
    }
    println!();

    // ── if you delete this ───────────────────────────
    if let Some(cons) = &result.consequences {
        println!(
            "  {}",
            ctx.style(&output::rule("if you delete this", 56), &dim)
        );
        println!();
        let recovery_label = format_recovery(&cons.recovery, cons.rebuild_seconds);
        println!(
            "  {:<10}  {}",
            ctx.style("recovery", &bold),
            ctx.style(&recovery_label, &yellow),
        );
        println!(
            "  {:<10}  {}",
            ctx.style("impact", &bold),
            ctx.style(&cons.impact, &dim),
        );
        if let Some(cmd) = &cons.recovery_cmd {
            println!(
                "  {:<10}  {}",
                ctx.style("recover", &bold),
                ctx.style(cmd, &dim),
            );
        }
        println!();
    }

    if result.safe {
        println!(
            "  {}  diskspace airlock {}",
            ctx.style("next:", &bold),
            ctx.style(&result.candidate_id, &dim),
        );
        println!();
    }
}

/// Format a recovery label like "rebuild · ~2 min" or "manual" or "irreversible".
fn format_recovery(recovery: &str, seconds: Option<u32>) -> String {
    let dur = match seconds {
        Some(s) if s < 60 => format!(" · ~{}s", s),
        Some(s) if s < 3600 => format!(" · ~{} min", s / 60),
        Some(s) => format!(" · ~{} hr", s / 3600),
        None => String::new(),
    };
    format!("{}{}", recovery, dur)
}

fn restat_check(path: &Path) -> CheckStep {
    match std::fs::metadata(path) {
        Ok(_) => CheckStep {
            name: "re-stat".into(),
            passed: true,
            note: "path exists and is readable".into(),
        },
        Err(e) => CheckStep {
            name: "re-stat".into(),
            passed: false,
            note: format!("cannot stat: {}", e),
        },
    }
}

fn liveness_check(path: &Path) -> CheckStep {
    let output = std::process::Command::new("lsof")
        .arg("+D")
        .arg(path.to_string_lossy().as_ref())
        .output();

    if let Ok(out) = output {
        let lines = String::from_utf8_lossy(&out.stdout);
        let open = lines.lines().count().saturating_sub(1); // subtract header
        if open > 0 {
            return CheckStep {
                name: "liveness".into(),
                passed: false,
                note: format!("{} open file handle(s)", open),
            };
        }
    } // lsof unavailable or no handles — fall through to mtime check

    // Check for writes in last 24h
    if walk_recent_mtime(path, chrono::Duration::hours(24)) {
        CheckStep {
            name: "liveness".into(),
            passed: false,
            note: "files modified within last 24h".into(),
        }
    } else {
        CheckStep {
            name: "liveness".into(),
            passed: true,
            note: "no open handles · no recent writes".into(),
        }
    }
}

fn walk_recent_mtime(path: &Path, threshold: chrono::Duration) -> bool {
    let cutoff = chrono::Utc::now() - threshold;
    if path.is_file() {
        return std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| chrono::DateTime::<chrono::Utc>::from(t) > cutoff)
            .unwrap_or(false);
    }
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            if walk_recent_mtime(&entry.path(), threshold) {
                return true;
            }
        }
    }
    false
}

fn policy_check(path: &Path, prof: &profile::Profile) -> CheckStep {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let home_path = Path::new(&home);

    for pattern in &prof.paths.never_touch {
        let expanded = crate::core::scanner::expand_home(pattern, home_path);
        if let Ok(pat) = glob::Pattern::new(&expanded) {
            if pat.matches_path(path) {
                return CheckStep {
                    name: "profile policy".into(),
                    passed: false,
                    note: format!("blocked by never_touch: {}", pattern),
                };
            }
        }
    }
    for pattern in &prof.paths.never_suggest {
        let expanded = crate::core::scanner::expand_home(pattern, home_path);
        if path.starts_with(&expanded) {
            return CheckStep {
                name: "profile policy".into(),
                passed: false,
                note: format!("marked never_suggest: {}", pattern),
            };
        }
    }
    CheckStep {
        name: "profile policy".into(),
        passed: true,
        note: "no policy blocks".into(),
    }
}

fn recency_check(path: &Path) -> CheckStep {
    let mut dir = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    };

    loop {
        let git_head = dir.join(".git").join("HEAD");
        if git_head.exists() {
            if let Ok(meta) = std::fs::metadata(&git_head) {
                if let Ok(modified) = meta.modified() {
                    let age_days = chrono::Utc::now()
                        .signed_duration_since(chrono::DateTime::<chrono::Utc>::from(modified))
                        .num_days();
                    let passed = age_days >= 7;
                    return CheckStep {
                        name: "project recency".into(),
                        passed,
                        note: if passed {
                            format!("last git activity {} days ago", age_days)
                        } else {
                            format!(
                                "git activity {} day(s) ago — project may be active",
                                age_days
                            )
                        },
                    };
                }
            }
        }
        match dir.parent() {
            Some(p) if p != dir.as_path() => dir = p.to_path_buf(),
            _ => break,
        }
    }

    CheckStep {
        name: "project recency".into(),
        passed: true,
        note: "no enclosing git repo".into(),
    }
}

fn bail_no_scan(ctx: &Context) {
    if ctx.json {
        eprintln!(r#"{{"error":"no scan found","hint":"run diskspace scan first"}}"#);
    } else {
        eprintln!("  No scan found. Run `diskspace scan` first.");
    }
}

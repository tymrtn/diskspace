use anyhow::{Context as _, Result};
use console::Style;
use std::path::Path;

use crate::commands::detect::build_candidates_pub;
use crate::commands::scan::scan_cache_path;
use crate::core::candidate::{CheckResult, CheckStep};
use crate::core::safety;
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

    // Agent-surface enrichment — attached AFTER the gate has decided `safe`, so
    // it can NEVER influence the actuation decision. The candidate was already
    // enriched in build_candidates (single source of truth), so copy the derived
    // fields onto the result for agents reading `diskspace check --json`.
    result.consequence_contract = candidate.consequence_contract.clone();
    result.metrics = candidate.metrics.clone();
    result.reference_url = candidate.reference_url.clone();

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
        data_safety_check(path),
        policy_check(path, prof),
        recency_check(path),
    ];

    let safe = steps.iter().all(|s| s.passed);
    // Confidence decays for each soft failure
    let confidence = steps
        .iter()
        .fold(1.0f32, |acc, s| if s.passed { acc } else { acc * 0.5 });

    // Use the `gate` constructor so this gate function never names the advisory
    // agent-surface fields. The scope-fence guard textually scans THIS function
    // body, so keeping the advisory field names out of it preserves the blind
    // gate. Enrichment is attached later in `run`, strictly after `safe` is set.
    Ok(CheckResult::gate(
        candidate_id.to_string(),
        safe,
        confidence,
        steps,
    ))
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

/// Built-in data-safety floor: refuse to auto-delete a database — the candidate
/// itself, or any database nested beneath it. Runs BEFORE any grant logic: a
/// `pressure_test` failure sets `safe = false`, and a grant only relaxes consent
/// AFTER `safe == true`, so the floor is fail-closed and not grant-overridable.
///
/// A path whose every matching rule is wholesale-regenerable (auto / redownload /
/// rebuild / recreate) is exempt — the curator vouched the tree rebuilds from a
/// source, so any db inside it is regenerable too, and scanning a giant cache
/// would falsely refuse it. Everything else (manual/irreversible rules such as
/// git worktrees, plus unruled/heuristic paths) is scanned. A wildcard-free rule
/// naming the EXACT db file (e.g. screenpipe's recording db) keeps that one db
/// deletable; a directory rule never vouches for a db merely nested beneath it.
fn data_safety_check(path: &Path) -> CheckStep {
    let name = "data safety";
    let pass = |note: &str| CheckStep {
        name: name.into(),
        passed: true,
        note: note.into(),
    };
    let fail = |note: String| CheckStep {
        name: name.into(),
        passed: false,
        note,
    };

    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let home_path = Path::new(&home);
    // `load_builtin` parses the compile-time-embedded YAML; on the (impossible)
    // parse failure, default to NO rules → nothing is vouched → the floor scans
    // and protects everything, which is the safe direction.
    let rules = crate::core::rules::load_builtin().unwrap_or_default();

    // (1) Wholesale-regenerable: exempt (and skip scanning a huge cache).
    if safety::is_regenerable_vouched(path, &rules, home_path) {
        return pass("regenerable build artifact (rule-vouched)");
    }

    // (2) Scan everything else for a database at or beneath the candidate.
    match safety::database_scan(path, safety::DB_SCAN_CAP) {
        safety::DbScan::Clean => pass("no database files"),
        safety::DbScan::Inconclusive => {
            fail("too large to verify database-free — refused (fail-closed)".into())
        }
        safety::DbScan::Found(db) => {
            if db == path && safety::rule_names_exact_path(path, &rules, home_path) {
                pass("rule names this exact database (curated)")
            } else {
                fail(format!(
                    "contains a database ({}) — never auto-deleted",
                    db.display()
                ))
            }
        }
    }
}

fn policy_check(path: &Path, prof: &profile::Profile) -> CheckStep {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let home_path = Path::new(&home);

    // Built-in absolute floor: credential / key / secret stores. Never
    // regenerable, never rule-targeted, never overridable by profile or grant.
    for prefix in safety::builtin_never_touch() {
        let expanded = crate::core::scanner::expand_home(prefix, home_path);
        if path.starts_with(&expanded) {
            return CheckStep {
                name: "profile policy".into(),
                passed: false,
                note: format!("built-in never_touch (secret store): {}", prefix),
            };
        }
    }

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
        eprintln!(r#"{{"error":"no scan found","hint":"run diskspace survey first"}}"#);
    } else {
        eprintln!("  No survey found. Run `diskspace survey` first.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    fn tmp() -> std::path::PathBuf {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("diskspace-gate-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// The core guarantee: an UNRULED candidate directory that contains a database
    /// fails the data-safety step — so `pressure_test` returns `safe == false` and
    /// no actuation (grant-driven or otherwise) can ever delete it.
    #[test]
    fn data_safety_vetoes_unruled_directory_containing_a_database() {
        let d = tmp();
        let app = d.join("SomeApp/state");
        fs::create_dir_all(&app).unwrap();
        fs::write(app.join("codex-dev.db"), b"x").unwrap();

        let step = data_safety_check(&d);
        assert!(!step.passed, "a dir holding a database must NOT pass");
        assert!(
            step.note.contains("database"),
            "note names the cause: {}",
            step.note
        );

        // End-to-end: the whole gate reports unsafe.
        let result = pressure_test("t", &d, &profile::Profile::default()).unwrap();
        assert!(
            !result.safe,
            "pressure_test must be unsafe for a db-bearing dir"
        );
        assert!(
            result
                .steps
                .iter()
                .any(|s| s.name == "data safety" && !s.passed),
            "the data-safety step is the (a) failing gate"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// A wildcard-free rule naming the EXACT db file (screenpipe's regenerable
    /// recording db, recovery class irreversible) keeps that one database
    /// deletable. The candidate IS the db file, so `database_scan` returns
    /// Found(self) and the exact-name override applies. Needs the file to exist
    /// for the scan, so create it in a tempdir and point the rule check at a real
    /// builtin rule via $HOME.
    #[test]
    fn data_safety_allows_exact_file_database_rule() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
        let path = std::path::Path::new(&home)
            .join(".screenpipe")
            .join("db.sqlite");
        // `database_scan` short-circuits on is_database_file (name only, no fs),
        // so the file need not exist for Found(self); the exact-name override is a
        // pure path+rule check.
        let step = data_safety_check(&path);
        assert!(
            step.passed,
            "the curated exact-file screenpipe db rule stays deletable: {}",
            step.note
        );
        assert!(step.note.contains("exact database"), "note: {}", step.note);
    }

    /// The built-in credential floor blocks a secret store even with an empty
    /// profile. Pure path check (no fs touch of the real `~/.ssh`).
    #[test]
    fn policy_blocks_builtin_secret_store() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
        let path = std::path::Path::new(&home).join(".ssh").join("id_ed25519");
        let step = policy_check(&path, &profile::Profile::default());
        assert!(!step.passed, "~/.ssh must be blocked by the built-in floor");
        assert!(step.note.contains("secret store"), "note: {}", step.note);
    }

    /// A plain build cache (no database, not a secret store) still passes both new
    /// checks — the floor must not break legitimate cleanup.
    #[test]
    fn plain_build_cache_still_passes_data_safety() {
        let d = tmp();
        let nm = d.join("node_modules/pkg");
        fs::create_dir_all(&nm).unwrap();
        fs::write(nm.join("index.js"), b"x").unwrap();
        assert!(
            data_safety_check(&d).passed,
            "a db-free cache passes data-safety"
        );
        assert!(
            policy_check(&d, &profile::Profile::default()).passed,
            "a temp build cache is not a secret store"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// Findings #1/#3 regression: a candidate matched by a DIRECTORY rule that is
    /// NOT wholesale-regenerable (here the real `**/stale/*` rule, recovery class
    /// `manual`) must STILL be scanned, and a database nested beneath it must veto
    /// the deletion. Before the fix, any rule match short-circuited the scan.
    #[test]
    fn data_safety_vetoes_ruled_directory_with_nested_database() {
        let d = tmp();
        let proj = d.join("stale").join("proj");
        fs::create_dir_all(&proj).unwrap();
        fs::write(proj.join("app.sqlite"), b"x").unwrap();
        // candidate path = .../stale/proj, matched by the builtin `**/stale/*`
        // (manual) rule — a directory rule, so it must not vouch for the nested db.
        let step = data_safety_check(&proj);
        assert!(
            !step.passed,
            "a manual-class directory rule must not let a nested db through: {}",
            step.note
        );
        assert!(step.note.contains("database"), "note: {}", step.note);
        let _ = fs::remove_dir_all(&d);
    }

    /// Use-case preservation: a candidate matched by a wholesale-regenerable rule
    /// (the real `**/node_modules`, recovery `redownload`) is EXEMPT from the scan
    /// — even when a db is nested inside — so large node_modules cleanup keeps
    /// working and never trips the Inconclusive fail-closed path.
    #[test]
    fn data_safety_exempts_regenerable_node_modules_even_with_nested_db() {
        let d = tmp();
        let nm = d.join("node_modules");
        let pkg = nm.join("some-pkg");
        fs::create_dir_all(&pkg).unwrap();
        fs::write(pkg.join("fixture.db"), b"x").unwrap();
        let step = data_safety_check(&nm);
        assert!(
            step.passed,
            "node_modules (redownload) is rule-vouched regenerable: {}",
            step.note
        );
        assert!(step.note.contains("regenerable"), "note: {}", step.note);
        let _ = fs::remove_dir_all(&d);
    }
}

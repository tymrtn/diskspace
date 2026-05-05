use anyhow::{Context as _, Result};
use console::Style;

use crate::commands::check;
use crate::commands::detect::build_candidates_pub;
use crate::commands::scan::scan_cache_path;
use crate::core::airlock_store;
use crate::core::scanner::ScanResult;
use crate::output::{self, Context};
use crate::profile;

const IMMEDIATE_MIN_CONFIDENCE: f32 = 0.85;

pub fn run(target: &str, immediate: bool, ctx: &Context) -> Result<()> {
    let cache = scan_cache_path();
    if !cache.exists() {
        if ctx.json {
            eprintln!(r#"{{"error":"no scan found","hint":"run diskspace scan first"}}"#);
        } else {
            eprintln!("  No scan found. Run `diskspace scan` first.");
        }
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(&cache).context("reading scan cache")?;
    let scan: ScanResult = serde_json::from_str(&content).context("parsing scan cache")?;
    let rules = crate::core::rules::load_builtin()?;
    let prof = profile::load()?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());

    let candidates = build_candidates_pub(&scan, &rules, &prof, &home);
    let candidate = match candidates.iter().find(|c| c.id == target) {
        Some(c) => c.clone(),
        None => {
            if ctx.json {
                eprintln!(r#"{{"error":"candidate not found","hint":"run diskspace detect"}}"#);
            } else {
                eprintln!(
                    "\n  Candidate '{}' not found. Run `diskspace detect` first.\n",
                    target
                );
            }
            std::process::exit(1);
        }
    };

    // --immediate requires high confidence
    if immediate && candidate.confidence < IMMEDIATE_MIN_CONFIDENCE {
        if ctx.json {
            eprintln!(
                r#"{{"error":"confidence_too_low","confidence":{:.2},"required":{:.2},"hint":"use airlock without --immediate or raise confidence threshold"}}"#,
                candidate.confidence, IMMEDIATE_MIN_CONFIDENCE
            );
        } else {
            eprintln!(
                "\n  --immediate requires confidence ≥ {:.0}%  (this candidate is {:.0}%)\n  Use `diskspace airlock {}` to airlock with restore option.\n",
                IMMEDIATE_MIN_CONFIDENCE * 100.0,
                candidate.confidence * 100.0,
                target,
            );
        }
        std::process::exit(3);
    }

    // Always pressure-test before acting
    let check_result = check::pressure_test(&candidate.id, &candidate.path, &prof)?;
    if !check_result.safe {
        if ctx.json {
            let out = serde_json::json!({
                "error": "pressure_test_failed",
                "candidate_id": target,
                "check": check_result,
            });
            eprintln!("{}", serde_json::to_string_pretty(&out)?);
        } else {
            check::render_check_result_pub(&check_result, ctx);
            eprintln!("  Airlock aborted — candidate did not pass pressure test.\n");
        }
        std::process::exit(2);
    }

    let size_str = output::format_bytes(candidate.size_bytes);

    if immediate {
        // Permanent delete — no airlock, no restore
        let prompt = format!(
            "  Permanently delete {} ({})? This cannot be undone.",
            candidate.path.display(),
            size_str
        );
        if !ctx.json && !ctx.yes && !ctx.confirm(&prompt) {
            println!("  Aborted.");
            return Ok(());
        }

        if candidate.path.is_dir() {
            std::fs::remove_dir_all(&candidate.path)?;
        } else {
            std::fs::remove_file(&candidate.path)?;
        }

        if ctx.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "deleted": candidate.path,
                    "size_bytes": candidate.size_bytes,
                    "candidate_id": candidate.id,
                }))?
            );
        } else {
            let red = Style::new().red().bold();
            let bold = Style::new().bold();
            let dim = Style::new().dim();
            println!();
            println!(
                "  {}  {} deleted permanently",
                ctx.style("✓", &red),
                ctx.style(&size_str, &bold),
            );
            println!(
                "     {}",
                ctx.style(&candidate.path.display().to_string(), &dim)
            );
            println!();
        }
        return Ok(());
    }

    // Standard airlock path
    if !ctx.json && !ctx.yes && prof.preferences.confirm_before_airlock {
        let prompt = format!(
            "  Airlock {} ({}) and free {}?",
            candidate.path.display(),
            candidate.id,
            size_str
        );
        if !ctx.confirm(&prompt) {
            println!("  Aborted.");
            return Ok(());
        }
    }

    let entry = airlock_store::airlock_path(
        &candidate.id,
        &candidate.path,
        prof.preferences.airlock_retention_days,
    )?;

    let mut manifest = airlock_store::load_manifest()?;
    manifest.entries.push(entry.clone());
    airlock_store::save_manifest(&manifest)?;

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&entry)?);
        return Ok(());
    }

    let green = Style::new().green().bold();
    let bold = Style::new().bold();
    let dim = Style::new().dim();

    println!();
    println!(
        "  {}  {} freed",
        ctx.style("✓", &green),
        ctx.style(&size_str, &bold),
    );
    println!(
        "     {} → airlock",
        ctx.style(&candidate.path.display().to_string(), &dim)
    );
    println!(
        "     auto-purge in {} days  ·  restore with: diskspace restore {}",
        prof.preferences.airlock_retention_days,
        ctx.style(&entry.id, &dim),
    );
    println!();

    Ok(())
}

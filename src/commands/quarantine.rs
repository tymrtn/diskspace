use anyhow::{Context as _, Result};
use console::Style;

use crate::commands::check;
use crate::commands::detect::build_candidates_pub;
use crate::commands::scan::scan_cache_path;
use crate::core::quarantine_store;
use crate::core::scanner::ScanResult;
use crate::output::{self, Context};
use crate::profile;

pub fn run(target: &str, ctx: &Context) -> Result<()> {
    let cache = scan_cache_path();
    if !cache.exists() {
        if ctx.json {
            eprintln!(r#"{{"error":"no scan found","hint":"run disk-advisor scan first"}}"#);
        } else {
            eprintln!("  No scan found. Run `disk-advisor scan` first.");
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
                eprintln!(r#"{{"error":"candidate not found","hint":"run disk-advisor detect"}}"#);
            } else {
                eprintln!("\n  Candidate '{}' not found. Run `disk-advisor detect` first.\n", target);
            }
            std::process::exit(1);
        }
    };

    // Always pressure-test before quarantine
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
            eprintln!("  Quarantine aborted — candidate did not pass pressure test.\n");
        }
        std::process::exit(2);
    }

    // Confirmation prompt
    let size_str = output::format_bytes(candidate.size_bytes);
    if !ctx.json && !ctx.yes && prof.preferences.confirm_before_quarantine {
        let prompt = format!(
            "  Quarantine {} ({}) and free {}?",
            candidate.path.display(),
            candidate.id,
            size_str
        );
        if !ctx.confirm(&prompt) {
            println!("  Aborted.");
            return Ok(());
        }
    }

    let entry = quarantine_store::quarantine_path(
        &candidate.id,
        &candidate.path,
        prof.preferences.quarantine_retention_days,
    )?;

    let mut manifest = quarantine_store::load_manifest()?;
    manifest.entries.push(entry.clone());
    quarantine_store::save_manifest(&manifest)?;

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
        "     {} → quarantine",
        ctx.style(&candidate.path.display().to_string(), &dim)
    );
    println!(
        "     auto-purge in {} days  ·  restore with: disk-advisor restore {}",
        prof.preferences.quarantine_retention_days,
        ctx.style(&entry.id, &dim),
    );
    println!();

    Ok(())
}

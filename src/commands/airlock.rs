use anyhow::{Context as _, Result};
use console::Style;

use crate::commands::check;
use crate::commands::detect::build_candidates_pub;
use crate::commands::scan::scan_cache_path;
use crate::core::airlock_store;
use crate::core::grant::Grant;
use crate::core::history::{self, ActionKind, Entry as HistEntry};
use crate::core::scanner::ScanResult;
use crate::output::{self, Context};
use crate::profile;
use std::path::Path;

const IMMEDIATE_MIN_CONFIDENCE: f32 = 0.85;

/// `grant` is threaded through but only consulted under the `actuation` feature,
/// and ALWAYS strictly after `pressure_test` returns `safe == true`. Without the
/// feature it is ignored and the existing human-consent flow is unchanged.
pub fn run(
    target: &str,
    immediate: bool,
    unsafe_confidence: bool,
    grant: Option<&Grant>,
    ctx: &Context,
) -> Result<()> {
    // Keep the parameter live for the non-actuation build without the
    // unused-variable lint (the grant is intentionally ignored there).
    #[cfg(not(feature = "actuation"))]
    let _ = grant;
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

    // Whether a present, valid grant will SUBSTITUTE for typed-id consent on a
    // below-floor `--immediate`. Under the `actuation` feature, if a grant is
    // present we DEFER the below-floor override decision to a grant consultation
    // that happens strictly AFTER the pressure-test clears the candidate (the
    // grant can never make an unsafe candidate actionable). Without the feature,
    // or without a grant, this stays false and the human typed-consent path runs
    // exactly as before.
    #[cfg(feature = "actuation")]
    let grant_may_satisfy_floor = grant.is_some();
    #[cfg(not(feature = "actuation"))]
    let grant_may_satisfy_floor = false;

    // --immediate requires high confidence, OR --unsafe-confidence + typed consent,
    // OR (under actuation) a present grant that authorizes it after the gate.
    if immediate && candidate.confidence < IMMEDIATE_MIN_CONFIDENCE && !grant_may_satisfy_floor {
        if !unsafe_confidence {
            if ctx.json {
                eprintln!(
                    r#"{{"error":"confidence_too_low","confidence":{:.2},"required":{:.2},"hint":"use --unsafe-confidence and re-type the candidate id to override"}}"#,
                    candidate.confidence, IMMEDIATE_MIN_CONFIDENCE
                );
            } else {
                eprintln!(
                    "\n  --immediate requires confidence ≥ {:.0}%  (this candidate is {:.0}%)\n  Override with: diskspace airlock {} --immediate --unsafe-confidence\n  Or use airlock (reversible): diskspace airlock {}\n",
                    IMMEDIATE_MIN_CONFIDENCE * 100.0,
                    candidate.confidence * 100.0,
                    target,
                    target,
                );
            }
            std::process::exit(3);
        }
        // Show consequences explicitly before asking for typed consent
        if !ctx.json {
            let dim = console::Style::new().dim();
            let yellow = console::Style::new().yellow();
            eprintln!();
            eprintln!(
                "  {}",
                ctx.style(&output::rule("low-confidence override", 56), &yellow)
            );
            eprintln!();
            if let Some(cons) = &candidate.consequences {
                eprintln!("  recovery   {}", ctx.style(&cons.recovery, &yellow));
                eprintln!("  impact     {}", ctx.style(&cons.impact, &dim));
                if let Some(cmd) = &cons.recovery_cmd {
                    eprintln!("  recover    {}", ctx.style(cmd, &dim));
                }
            } else {
                eprintln!(
                    "  {}",
                    ctx.style("no consequence metadata for this rule — be careful", &dim)
                );
            }
        }
        if !ctx.confirm_typed_id(&candidate.id) {
            if !ctx.json {
                eprintln!("\n  Override not confirmed. Aborting.\n");
            }
            std::process::exit(3);
        }
    }

    // Always pressure-test before acting. THIS is the HARD gate; all grant logic
    // below runs strictly after it returns safe == true.
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

    // Grant consultation — AFTER the hard gate. Only relevant under actuation when
    // a grant is present AND this is a below-floor `--immediate` that the grant is
    // standing in for typed consent on. `allows()` is the pure in-bound check; on
    // Deny we SKIP (act on nothing) and exit non-zero, recording the denial in the
    // JSON output and an audit line. On Allow we proceed; an above-floor candidate
    // or a non-immediate airlock never needs the grant and is unaffected.
    #[cfg(feature = "actuation")]
    {
        use crate::core::grant::{self, GrantDecision};
        if let Some(g) = grant {
            if immediate && candidate.confidence < IMMEDIATE_MIN_CONFIDENCE {
                let decision = grant::allows(
                    g,
                    candidate.consequences.as_ref(),
                    candidate.confidence,
                    candidate.size_bytes,
                    &candidate.path,
                    0,
                );
                grant::audit(
                    g,
                    "airlock",
                    &candidate.path,
                    candidate.size_bytes,
                    &decision,
                );
                if let GrantDecision::Deny(reason) = decision {
                    if ctx.json {
                        let out = serde_json::json!({
                            "error": "grant_denied",
                            "candidate_id": target,
                            "reason": reason,
                        });
                        eprintln!("{}", serde_json::to_string_pretty(&out)?);
                    } else {
                        eprintln!("\n  Grant denied: {}\n", reason);
                    }
                    std::process::exit(3);
                }
            }
        }
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

        let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
        let df_before = history::free_bytes(Path::new(&home));

        if candidate.path.is_dir() {
            std::fs::remove_dir_all(&candidate.path)?;
        } else {
            std::fs::remove_file(&candidate.path)?;
        }

        let df_after = history::free_bytes(Path::new(&home));
        let actually_freed = match (df_before, df_after) {
            (Some(b), Some(a)) if a > b => Some(a - b),
            _ => None,
        };

        history::append(&HistEntry {
            ts: chrono::Utc::now(),
            command: ActionKind::Reclaim,
            candidate_id: Some(candidate.id.clone()),
            rule_id: Some(candidate.rule_id.clone()),
            path: candidate.path.clone(),
            size_bytes: candidate.size_bytes,
            df_before,
            df_after,
            actually_freed,
            reversible: false,
            undo_cmd: None,
            rule_confidence: Some(candidate.confidence),
            context: serde_json::Map::new(),
        });

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

    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let df_before = history::free_bytes(Path::new(&home));

    let (entry, kind) = airlock_store::airlock_path(
        &candidate.id,
        &candidate.path,
        prof.preferences.airlock_retention_days,
    )?;

    let mut manifest = airlock_store::load_manifest()?;
    manifest.entries.push(entry.clone());
    airlock_store::save_manifest(&manifest)?;

    let df_after = history::free_bytes(Path::new(&home));
    let actually_freed = match (kind, df_before, df_after) {
        (airlock_store::MoveKind::CopyRemove, Some(b), Some(a)) if a > b => Some(a - b),
        (airlock_store::MoveKind::Rename, _, _) => None, // bytes still on disk
        _ => None,
    };
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
    history::append(&HistEntry {
        ts: chrono::Utc::now(),
        command: ActionKind::Airlock,
        candidate_id: Some(candidate.id.clone()),
        rule_id: Some(candidate.rule_id.clone()),
        path: candidate.path.clone(),
        size_bytes: candidate.size_bytes,
        df_before,
        df_after,
        actually_freed,
        reversible: true,
        undo_cmd: Some(format!("diskspace restore {}", entry.id)),
        rule_confidence: Some(candidate.confidence),
        context: ctx_map,
    });

    if ctx.json {
        let payload = serde_json::json!({
            "entry": entry,
            "move_kind": match kind {
                airlock_store::MoveKind::Rename => "rename",
                airlock_store::MoveKind::CopyRemove => "copy_remove",
            },
            "actually_freed": kind == airlock_store::MoveKind::CopyRemove,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let green = Style::new().green().bold();
    let yellow = Style::new().yellow();
    let bold = Style::new().bold();
    let dim = Style::new().dim();

    println!();
    match kind {
        airlock_store::MoveKind::CopyRemove => {
            println!(
                "  {}  {} freed",
                ctx.style("✓", &green),
                ctx.style(&size_str, &bold),
            );
        }
        airlock_store::MoveKind::Rename => {
            println!(
                "  {}  {} staged for purge  {}",
                ctx.style("◐", &yellow),
                ctx.style(&size_str, &bold),
                ctx.style(
                    "(same-volume rename — bytes still on disk until purge)",
                    &dim
                ),
            );
        }
    }
    println!(
        "     {} → airlock",
        ctx.style(&candidate.path.display().to_string(), &dim)
    );
    println!(
        "     auto-purge in {} days  ·  restore with: diskspace restore {}",
        prof.preferences.airlock_retention_days,
        ctx.style(&entry.id, &dim),
    );
    if kind == airlock_store::MoveKind::Rename {
        println!(
            "     {} {}",
            ctx.style("→", &yellow),
            ctx.style(
                "to actually free now: diskspace purge --older-than 0 --yes",
                &dim
            ),
        );
    }
    println!();

    Ok(())
}

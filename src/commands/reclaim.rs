use anyhow::{Context as _, Result};
use console::Style;
use std::path::Path;

use crate::commands::check;
use crate::commands::detect::build_candidates_pub;
use crate::commands::scan::scan_cache_path;
use crate::core::candidate::Candidate;
use crate::core::grant::Grant;
use crate::core::history::{self, ActionKind, Entry as HistEntry};
use crate::core::scanner::ScanResult;
use crate::output::{self, Context};
use crate::profile;

const MIN_CONFIDENCE: f32 = 0.85;

/// `grant` is threaded through but only consulted under the `actuation` feature,
/// and ALWAYS strictly after `pressure_test` has returned `safe == true`. Without
/// the feature it is ignored and the existing human-consent flow is unchanged.
pub fn run(
    top: usize,
    unsafe_confidence: bool,
    grant: Option<&Grant>,
    ctx: &Context,
) -> Result<()> {
    // Keep the parameter live for the non-actuation build (where the grant is
    // intentionally ignored) without tripping the unused-variable lint.
    #[cfg(not(feature = "actuation"))]
    let _ = grant;
    let cache = scan_cache_path();
    if !cache.exists() {
        if ctx.json {
            eprintln!(r#"{{"error":"no scan found","hint":"run diskspace scan first"}}"#);
        } else {
            eprintln!("\n  No scan found. Run `diskspace scan` first.\n");
        }
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(&cache).context("reading scan cache")?;
    let scan: ScanResult = serde_json::from_str(&content).context("parsing scan cache")?;
    let rules = crate::core::rules::load_builtin()?;
    let prof = profile::load()?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());

    let candidates = build_candidates_pub(&scan, &rules, &prof, &home);

    // Honor the confidence floor unless --unsafe-confidence is set; in that case
    // every below-threshold pick will require typed-id confirmation later.
    let effective_floor = if unsafe_confidence {
        0.0
    } else {
        MIN_CONFIDENCE
    };
    let mut high_conf: Vec<Candidate> = candidates
        .into_iter()
        .filter(|c| c.confidence >= effective_floor)
        .take(top)
        .collect();

    if high_conf.is_empty() {
        if ctx.json {
            println!(r#"{{"reclaimed":[],"message":"no high-confidence candidates"}}"#);
        } else {
            println!(
                "\n  No candidates at confidence ≥ {:.0}%. Run `diskspace detect` and use `airlock` for lower-confidence items.\n",
                MIN_CONFIDENCE * 100.0
            );
        }
        return Ok(());
    }

    // Pressure-test each
    let mut survivors: Vec<Candidate> = Vec::new();
    let mut blocked: Vec<(Candidate, String)> = Vec::new();
    for c in high_conf.drain(..) {
        let result = check::pressure_test(&c.id, &c.path, &prof)?;
        if result.safe {
            survivors.push(c);
        } else {
            let note = result
                .steps
                .iter()
                .find(|s| !s.passed)
                .map(|s| s.note.clone())
                .unwrap_or_else(|| "blocked".into());
            blocked.push((c, note));
        }
    }

    let total_bytes: u64 = survivors.iter().map(|c| c.size_bytes).sum();
    let free_before = free_bytes(Path::new(&home));

    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let red = Style::new().red().bold();
    let yellow = Style::new().yellow();
    let green = Style::new().green().bold();

    if !ctx.json {
        println!();
        println!(
            "  {}",
            ctx.style(&output::rule("reclaim  ·  jettisoning cargo", 56), &dim)
        );
        println!();
        if let Some(fb) = free_before {
            println!(
                "  {}  {}  free now",
                ctx.style("disk", &dim),
                ctx.style(&output::format_bytes(fb), &bold),
            );
            println!();
        }

        for c in &survivors {
            println!(
                "  {}  {:>9}  {}  {}",
                ctx.style("✓", &green),
                ctx.style(&output::format_bytes(c.size_bytes), &bold),
                ctx.style(&format!("{:>4.0}%", c.confidence * 100.0), &yellow),
                ctx.style(&c.path.display().to_string(), &dim),
            );
        }
        for (c, note) in &blocked {
            println!(
                "  {}  {:>9}  {}  {}  {}",
                ctx.style("✗", &red),
                ctx.style(&output::format_bytes(c.size_bytes), &dim),
                ctx.style(&format!("{:>4.0}%", c.confidence * 100.0), &dim),
                ctx.style(&c.path.display().to_string(), &dim),
                ctx.style(&format!("(skipped: {})", note), &dim),
            );
        }

        println!();
        println!(
            "  {}  {}  ready to permanently delete  ·  {} blocked",
            ctx.style("→", &yellow),
            ctx.style(&output::format_bytes(total_bytes), &bold),
            blocked.len(),
        );
        println!();
    }

    if survivors.is_empty() {
        if ctx.json {
            println!(r#"{{"reclaimed":[],"message":"all candidates blocked by pressure test"}}"#);
        } else {
            println!("  Nothing to reclaim — all candidates blocked.\n");
        }
        return Ok(());
    }

    if !ctx.json && !ctx.yes {
        let prompt = format!(
            "  Permanently delete {} item(s) totaling {}? This cannot be undone.",
            survivors.len(),
            output::format_bytes(total_bytes)
        );
        if !ctx.confirm(&prompt) {
            println!("  Aborted.");
            return Ok(());
        }
    }

    // Below-floor consent. A survivor below MIN_CONFIDENCE needs an explicit
    // override before we permanently delete it. There are two override paths:
    //
    //   * The grant path (only when the `actuation` feature is built AND a valid
    //     grant is present): the grant SUBSTITUTES for typed-id consent on a
    //     below-floor survivor whose action falls inside its bound. The grant is
    //     consulted ONLY here, strictly AFTER the pressure-test already cleared
    //     the survivor (`result.safe == true` above) — it can NEVER make an unsafe
    //     candidate actionable. Denied below-floor survivors are SKIPPED (removed
    //     from the act-list) and recorded so the JSON output and the audit log
    //     both show the denial.
    //   * The human path (no feature, or no grant): the existing typed-id consent
    //     loop, unchanged.
    //
    // Above-floor survivors already cleared the human floor and never consult a
    // grant. `grant_denied` collects the JSON records for skipped survivors. It is
    // only mutated under the `actuation` feature (`allow(unused_mut)` keeps the
    // non-actuation build warning-free, where it stays an empty Vec).
    #[allow(unused_mut)]
    let mut grant_denied: Vec<serde_json::Value> = Vec::new();

    #[cfg(feature = "actuation")]
    let grant_acted: Vec<(String, u64)> = {
        use crate::core::grant::{self, GrantDecision};
        let mut acted = Vec::new();
        if let Some(g) = grant {
            // Track cumulative spend across this run so max_bytes bounds the WHOLE
            // batch, not each item in isolation.
            let mut spent: u64 = 0;
            let mut kept: Vec<Candidate> = Vec::with_capacity(survivors.len());
            for c in survivors.drain(..) {
                if c.confidence >= MIN_CONFIDENCE {
                    // Above the floor — no grant needed.
                    kept.push(c);
                    continue;
                }
                let decision = grant::allows(
                    g,
                    c.consequences.as_ref(),
                    c.confidence,
                    c.size_bytes,
                    &c.path,
                    spent,
                );
                // Audit the consultation regardless of outcome.
                grant::audit(g, "reclaim", &c.path, c.size_bytes, &decision);
                match decision {
                    GrantDecision::Allow => {
                        spent = spent.saturating_add(c.size_bytes);
                        acted.push((c.id.clone(), c.size_bytes));
                        kept.push(c);
                    }
                    GrantDecision::Deny(reason) => {
                        if !ctx.json {
                            let dim = Style::new().dim();
                            println!(
                                "  {}  {}  grant denied: {}",
                                ctx.style("✗", &Style::new().red().bold()),
                                ctx.style(&c.id, &dim),
                                ctx.style(&reason, &dim),
                            );
                        }
                        grant_denied.push(serde_json::json!({
                            "id": c.id,
                            "path": c.path,
                            "size_bytes": c.size_bytes,
                            "reason": reason,
                        }));
                        // SKIP: do not act on a denied candidate.
                    }
                }
            }
            survivors = kept;
        }
        acted
    };

    // Typed-id consent fallback: only when NO grant satisfied the override above.
    // Under actuation with a present grant, every below-floor survivor was already
    // resolved (allowed→kept, denied→dropped), so there is nothing left below the
    // floor and this loop is a no-op. Without the feature (or without a grant) it
    // is the unchanged human path.
    if unsafe_confidence {
        let low_conf: Vec<&Candidate> = survivors
            .iter()
            .filter(|c| c.confidence < MIN_CONFIDENCE)
            .collect();
        if !low_conf.is_empty() {
            let yellow = Style::new().yellow();
            println!();
            println!(
                "  {}  {} below-threshold item(s) — confirm each by id",
                ctx.style("⚠", &yellow),
                low_conf.len()
            );
            for c in &low_conf {
                println!(
                    "      {} ({:.0}%)",
                    ctx.style(&c.id, &yellow),
                    c.confidence * 100.0
                );
                if !ctx.confirm_typed_id(&c.id) {
                    eprintln!("\n  Aborting — id mismatch on {}.\n", c.id);
                    return Ok(());
                }
            }
        }
    }

    let mut deleted: Vec<serde_json::Value> = Vec::new();
    let mut deleted_bytes: u64 = 0;
    for c in &survivors {
        let result = if c.path.is_dir() {
            std::fs::remove_dir_all(&c.path)
        } else {
            std::fs::remove_file(&c.path)
        };
        match result {
            Ok(_) => {
                deleted_bytes += c.size_bytes;
                deleted.push(serde_json::json!({
                    "id": c.id,
                    "path": c.path,
                    "size_bytes": c.size_bytes,
                }));
                history::append(&HistEntry {
                    ts: chrono::Utc::now(),
                    command: ActionKind::Reclaim,
                    candidate_id: Some(c.id.clone()),
                    rule_id: Some(c.rule_id.clone()),
                    path: c.path.clone(),
                    size_bytes: c.size_bytes,
                    df_before: free_before,
                    df_after: None,
                    actually_freed: None,
                    reversible: false,
                    undo_cmd: None,
                    rule_confidence: Some(c.confidence),
                    context: serde_json::Map::new(),
                });
                if !ctx.json {
                    println!(
                        "  {}  {} freed  {}",
                        ctx.style("✓", &red),
                        ctx.style(&output::format_bytes(c.size_bytes), &bold),
                        ctx.style(&c.path.display().to_string(), &dim),
                    );
                }
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
    }

    let free_after = free_bytes(Path::new(&home));

    if ctx.json {
        let mut out = serde_json::json!({
            "reclaimed": deleted,
            "bytes_deleted": deleted_bytes,
            "free_before": free_before,
            "free_after": free_after,
        });
        if !grant_denied.is_empty() {
            out["grant_denied"] = serde_json::Value::Array(grant_denied);
        }
        #[cfg(feature = "actuation")]
        if !grant_acted.is_empty() {
            out["grant_acted"] = serde_json::Value::Array(
                grant_acted
                    .into_iter()
                    .map(|(id, bytes)| serde_json::json!({ "id": id, "size_bytes": bytes }))
                    .collect(),
            );
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!();
        if let (Some(before), Some(after)) = (free_before, free_after) {
            let delta = after.saturating_sub(before);
            println!(
                "  {}  {} → {}  ({} freed)",
                ctx.style("disk", &bold),
                ctx.style(&output::format_bytes(before), &dim),
                ctx.style(&output::format_bytes(after), &green),
                ctx.style(&output::format_bytes(delta), &bold),
            );
        } else {
            println!(
                "  {}  {} freed",
                ctx.style("✓", &green),
                ctx.style(&output::format_bytes(deleted_bytes), &bold),
            );
        }
        println!();
    }

    Ok(())
}

/// Free bytes available on the filesystem containing `path`. Delegates to the
/// single consolidated POSIX `df -kP` parser in [`crate::core::fsutil`] so this
/// path is cross-platform (the old inline `df -k` parse mis-read Linux's
/// line-wrapped `df` output).
fn free_bytes(path: &Path) -> Option<u64> {
    crate::core::fsutil::free_bytes(path)
}

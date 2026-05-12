//! `diskspace undo` — friendlier wrapper around `restore`. Reads the receipts
//! ledger, finds the most recent reversible action, and reverses it.

use anyhow::Result;
use console::Style;

use crate::core::airlock_store;
use crate::core::history::{self, ActionKind, Entry as HistEntry};
use crate::output::{self, Context};

pub fn run(ctx: &Context) -> Result<()> {
    // Find the most recent reversible action in the ledger.
    let entries = history::tail(50)?;
    let target = entries.iter().find(|e| {
        e.reversible
            && matches!(e.command, ActionKind::Airlock | ActionKind::Doctor)
            && e.undo_cmd.is_some()
    });

    let target = match target {
        Some(t) => t,
        None => {
            if ctx.json {
                println!(
                    r#"{{"undone":null,"message":"no reversible action found in recent history"}}"#
                );
            } else {
                println!(
                    "\n  {}  No reversible action found in recent history.\n  Try `diskspace receipt` to see what's in the ledger.\n",
                    Style::new().dim().apply_to("○")
                );
            }
            return Ok(());
        }
    };

    // Find the matching airlock entry in the manifest using candidate_id +
    // the original path. (We don't persist the airlock entry id in history
    // directly — it's encoded in the undo_cmd, which we parse below.)
    let undo_id = match parse_id_from_undo_cmd(target.undo_cmd.as_deref()) {
        Some(id) => id,
        None => {
            eprintln!(
                "  Could not parse the undo id from the ledger entry. Try `diskspace restore --all` or look at `diskspace status`."
            );
            std::process::exit(1);
        }
    };

    if !ctx.json {
        let dim = Style::new().dim();
        let bold = Style::new().bold();
        let yellow = Style::new().yellow();
        println!();
        println!(
            "  {}",
            ctx.style(
                &output::rule("undo  ·  reverse last reversible action", 60),
                &dim
            )
        );
        println!();
        println!(
            "  {:<10}  {}",
            ctx.style("path", &bold),
            ctx.style(&target.path.display().to_string(), &dim)
        );
        println!(
            "  {:<10}  {}",
            ctx.style("size", &bold),
            ctx.style(&output::format_bytes(target.size_bytes), &yellow)
        );
        println!(
            "  {:<10}  {}",
            ctx.style("when", &bold),
            ctx.style(&target.ts.format("%Y-%m-%d %H:%M UTC").to_string(), &dim)
        );
        println!(
            "  {:<10}  {}",
            ctx.style("via", &bold),
            ctx.style(&format!("airlock id {}", undo_id), &dim)
        );
        println!();
    }

    if !ctx.json && !ctx.yes {
        let prompt = format!(
            "  Restore {} to {}?",
            output::format_bytes(target.size_bytes),
            target.path.display()
        );
        if !ctx.confirm(&prompt) {
            println!("  Aborted.");
            return Ok(());
        }
    }

    // Look up the airlock entry in the manifest, restore it, and remove from manifest.
    let mut manifest = airlock_store::load_manifest()?;
    let idx = manifest.entries.iter().position(|e| e.id == undo_id);
    let idx = match idx {
        Some(i) => i,
        None => {
            if ctx.json {
                eprintln!(
                    r#"{{"error":"airlock_entry_not_found","id":"{}","hint":"may have been purged already"}}"#,
                    undo_id
                );
            } else {
                eprintln!(
                    "\n  Airlock entry '{}' not found — likely already purged.\n  Run `diskspace status` to see what's still recoverable.\n",
                    undo_id
                );
            }
            std::process::exit(1);
        }
    };

    let entry = manifest.entries[idx].clone();
    airlock_store::restore_entry(&entry)?;
    manifest.entries.remove(idx);
    airlock_store::save_manifest(&manifest)?;

    // Record the restore in history.
    history::append(&HistEntry {
        ts: chrono::Utc::now(),
        command: ActionKind::Restore,
        candidate_id: Some(entry.candidate_id.clone()),
        rule_id: None,
        path: entry.original_path.clone(),
        size_bytes: entry.size_bytes,
        df_before: None,
        df_after: None,
        actually_freed: None,
        reversible: false,
        undo_cmd: None,
        rule_confidence: None,
        context: serde_json::Map::new(),
    });

    if ctx.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "undone": true,
                "id": entry.id,
                "path": entry.original_path,
                "size_bytes": entry.size_bytes,
            }))?
        );
    } else {
        let green = Style::new().green().bold();
        let bold = Style::new().bold();
        let dim = Style::new().dim();
        println!();
        println!(
            "  {}  {} restored",
            ctx.style("✓", &green),
            ctx.style(&output::format_bytes(entry.size_bytes), &bold),
        );
        println!(
            "     {}",
            ctx.style(&entry.original_path.display().to_string(), &dim)
        );
        println!();
    }

    Ok(())
}

/// Extracts the airlock entry id from a command string like
/// `diskspace restore xcode-derived-data-13832c01-1777897313`.
fn parse_id_from_undo_cmd(cmd: Option<&str>) -> Option<String> {
    let cmd = cmd?;
    cmd.split_whitespace().last().map(|s| s.to_string())
}

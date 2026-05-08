use anyhow::Result;
use console::Style;

use crate::core::airlock_store;
use crate::core::history::{self, ActionKind, Entry as HistEntry};
use crate::output::{self, Context};

pub fn run(older_than: Option<u32>, dry_run: bool, ctx: &Context) -> Result<()> {
    let mut manifest = airlock_store::load_manifest()?;
    let now = chrono::Utc::now();

    if manifest.entries.is_empty() {
        if ctx.json {
            println!(r#"{{"purged":[],"message":"airlock is empty"}}"#);
        } else {
            println!("\n  Airlock is empty — nothing to purge.\n");
        }
        return Ok(());
    }

    // Determine which entries qualify
    let to_purge: Vec<usize> = manifest
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            if let Some(days) = older_than {
                let age = now.signed_duration_since(e.airlocked_at).num_days();
                age >= days as i64
            } else {
                // Default: purge anything past its auto_purge_at date
                now >= e.auto_purge_at
            }
        })
        .map(|(i, _)| i)
        .collect();

    if to_purge.is_empty() {
        if ctx.json {
            println!(r#"{{"purged":[],"message":"no entries eligible for purge"}}"#);
        } else {
            println!("\n  No entries eligible for purge yet.\n");
        }
        return Ok(());
    }

    let red = Style::new().red().bold();
    let bold = Style::new().bold();
    let dim = Style::new().dim();
    let total_bytes: u64 = to_purge
        .iter()
        .map(|&i| manifest.entries[i].size_bytes)
        .sum();

    if dry_run {
        if ctx.json {
            let preview: Vec<_> = to_purge.iter().map(|&i| {
                let e = &manifest.entries[i];
                serde_json::json!({"id": e.id, "size_bytes": e.size_bytes, "path": e.original_path})
            }).collect();
            println!("{}", serde_json::to_string_pretty(&preview)?);
        } else {
            println!();
            println!(
                "  {} (dry run — nothing deleted)",
                ctx.style("Eligible for purge:", &bold)
            );
            println!();
            for &i in &to_purge {
                let e = &manifest.entries[i];
                println!(
                    "  {}  {}  {}",
                    ctx.style("◦", &dim),
                    ctx.style(&output::format_bytes(e.size_bytes), &bold),
                    ctx.style(&e.original_path.display().to_string(), &dim),
                );
            }
            println!();
            println!(
                "  Would free {}. Run without --dry-run to purge.",
                ctx.style(&output::format_bytes(total_bytes), &bold),
            );
            println!();
        }
        return Ok(());
    }

    // Confirm before irreversible delete
    if !ctx.yes && !ctx.json {
        let prompt = format!(
            "  Permanently delete {} ({})? This cannot be undone.",
            to_purge.len(),
            output::format_bytes(total_bytes)
        );
        if !ctx.confirm(&prompt) {
            println!("  Aborted.");
            return Ok(());
        }
    }

    let mut purged = Vec::new();
    for &i in to_purge.iter().rev() {
        let entry = &manifest.entries[i];
        // Remove from airlock store
        if entry.airlock_path.exists() {
            if entry.airlock_path.is_dir() {
                std::fs::remove_dir_all(&entry.airlock_path)?;
            } else {
                std::fs::remove_file(&entry.airlock_path)?;
            }
            // Clean up slot dir
            if let Some(slot) = entry.airlock_path.parent() {
                let _ = std::fs::remove_dir(slot);
            }
        }
        if !ctx.json {
            println!(
                "  {}  {} purged  {}",
                ctx.style("✓", &red),
                ctx.style(&output::format_bytes(entry.size_bytes), &bold),
                ctx.style(&entry.original_path.display().to_string(), &dim),
            );
        }
        purged.push(serde_json::json!({
            "id": entry.id,
            "size_bytes": entry.size_bytes,
            "original_path": entry.original_path,
        }));
        history::append(&HistEntry {
            ts: chrono::Utc::now(),
            command: ActionKind::Purge,
            candidate_id: Some(entry.candidate_id.clone()),
            rule_id: None,
            path: entry.original_path.clone(),
            size_bytes: entry.size_bytes,
            df_before: None,
            df_after: None,
            actually_freed: Some(entry.size_bytes), // purge actually frees bytes
            reversible: false,
            undo_cmd: None,
            rule_confidence: None,
            context: serde_json::Map::new(),
        });
        manifest.entries.remove(i);
    }

    airlock_store::save_manifest(&manifest)?;

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&purged)?);
    } else {
        println!();
        println!(
            "  {} freed permanently.",
            ctx.style(&output::format_bytes(total_bytes), &bold)
        );
        println!();
    }

    Ok(())
}

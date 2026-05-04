use anyhow::Result;
use console::Style;

use crate::core::quarantine_store;
use crate::output::{self, Context};

pub fn run(target: Option<&str>, all: bool, ctx: &Context) -> Result<()> {
    let mut manifest = quarantine_store::load_manifest()?;

    if manifest.entries.is_empty() {
        if ctx.json {
            println!("{}", r#"{"restored":[],"message":"quarantine is empty"}"#);
        } else {
            println!("\n  Quarantine is empty — nothing to restore.\n");
        }
        return Ok(());
    }

    let to_restore: Vec<usize> = if all {
        (0..manifest.entries.len()).collect()
    } else if let Some(t) = target {
        match manifest.entries.iter().position(|e| {
            e.id == t || e.original_path.to_string_lossy() == t
        }) {
            Some(i) => vec![i],
            None => {
                if ctx.json {
                    eprintln!(r#"{{"error":"entry not found","target":"{}"}}"#, t);
                } else {
                    eprintln!(
                        "\n  Entry '{}' not found. Run `disk-advisor status` to list quarantined items.\n",
                        t
                    );
                }
                std::process::exit(1);
            }
        }
    } else {
        if ctx.json {
            eprintln!(r#"{{"error":"specify a target id or use --all"}}"#);
        } else {
            eprintln!("  Specify an entry ID or use --all. Run `disk-advisor status` to list entries.");
        }
        std::process::exit(1);
    };

    let green = Style::new().green().bold();
    let bold = Style::new().bold();
    let dim = Style::new().dim();
    let mut restored = Vec::new();

    // Restore in reverse so indices stay valid
    for &i in to_restore.iter().rev() {
        let entry = &manifest.entries[i];
        quarantine_store::restore_entry(entry)?;
        if !ctx.json {
            println!(
                "  {}  {} restored  {}",
                ctx.style("✓", &green),
                ctx.style(&output::format_bytes(entry.size_bytes), &bold),
                ctx.style(&entry.original_path.display().to_string(), &dim),
            );
        }
        restored.push(serde_json::json!({
            "id": entry.id,
            "path": entry.original_path,
            "size_bytes": entry.size_bytes,
        }));
        manifest.entries.remove(i);
    }

    quarantine_store::save_manifest(&manifest)?;

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&restored)?);
    } else {
        println!();
    }

    Ok(())
}

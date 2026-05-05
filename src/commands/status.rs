use anyhow::Result;
use console::Style;

use crate::core::airlock_store;
use crate::output::{self, Context};

pub fn run(ctx: &Context) -> Result<()> {
    let manifest = airlock_store::load_manifest()?;
    let now = chrono::Utc::now();

    if ctx.json {
        let total: u64 = manifest.entries.iter().map(|e| e.size_bytes).sum();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "airlock": manifest.entries,
                "total_bytes": total,
                "count": manifest.entries.len(),
            }))?
        );
        return Ok(());
    }

    let bold = Style::new().bold();
    let dim = Style::new().dim();
    let yellow = Style::new().yellow();
    let red = Style::new().red();

    println!();
    println!(
        "  {}",
        ctx.style(&output::rule("airlock status", 56), &dim)
    );
    println!();

    if manifest.entries.is_empty() {
        println!("  {}", ctx.style("Airlock is empty.", &dim));
        println!();
        return Ok(());
    }

    let total: u64 = manifest.entries.iter().map(|e| e.size_bytes).sum();

    for entry in &manifest.entries {
        let days_left = entry.auto_purge_at.signed_duration_since(now).num_days();
        let age_style = if days_left <= 3 {
            Style::new().red()
        } else if days_left <= 7 {
            Style::new().yellow()
        } else {
            dim.clone()
        };

        println!(
            "  {}  {:>9}  {}",
            ctx.style("◦", &yellow),
            ctx.style(&output::format_bytes(entry.size_bytes), &bold),
            ctx.style(&entry.original_path.display().to_string(), &dim),
        );
        println!(
            "     id: {}  ·  purges in {} days",
            ctx.style(&entry.id, &dim),
            ctx.style(&days_left.max(0).to_string(), &age_style),
        );
        println!();
    }

    println!(
        "  {} held  ·  {} total",
        ctx.style(&manifest.entries.len().to_string(), &bold),
        ctx.style(&output::format_bytes(total), &bold),
    );
    println!(
        "  restore: {}  ·  purge now: {}",
        ctx.style("disk-advisor restore <id>", &dim),
        ctx.style("disk-advisor purge --dry-run", &red),
    );
    println!();

    Ok(())
}

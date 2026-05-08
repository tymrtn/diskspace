use anyhow::Result;
use chrono::Utc;
use console::Style;

use crate::core::history;
use crate::output::{self, Context};

pub fn run(last: usize, ctx: &Context) -> Result<()> {
    let entries = history::tail(last)?;

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let green = Style::new().green().bold();
    let red = Style::new().red().bold();
    let yellow = Style::new().yellow();

    println!();
    println!(
        "  {}",
        ctx.style(&output::rule("receipts  ·  action history", 60), &dim)
    );
    println!();

    if entries.is_empty() {
        println!(
            "  {}  no actions recorded yet  ·  history at ~/.diskspace/history.jsonl",
            ctx.style("○", &dim)
        );
        println!();
        return Ok(());
    }

    let total_actually_freed: u64 = entries.iter().filter_map(|e| e.actually_freed).sum();
    let total_size: u64 = entries.iter().map(|e| e.size_bytes).sum();
    let restorable: usize = entries.iter().filter(|e| e.reversible).count();

    println!(
        "  {} {} actions  ·  {} touched  ·  {} actually freed  ·  {} restorable",
        ctx.style("→", &yellow),
        entries.len(),
        ctx.style(&output::format_bytes(total_size), &bold),
        ctx.style(&output::format_bytes(total_actually_freed), &green),
        restorable,
    );
    println!();

    let now = Utc::now();
    for e in &entries {
        let age = now.signed_duration_since(e.ts);
        let age_str = if age.num_days() > 0 {
            format!("{}d ago", age.num_days())
        } else if age.num_hours() > 0 {
            format!("{}h ago", age.num_hours())
        } else if age.num_minutes() > 0 {
            format!("{}m ago", age.num_minutes())
        } else {
            "just now".into()
        };

        let cmd_style = match e.command {
            history::ActionKind::Reclaim | history::ActionKind::Purge => &red,
            history::ActionKind::Airlock => &yellow,
            history::ActionKind::Restore => &green,
            history::ActionKind::Doctor => &yellow,
        };

        println!(
            "  {}  {:<8}  {:<10}  {:>9}  {}",
            ctx.style("◇", &dim),
            ctx.style(&e.command.to_string(), cmd_style),
            ctx.style(&age_str, &dim),
            ctx.style(&output::format_bytes(e.size_bytes), &bold),
            ctx.style(&e.path.display().to_string(), &dim),
        );

        if let Some(undo) = &e.undo_cmd {
            println!(
                "       {} {}",
                ctx.style("↺", &green),
                ctx.style(undo, &dim),
            );
        }
    }

    println!();
    println!(
        "  {}",
        ctx.style("Full ledger: ~/.diskspace/history.jsonl", &dim)
    );
    println!();
    Ok(())
}

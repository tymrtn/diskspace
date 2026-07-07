//! `diskspace trend` — the velocity view: where is the disk HEADED, and what is
//! driving it?
//!
//! Everything here is read-only and advisory: it reads the P1 measurement logs
//! (`df_series.jsonl` for the whole-volume burn rate, `series.jsonl` for
//! per-entry growth attribution) and never touches the filesystem or the
//! actuation path. The snapshot commands (`detect`, `scan`) answer "what can I
//! delete now?"; this answers "why is the disk filling, and how fast?" — the
//! question a threshold alert can't.

use anyhow::Result;
use console::Style;

use crate::core::metrics;
use crate::output::{self, Context};

pub fn run(window_days: f64, top: usize, ctx: &Context) -> Result<()> {
    let trend = metrics::burn_trend(window_days)?;
    let growers = metrics::top_growers(window_days, top)?;

    if ctx.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "trend": trend,
                "growers": growers,
            }))?
        );
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
        ctx.style(
            &output::rule(&format!("trend  ·  last {:.0} day(s)", window_days), 60),
            &dim
        )
    );
    println!();

    match (trend.burn_rate_bytes_per_day, trend.days_to_full) {
        (Some(rate), Some(days)) if rate > 0.0 => {
            println!(
                "  {} filling at {}/day  ·  full in ~{} day(s) at this rate",
                ctx.style("→", &red),
                ctx.style(&output::format_bytes(rate as u64), &bold),
                ctx.style(&days.to_string(), &red),
            );
        }
        (Some(rate), _) if rate < 0.0 => {
            println!(
                "  {} reclaiming {}/day — free space is growing",
                ctx.style("→", &green),
                ctx.style(&output::format_bytes((-rate) as u64), &bold),
            );
        }
        (Some(_), _) => {
            println!("  {} flat — no meaningful drift", ctx.style("→", &dim));
        }
        (None, _) => {
            println!(
                "  {}  not enough samples in the window yet ({} so far) — the watch \
                 agent records one every 5 minutes",
                ctx.style("○", &dim),
                trend.samples,
            );
        }
    }
    println!(
        "  {}",
        ctx.style(&format!("{} df sample(s) in window", trend.samples), &dim)
    );
    println!();

    if growers.is_empty() {
        println!(
            "  {}  no tracked entry grew inside the window",
            ctx.style("○", &dim)
        );
    } else {
        println!(
            "  {} top growers — what is driving the fill:",
            ctx.style("→", &yellow)
        );
        println!();
        for g in &growers {
            println!(
                "  {}  {:>10}  {:>12}  {}",
                ctx.style("◆", &yellow),
                ctx.style(&format!("+{}", output::format_bytes(g.delta_bytes)), &bold),
                ctx.style(
                    &format!("{}/day", output::format_bytes(g.per_day_bytes as u64)),
                    &dim
                ),
                ctx.style(&g.path.display().to_string(), &dim),
            );
        }
    }

    println!();
    println!(
        "  {}",
        ctx.style(
            "Advisory only — nothing here triggers a deletion. `diskspace detect` to act.",
            &dim
        )
    );
    println!();
    Ok(())
}

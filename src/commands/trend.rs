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
    // Free-space history for the sparkline — same window as the fit.
    let cutoff =
        chrono::Utc::now() - chrono::Duration::milliseconds((window_days * 86_400_000.0) as i64);
    let free_series: Vec<f64> = metrics::read_df_series()?
        .into_iter()
        .filter(|s| s.ts >= cutoff)
        .map(|s| s.free_bytes as f64)
        .collect();

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

    if free_series.len() >= 2 {
        let min = free_series.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = free_series
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let now_free = *free_series.last().unwrap();
        println!(
            "  free space   {}   {} now",
            ctx.style(&output::sparkline(&free_series, 36), &bold),
            ctx.style(&output::format_bytes(now_free as u64), &bold),
        );
        println!(
            "  {}",
            ctx.style(
                &format!(
                    "{:width$}low {} · high {}",
                    "",
                    output::format_bytes(min as u64),
                    output::format_bytes(max as u64),
                    width = 13
                ),
                &dim
            )
        );
        println!();
    }

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
    if let (Some(since), Some(step)) = (trend.since, trend.step_bytes) {
        let ago = chrono::Utc::now() - since;
        let ago_str = if ago.num_days() > 0 {
            format!("{}d ago", ago.num_days())
        } else {
            format!("{}h ago", ago.num_hours().max(1))
        };
        println!(
            "  {}",
            ctx.style(
                &format!(
                    "rate measured since {} — a one-time {} of {} reset the trend \
                     (older samples would fake the rate)",
                    ago_str,
                    if step > 0 { "reclaim" } else { "landing" },
                    output::format_bytes(step.unsigned_abs()),
                ),
                &dim
            )
        );
    }
    println!(
        "  {}",
        ctx.style(&format!("{} df sample(s) in fit", trend.samples), &dim)
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
        let max_delta = growers.iter().map(|g| g.delta_bytes).max().unwrap_or(0);
        for g in &growers {
            println!(
                "  {}  {:>10}  {}  {:>12}  {}",
                ctx.style("◆", &yellow),
                ctx.style(&format!("+{}", output::format_bytes(g.delta_bytes)), &bold),
                ctx.style(&output::size_bar(g.delta_bytes, max_delta, 12), &yellow),
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
    println!(
        "  {}",
        ctx.style(
            "Live view: `diskspace top`  ·  agents: `diskspace --json trend`",
            &dim
        )
    );
    println!();
    Ok(())
}

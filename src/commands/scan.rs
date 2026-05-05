use anyhow::Result;
use console::Style;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::time::Duration;

use crate::core::rules;
use crate::core::scanner;
use crate::output::{self, Context};
use crate::profile;

pub fn scan_cache_path() -> PathBuf {
    profile::data_dir().join("scan.json")
}

pub fn run(path: Option<PathBuf>, ctx: &Context) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let root = path.unwrap_or_else(|| PathBuf::from(&home));

    if !root.exists() {
        anyhow::bail!("Path does not exist: {}", root.display());
    }

    // Offer wizard on first scan if no profile exists yet
    if crate::commands::wizard::should_run(ctx) {
        crate::commands::wizard::run(ctx)?;
    }

    let rule_list = rules::load_builtin()?;

    let spinner = if !ctx.json && !ctx.quiet {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("Scanning {}…", root.display()));
        pb.enable_steady_tick(Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    let mut result = scanner::scan(&root, &rule_list)?;
    scanner::aggregate_dir_sizes(&mut result);

    if let Some(pb) = &spinner {
        pb.finish_and_clear();
    }

    // Persist cache
    std::fs::create_dir_all(profile::data_dir())?;
    let json = serde_json::to_string_pretty(&result)?;
    std::fs::write(scan_cache_path(), &json)?;

    if ctx.json {
        println!("{}", json);
        return Ok(());
    }

    // Human output: category summary
    let bold = Style::new().bold();
    let dim = Style::new().dim();
    let cyan = Style::new().cyan().bold();

    let total = output::format_bytes(result.total_bytes);
    let scanned_at = result.scanned_at.format("%H:%M:%S").to_string();

    println!();
    let (top, bot) = output::box_line(&format!("scan  ·  {}  ·  {}", total, root.display()), 60);
    println!("  {}", ctx.style(&top, &dim));
    println!();

    // Group entries by category and show bar chart
    use std::collections::HashMap;
    let mut by_cat: HashMap<String, u64> = HashMap::new();
    for e in &result.entries {
        *by_cat.entry(e.category.to_string()).or_insert(0) += e.size_bytes;
    }

    let max = by_cat.values().copied().max().unwrap_or(1);
    let mut cats: Vec<_> = by_cat.into_iter().collect();
    cats.sort_by(|a, b| b.1.cmp(&a.1));

    for (cat, size) in &cats {
        if *size == 0 {
            continue;
        }
        let icon = output::category_icon(cat);
        let cat_style = output::category_style(cat);
        let bar = output::size_bar(*size, max, 22);
        let size_str = output::format_bytes(*size);
        println!(
            "  {} {:<18}  {:<22}  {:>8}",
            ctx.style(icon, &cat_style),
            ctx.style(cat, &bold),
            ctx.style(&bar, &cat_style),
            ctx.style(&size_str, &dim),
        );
    }

    println!();
    println!("  {}", ctx.style(&bot, &dim));
    // Show cloud placeholder notice if any files were skipped
    if result.cloud_placeholder_bytes > 0 {
        let cloud_str = output::format_bytes(result.cloud_placeholder_bytes);
        println!(
            "  {} {}",
            ctx.style("☁", &dim),
            ctx.style(
                &format!(
                    "{} in cloud-only files skipped (iCloud / Dropbox — not local)",
                    cloud_str
                ),
                &dim
            ),
        );
    }

    println!();
    println!(
        "  {} {}    {}",
        ctx.style("✓", &Style::new().green().bold()),
        ctx.style(&format!("scan complete  ·  {}", scanned_at), &dim),
        ctx.style("run diskspace detect →", &cyan),
    );
    println!();

    Ok(())
}

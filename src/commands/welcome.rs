use anyhow::Result;
use console::Style;

use crate::output::{self, Context};
use crate::profile;

const LOGO: &str = r"
   ·      ·    ✦    ·       ·  ✦   ·    ·   ·     ·
        ___ ___ ___ _  _____ ___  _   ___ ___
       |   \_ _/ __| |/ / __| _ \/_\ / __| __|
       | |) | |\__ \ ' <\__ \  _/ _ \ (__| _|
       |___/___|___/_|\_\___/_|/_/ \_\___|___|
   ·    ·  ✦   ·   ·       ·  ·   ✦    ·     ·";

pub fn run(ctx: &Context) -> Result<()> {
    if ctx.json {
        println!(r#"{{"message":"Run diskspace --help for usage"}}"#);
        return Ok(());
    }

    // First-run wizard: no profile + interactive TTY
    if crate::commands::wizard::should_run(ctx) {
        crate::commands::wizard::run(ctx)?;
    }

    let cyan = Style::new().cyan();
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let green = Style::new().green().bold();

    if ctx.quiet {
        println!("\n  diskspace — find the dead weight in your cargo hold\n");
        return Ok(());
    }

    println!("{}", ctx.style(LOGO, &cyan));
    println!();
    println!(
        "  {}",
        ctx.style("find the dead weight in your cargo hold", &dim)
    );
    println!();

    // ── ship status ──────────────────────────────────
    let profile_exists = profile::profile_path().exists();
    let scan_exists = crate::commands::scan::scan_cache_path().exists();

    println!("  {}", ctx.style(&output::rule("ship status", 54), &dim));
    println!();

    let check = |ok: bool| -> String {
        if ok {
            ctx.style("✓", &green)
        } else {
            ctx.style("○", &dim)
        }
    };

    // Live disk free/total for $HOME — the number an agent firefighting an ENOSPC
    // needs FIRST, before any scan. Read straight from `df` (the consolidated
    // POSIX parser), so it is always current even when the scan cache is stale.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    match crate::core::fsutil::df_free_and_total(std::path::Path::new(&home)) {
        Ok((free, total)) => {
            let pct = if total > 0 {
                (free as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            // Low free space gets a louder marker so a near-full disk is unmissable.
            let (marker, marker_style) = if pct < 5.0 {
                ("✗", Style::new().red().bold())
            } else if pct < 10.0 {
                ("◐", Style::new().yellow())
            } else {
                ("✓", green.clone())
            };
            println!(
                "  {}  disk free     {}",
                ctx.style(marker, &marker_style),
                ctx.style(
                    &format!(
                        "{} free of {}  ({:.0}%)",
                        output::format_bytes(free),
                        output::format_bytes(total),
                        pct
                    ),
                    &bold
                ),
            );
        }
        Err(_) => {
            println!(
                "  {}  disk free     {}",
                check(false),
                ctx.style("unavailable (df failed)", &dim)
            );
        }
    }

    println!(
        "  {}  crew profile  {}",
        check(profile_exists),
        if profile_exists {
            ctx.style("calibrated", &bold)
        } else {
            ctx.style("not set    →  diskspace profile edit", &dim)
        }
    );
    // Scan age makes a STALE survey visible: "scanned 2h ago" vs "no scan yet".
    let scan_age = scan_age_label();
    println!(
        "  {}  hold survey   {}",
        check(scan_exists),
        match &scan_age {
            Some(age) => ctx.style(age, &bold),
            None => ctx.style("not run    →  diskspace survey", &dim),
        }
    );
    println!();

    // ── flight plan ───────────────────────────────────
    println!("  {}", ctx.style(&output::rule("flight plan", 54), &dim));
    println!();

    let steps: &[(&str, &str)] = &[
        (
            "diskspace survey",
            "survey your cargo hold (the broad categorized walk)",
        ),
        ("diskspace detect", "find dead weight, ranked by yield"),
        ("diskspace check <id>", "pressure-test before venting"),
        ("diskspace airlock <id>", "stage cargo for safe disposal"),
        ("diskspace reclaim", "jettison high-confidence weight NOW"),
        (
            "diskspace scan",
            "sweep for the largest uncharted dirs (was `hunt`)",
        ),
    ];

    for (cmd, desc) in steps {
        println!(
            "  {}  {}",
            ctx.style(&format!("{:<32}", cmd), &cyan),
            ctx.style(desc, &dim)
        );
    }

    println!();
    // Transition hint: `scan` changed meaning this release. The full categorized
    // walk of $HOME is now `survey`; `scan` sweeps for the large uncharted dirs no
    // rule covers (the command formerly called `hunt`).
    println!(
        "  {}",
        ctx.style(
            "Note: the full categorized walk is now `diskspace survey`; `diskspace scan` sweeps for uncharted dirs.",
            &dim
        )
    );
    println!();
    println!("  {}", ctx.style(&output::rule("", 54), &dim));
    println!();

    Ok(())
}

/// Human-readable age of the cached scan, e.g. `scanned 2h ago` / `scanned just
/// now`. `None` when there is no readable scan cache (so welcome prints the "not
/// run" hint instead). Reads ONLY the `scanned_at` field — a torn/legacy cache that
/// fails to parse is treated as "no scan" rather than crashing welcome.
fn scan_age_label() -> Option<String> {
    let cache = crate::commands::scan::scan_cache_path();
    let content = std::fs::read_to_string(&cache).ok()?;
    let scan: crate::core::scanner::ScanResult = serde_json::from_str(&content).ok()?;
    Some(format!(
        "scanned {}",
        humanize_age(chrono::Utc::now().signed_duration_since(scan.scanned_at))
    ))
}

/// Render a `chrono::Duration` as a compact relative age: `just now`, `5m ago`,
/// `2h ago`, `3d ago`. A negative span (clock skew — a scan stamped in the future)
/// reads as `just now` rather than a nonsense negative.
fn humanize_age(d: chrono::Duration) -> String {
    let secs = d.num_seconds();
    if secs < 60 {
        "just now".to_string()
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanize_age_buckets() {
        assert_eq!(humanize_age(chrono::Duration::seconds(5)), "just now");
        assert_eq!(humanize_age(chrono::Duration::seconds(305)), "5m ago");
        assert_eq!(humanize_age(chrono::Duration::seconds(7200)), "2h ago");
        assert_eq!(
            humanize_age(chrono::Duration::seconds(3 * 86_400)),
            "3d ago"
        );
        // Clock skew (future timestamp) must not produce a negative age.
        assert_eq!(humanize_age(chrono::Duration::seconds(-10)), "just now");
    }
}

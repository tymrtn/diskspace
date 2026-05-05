use anyhow::Result;
use console::Style;

use crate::output::{self, Context};
use crate::profile;

const LOGO: &str = r"
  ·▄▄▄▄  ▪  .▄▄ · ▄ •▄      ▄▄▄· ·▄▄▄▄  ▌ ▐·▪  .▄▄ · ▄▄▄
  ██▪ ██ ██ ▐█ ▀. █▌▄▌▪    ▐█ ▀█ ██▪ ██ ▪█·█▌██ ▐█ ▀. ▀▄ █·
  ▐█· ▐█▌▐█·▄▀▀▀█▄▐▀▀▄·    ▄█▀▀█ ▐█· ▐█▌▐█▐█•▐█·▄▀▀▀█▄▐▀▀▄
  ██. ██ ▐█▌▐█▄▪▐█▐█.█▌    ▐█ ▪▐▌██. ██  ███ ▐█▌▐█▄▪▐█▐█•█▌
  ▀▀▀▀▀• ▀▀▀ ▀▀▀▀ ·▀  ▀     ▀  ▀ ▀▀▀▀▀• . ▀  ▀▀▀ ▀▀▀▀ .▀  ▀";

pub fn run(ctx: &Context) -> Result<()> {
    if ctx.json {
        println!(r#"{{"message":"Run disk-advisor --help for usage"}}"#);
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

    // Small tasteful header instead of full logo in quiet mode
    if ctx.quiet {
        println!("\n  disk-advisor — find and reclaim disk space safely\n");
        return Ok(());
    }

    println!("{}", ctx.style(LOGO, &cyan));
    println!();
    println!(
        "  {}",
        ctx.style(
            "find and safely reclaim your disk's lowest-hanging fruit",
            &dim
        )
    );
    println!();

    // ── state indicator ──────────────────────────────
    let profile_exists = profile::profile_path().exists();
    let scan_exists = crate::commands::scan::scan_cache_path().exists();

    println!("  {}", ctx.style(&output::rule("status", 54), &dim));
    println!();

    let check = |ok: bool| -> String {
        if ok {
            ctx.style("✓", &green)
        } else {
            ctx.style("○", &dim)
        }
    };

    println!(
        "  {}  profile    {}",
        check(profile_exists),
        if profile_exists {
            ctx.style("configured", &bold)
        } else {
            ctx.style("not found  →  disk-advisor profile edit", &dim)
        }
    );
    println!(
        "  {}  scan       {}",
        check(scan_exists),
        if scan_exists {
            ctx.style("cached", &bold)
        } else {
            ctx.style("not run    →  disk-advisor scan", &dim)
        }
    );
    println!();

    // ── quick start ───────────────────────────────────
    println!("  {}", ctx.style(&output::rule("quick start", 54), &dim));
    println!();

    let steps: &[(&str, &str)] = &[
        ("disk-advisor scan", "scan your home directory"),
        ("disk-advisor detect", "find cleanup candidates"),
        ("disk-advisor check <id>", "pressure-test a candidate"),
        ("disk-advisor airlock <id>", "safely reclaim space"),
    ];

    for (cmd, desc) in steps {
        println!(
            "  {}  {}",
            ctx.style(&format!("{:<32}", cmd), &cyan),
            ctx.style(desc, &dim)
        );
    }

    println!();
    println!("  {}", ctx.style(&output::rule("", 54), &dim));
    println!();

    Ok(())
}

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

    println!(
        "  {}  crew profile  {}",
        check(profile_exists),
        if profile_exists {
            ctx.style("calibrated", &bold)
        } else {
            ctx.style("not set    →  diskspace profile edit", &dim)
        }
    );
    println!(
        "  {}  hold survey   {}",
        check(scan_exists),
        if scan_exists {
            ctx.style("cached", &bold)
        } else {
            ctx.style("not run    →  diskspace scan", &dim)
        }
    );
    println!();

    // ── flight plan ───────────────────────────────────
    println!("  {}", ctx.style(&output::rule("flight plan", 54), &dim));
    println!();

    let steps: &[(&str, &str)] = &[
        ("diskspace scan", "survey your cargo hold"),
        ("diskspace detect", "find dead weight, ranked by yield"),
        ("diskspace check <id>", "pressure-test before venting"),
        ("diskspace airlock <id>", "stage cargo for safe disposal"),
        ("diskspace reclaim", "jettison high-confidence weight NOW"),
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

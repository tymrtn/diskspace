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

    // ── ship status: everything already known, drawn without scanning ───────
    // The number an agent firefighting an ENOSPC needs FIRST is live free space;
    // the panel reads it from `df` and then shows the watcher's last sample, the
    // survey's age and owners, trend and incidents, each labelled with how
    // current it is.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let state = crate::commands::known_state::collect(std::path::Path::new(&home));
    crate::commands::known_state::render(&state, "ship status", ctx);

    if !profile::profile_path().exists() {
        println!(
            "  {}  {}",
            ctx.style("○", &dim),
            ctx.style("crew profile not set  →  diskspace profile edit", &dim)
        );
        println!();
    }

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

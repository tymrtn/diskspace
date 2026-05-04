use anyhow::Result;
use crate::output::Context;

pub fn run(_older_than: Option<u32>, _dry_run: bool, ctx: &Context) -> Result<()> {
    if ctx.json {
        eprintln!(r#"{{"error":"purge not yet implemented","milestone":"M2"}}"#);
    } else {
        eprintln!("  `purge` is coming in M2. Nothing has been deleted.");
    }
    std::process::exit(1);
}

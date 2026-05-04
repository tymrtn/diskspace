use anyhow::Result;
use crate::output::Context;

pub fn run(_target: &str, ctx: &Context) -> Result<()> {
    if ctx.json {
        eprintln!(r#"{{"error":"quarantine not yet implemented","milestone":"M2"}}"#);
    } else {
        eprintln!("  `quarantine` is coming in M2. Use `disk-advisor check <id>` first.");
    }
    std::process::exit(1);
}

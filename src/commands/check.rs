use anyhow::Result;
use crate::output::Context;

pub fn run(_candidate_id: &str, ctx: &Context) -> Result<()> {
    if ctx.json {
        eprintln!(r#"{{"error":"check not yet implemented","milestone":"M2"}}"#);
    } else {
        eprintln!("  `check` is coming in M2. Use `disk-advisor detect` to review candidates first.");
    }
    std::process::exit(1);
}

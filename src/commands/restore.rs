use anyhow::Result;
use crate::output::Context;

pub fn run(_target: Option<&str>, _all: bool, ctx: &Context) -> Result<()> {
    if ctx.json {
        eprintln!(r#"{{"error":"restore not yet implemented","milestone":"M2"}}"#);
    } else {
        eprintln!("  `restore` is coming in M2.");
    }
    std::process::exit(1);
}

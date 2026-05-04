use anyhow::Result;
use crate::output::Context;

pub fn run(ctx: &Context) -> Result<()> {
    if ctx.json {
        println!(r#"{{"quarantine":[],"pending_purge":[],"reclaimable_bytes":0}}"#);
    } else {
        println!("\n  Quarantine is empty. No items held.\n");
    }
    Ok(())
}

//! `diskspace investigate` — the read-only answer to "what is going on?".
//!
//! Draws the known-state panel (see [`crate::commands::known_state`]) and
//! nothing else: no survey walk, no airlock, no deletion. It is the same panel
//! the bare `diskspace` launch shows, under a name a notification or an agent
//! can invoke directly.
//!
//! `--json` emits the same state as a machine-readable document.

use anyhow::Result;

use crate::commands::known_state;
use crate::output::Context;

pub fn run(ctx: &Context) -> Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let state = known_state::collect(std::path::Path::new(&home));

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&state)?);
        return Ok(());
    }

    known_state::render(&state, "investigate  ·  known state", ctx);
    Ok(())
}

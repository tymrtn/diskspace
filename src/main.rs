mod commands;
mod core;
mod output;
mod profile;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "disk-advisor")]
#[command(about = "Find and safely reclaim your disk's lowest-hanging fruit")]
#[command(version)]
#[command(
    after_help = "Run without arguments to get started, or try `disk-advisor scan` to begin."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Output results as JSON (for agents and scripts)
    #[arg(long, global = true)]
    json: bool,

    /// Skip confirmation prompts
    #[arg(long, short = 'y', global = true)]
    yes: bool,

    /// Suppress colors and decorations
    #[arg(long, global = true)]
    no_color: bool,

    /// Show full reasoning traces and details
    #[arg(long, short = 'v', global = true)]
    verbose: bool,

    /// Minimal output — no confidence bars or decorations
    #[arg(long, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory and annotate what's there
    Scan {
        /// Path to scan (default: $HOME)
        path: Option<PathBuf>,
    },
    /// Detect cleanup candidates ranked by yield × confidence
    Detect {
        /// Show all candidates (default: top 10)
        #[arg(long)]
        all: bool,
        /// Max candidates to show
        #[arg(long, default_value = "10")]
        top: usize,
    },
    /// Pressure-test a candidate before acting on it
    Check {
        /// Candidate ID from `detect` output
        candidate_id: String,
    },
    /// Reversibly move candidates to airlock
    Airlock {
        /// Candidate ID or file path
        target: String,
        /// Delete immediately without airlock — only allowed for high-confidence candidates (≥0.85)
        #[arg(long)]
        immediate: bool,
    },
    /// Restore an airlocked item to its original location
    Restore {
        /// Candidate ID or path
        target: Option<String>,
        /// Restore everything in airlock
        #[arg(long)]
        all: bool,
    },
    /// Permanently delete airlocked items (irreversible)
    Purge {
        /// Only purge items older than N days
        #[arg(long, value_name = "DAYS")]
        older_than: Option<u32>,
        /// Show what would be purged without doing it
        #[arg(long)]
        dry_run: bool,
    },
    /// Reclaim space NOW — permanently delete top high-confidence candidates (skips airlock)
    Reclaim {
        /// Max items to delete (default: 10)
        #[arg(long, default_value = "10")]
        top: usize,
    },
    /// Show airlock state and pending purges
    Status,
    /// Read or write your personalization profile
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    /// Print the current profile
    Get,
    /// Set a profile value (e.g. domains.ios_development.active=false)
    Set {
        /// key=value to set
        assignment: String,
    },
    /// Open profile in $EDITOR
    Edit,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let ctx = output::Context {
        json: cli.json,
        yes: cli.yes,
        no_color: cli.no_color || !console::user_attended(),
        verbose: cli.verbose,
        quiet: cli.quiet,
    };

    match cli.command {
        None => commands::welcome::run(&ctx),
        Some(Commands::Scan { path }) => commands::scan::run(path, &ctx),
        Some(Commands::Detect { all, top }) => commands::detect::run(all, top, &ctx),
        Some(Commands::Check { candidate_id }) => commands::check::run(&candidate_id, &ctx),
        Some(Commands::Airlock { target, immediate }) => {
            commands::airlock::run(&target, immediate, &ctx)
        }
        Some(Commands::Restore { target, all }) => {
            commands::restore::run(target.as_deref(), all, &ctx)
        }
        Some(Commands::Purge {
            older_than,
            dry_run,
        }) => commands::purge::run(older_than, dry_run, &ctx),
        Some(Commands::Reclaim { top }) => commands::reclaim::run(top, &ctx),
        Some(Commands::Status) => commands::status::run(&ctx),
        Some(Commands::Profile { action }) => match action {
            ProfileAction::Get => commands::profile_cmd::get(&ctx),
            ProfileAction::Set { assignment } => commands::profile_cmd::set(&assignment, &ctx),
            ProfileAction::Edit => commands::profile_cmd::edit(&ctx),
        },
    }
}

mod commands;
mod core;
mod output;
mod profile;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "diskspace")]
#[command(about = "Find and safely reclaim your disk's lowest-hanging fruit")]
#[command(version)]
#[command(after_help = "Run without arguments to get started, or try `diskspace scan` to begin.")]
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
        /// Bypass the 0.85 confidence floor for --immediate. Requires retyping the candidate id.
        #[arg(long)]
        unsafe_confidence: bool,
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
        /// Lower the confidence floor below 0.85. Requires confirming each item by id.
        #[arg(long)]
        unsafe_confidence: bool,
    },
    /// Hunt for the largest directories that no rule covers — find the long tail
    Hunt {
        /// Max results to show (default: 15)
        #[arg(long, default_value = "15")]
        top: usize,
        /// Minimum directory size in MB (default: 500)
        #[arg(long, default_value = "500")]
        min_size_mb: u64,
    },
    /// Show recent action history (the receipts ledger)
    Receipt {
        /// Number of recent entries to show (default: 20)
        #[arg(long, default_value = "20")]
        last: usize,
    },
    /// Explain a path: matching rule, consequences, live pressure-test, recommended command
    Explain {
        /// Path to inspect (~ expands to $HOME)
        path: String,
    },
    /// Emergency recovery — one-command scan + detect + execute to free a target amount
    Doctor {
        /// Free at least this much (e.g. 20G, 500M). Defaults to pressure threshold + 1 GB.
        #[arg(long)]
        need: Option<String>,
    },
    /// Reverse the most recent reversible action from the receipts ledger
    Undo,
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
        Some(Commands::Airlock {
            target,
            immediate,
            unsafe_confidence,
        }) => commands::airlock::run(&target, immediate, unsafe_confidence, &ctx),
        Some(Commands::Restore { target, all }) => {
            commands::restore::run(target.as_deref(), all, &ctx)
        }
        Some(Commands::Purge {
            older_than,
            dry_run,
        }) => commands::purge::run(older_than, dry_run, &ctx),
        Some(Commands::Reclaim {
            top,
            unsafe_confidence,
        }) => commands::reclaim::run(top, unsafe_confidence, &ctx),
        Some(Commands::Hunt { top, min_size_mb }) => commands::hunt::run(top, min_size_mb, &ctx),
        Some(Commands::Receipt { last }) => commands::receipt::run(last, &ctx),
        Some(Commands::Explain { path }) => commands::explain::run(&path, &ctx),
        Some(Commands::Doctor { need }) => commands::doctor::run(need, &ctx),
        Some(Commands::Undo) => commands::undo::run(&ctx),
        Some(Commands::Status) => commands::status::run(&ctx),
        Some(Commands::Profile { action }) => match action {
            ProfileAction::Get => commands::profile_cmd::get(&ctx),
            ProfileAction::Set { assignment } => commands::profile_cmd::set(&assignment, &ctx),
            ProfileAction::Edit => commands::profile_cmd::edit(&ctx),
        },
    }
}

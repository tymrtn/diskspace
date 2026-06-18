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

    /// Path to a signed capability grant (`grant.json`) authorizing autonomous
    /// actuation. Defaults to `preferences.grant_path` from the profile, then to
    /// `~/.diskspace/grant.json`. The grant is VERIFIED against the trusted public
    /// key; it can never widen a candidate past the hard pressure-test. Only
    /// consulted when the binary is built with the `actuation` feature.
    #[arg(long, global = true)]
    grant: Option<String>,
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
        /// Force a fresh live walk of $HOME instead of reading the scan cache.
        /// Slow (minutes on a large disk); the cache path is sub-second.
        #[arg(long)]
        fresh: bool,
    },
    /// Label a large unrule'd directory (git pack, VM disk, model, backup, …) and,
    /// with --yes, take the SAFE ACTION for it (git-repack / reversible airlock /
    /// recommend stow). No path → classify the top unrule'd dirs into a table.
    Classify {
        /// Directory to classify (~ expands to $HOME). Omit to classify the top
        /// unrule'd dirs from the scan cache as a read-only table.
        path: Option<String>,
        /// Execute the safe action for the inferred strategy (git gc for a git pack,
        /// reversible airlock for a VM disk, recommend stow for offloadable data).
        /// Without it, classify only SUGGESTS. (The global `-y/--yes` works too.)
        #[arg(long = "act")]
        act: bool,
    },
    /// Offload cloud-synced data to free LOCAL space WITHOUT deleting it (reversible).
    /// `stow <path>` detects the cloud provider and the safe offload mechanism: iCloud
    /// → `brctl evict` (with --yes); classic Dropbox → advise the Finder online-only
    /// steps (or `maestral excluded add` when Maestral is the active client).
    /// No path → list the cloud-offload candidates + total reclaimable GB (read-only).
    Stow {
        /// Path to offload (~ expands to $HOME). Omit to list cloud-offload
        /// candidates from the scan cache with the total reclaimable-without-deleting
        /// GB (read-only).
        path: Option<String>,
        /// Actually perform the offload (iCloud `brctl evict` / Maestral `excluded
        /// add`). Without it, stow only SUGGESTS the command. (The global `-y/--yes`
        /// works too.) NEVER deletes a local file in ~/Dropbox.
        #[arg(long = "act")]
        act: bool,
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
    /// Build a content-addressed recovery plan WITHOUT executing it (TOCTOU-safe phase 1)
    Plan {
        /// Free at least this much (e.g. 20G, 500M)
        #[arg(long)]
        need: String,
        /// Execution mode the plan records: `airlock` (reversible) or `immediate`
        #[arg(long, default_value = "airlock")]
        mode: String,
    },
    /// Apply a previously-built plan by hash, re-validating every step LIVE first (phase 2)
    Apply {
        /// The plan hash printed by `diskspace plan`
        plan_hash: String,
    },
    /// Run a command; on ENOSPC, free space via the doctor path and re-run it ONCE
    Guard {
        /// The command to run, e.g. --exec "cargo build --release". Tokenized via
        /// shell-words and run by ARGV — never through a shell.
        #[arg(long)]
        exec: String,
        /// How much to free if the command hits ENOSPC (e.g. 20G, 500M). Default 5G.
        #[arg(long)]
        need: Option<String>,
    },
    /// Reverse the most recent reversible action from the receipts ledger
    Undo,
    /// Background disk-pressure monitor (launchd-backed). Nudges at 10% free, urgent at 5%.
    Watch {
        #[command(subcommand)]
        action: WatchAction,
    },
    /// Show airlock state and pending purges
    Status,
    /// Verify the P1 measurement layer's invariants hold at runtime (read-only)
    Selfcheck {
        /// Run the G1–G7 measurement-layer gate
        #[arg(long)]
        measurement: bool,
    },
    /// Read or write your personalization profile
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Issue, inspect, and key the ed25519 capability grants that bound an
    /// autonomous actor. `keygen`/`issue` use the PRIVATE key and run OFF-BOX on
    /// your Mac; the actor box holds only the public key and merely verifies.
    Grant {
        #[command(subcommand)]
        action: GrantAction,
    },
}

#[derive(Subcommand)]
enum WatchAction {
    /// Install the launchd agent so diskspace checks disk pressure in the background
    Install,
    /// Remove the launchd agent
    Uninstall,
    /// Show whether the agent is installed/loaded and what the last check saw
    Status,
    /// Run one disk-pressure check (called by launchd; you can also run it by hand)
    Run,
}

#[derive(Subcommand)]
enum GrantAction {
    /// Generate an ed25519 keypair. Private key → --out (mode 0600, keep OFF the
    /// actor box); public key → ~/.diskspace/grant.pub (or --pub-out).
    Keygen {
        /// Where to write the PRIVATE key (hex, mode 0600). Keep this off-box.
        #[arg(long)]
        out: PathBuf,
        /// Where to write the public key (default: ~/.diskspace/grant.pub)
        #[arg(long)]
        pub_out: Option<PathBuf>,
    },
    /// Mint + sign a grant with the private key (off-box). Writes the signed
    /// grant to ~/.diskspace/grant.json (or --out).
    Issue {
        /// build-recovery | routine-cleanup | agent-autonomy
        #[arg(long)]
        category: String,
        /// Cumulative byte budget, e.g. 20G, 500M, 1024
        #[arg(long)]
        max_bytes: String,
        /// Highest recovery class to authorize: auto | redownload | rebuild |
        /// recreate | manual | irreversible
        #[arg(long)]
        recovery_ceiling: String,
        /// Confidence floor a candidate must meet (0.0–1.0)
        #[arg(long)]
        min_confidence: f32,
        /// Optional glob the path must match (~ expands to $HOME)
        #[arg(long)]
        path_scope: Option<String>,
        /// Validity window, e.g. 2h, 7d, 30m, 90s
        #[arg(long)]
        expires_in: String,
        /// Path to the PRIVATE key (off-box)
        #[arg(long)]
        priv_key: PathBuf,
        /// Where to write the signed grant (default: ~/.diskspace/grant.json)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Show the active grant and whether its signature verifies.
    Show,
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

    // Resolve the capability grant ONCE, here, so every actuation site shares the
    // same loaded+validated authority. Precedence for the grant FILE:
    //   1. `--grant <path>` on the command line
    //   2. `preferences.grant_path` in the profile
    //   3. `~/.diskspace/grant.json` (grant::load's default)
    // `grant::load` parses AND verifies the signature against the trusted public
    // key; a present-but-INVALID grant is a hard error (fail-closed — a corrupt or
    // tampered grant must never silently degrade to "no grant / human consent").
    // A missing file yields `None` (the human-consent fallback). The actor only
    // ever VERIFIES — minting requires the off-box private key it does not hold.
    //
    // Gated on the `actuation` feature: WITHOUT it, the grant is never loaded and
    // every command keeps EXACTLY the existing human-consent behavior (a stray or
    // even malformed grant.json on disk changes nothing). The `grant_ref` is still
    // threaded into the call sites in both builds — the commands simply ignore it
    // when the feature is off.
    #[cfg(feature = "actuation")]
    let grant: Option<core::grant::Grant> = {
        let explicit = cli.grant.clone();
        let from_profile = profile::load()
            .ok()
            .and_then(|p| p.preferences.grant_path.clone());
        let chosen_path = explicit.or(from_profile);
        let load_arg = chosen_path.as_deref().map(std::path::Path::new);
        match core::grant::load(load_arg) {
            Ok(g) => g,
            Err(e) => {
                if ctx.json {
                    println!(
                        "{}",
                        serde_json::json!({ "error": "invalid_grant", "detail": e.to_string() })
                    );
                } else {
                    eprintln!("\n  Grant present but INVALID: {}\n", e);
                }
                std::process::exit(2);
            }
        }
    };
    #[cfg(not(feature = "actuation"))]
    let grant: Option<core::grant::Grant> = {
        // `--grant` is accepted on the CLI in every build for a stable interface,
        // but without the `actuation` feature it is inert. Bind it to silence the
        // unused-field lint and make the no-op explicit.
        let _ = &cli.grant;
        None
    };
    let grant_ref = grant.as_ref();

    match cli.command {
        None => commands::welcome::run(&ctx),
        Some(Commands::Scan { path }) => commands::scan::run(path, &ctx),
        Some(Commands::Detect { all, top }) => commands::detect::run(all, top, &ctx),
        Some(Commands::Check { candidate_id }) => commands::check::run(&candidate_id, &ctx),
        Some(Commands::Airlock {
            target,
            immediate,
            unsafe_confidence,
        }) => commands::airlock::run(&target, immediate, unsafe_confidence, grant_ref, &ctx),
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
        }) => commands::reclaim::run(top, unsafe_confidence, grant_ref, &ctx),
        Some(Commands::Hunt {
            top,
            min_size_mb,
            fresh,
        }) => commands::hunt::run(top, min_size_mb, fresh, &ctx),
        Some(Commands::Classify { path, act }) => {
            // Act on the safe action when EITHER the local `--act` or the global
            // `-y/--yes` is set, so both `classify <p> --yes` and `classify <p>
            // --act` execute (suggest-only otherwise).
            commands::classify::run(path.as_deref(), act || ctx.yes, &ctx)
        }
        Some(Commands::Stow { path, act }) => {
            // Offload (brctl evict / maestral excluded) runs only when EITHER the
            // local `--act` or the global `-y/--yes` is set; suggest-only otherwise.
            commands::stow::run(path.as_deref(), act || ctx.yes, &ctx)
        }
        Some(Commands::Receipt { last }) => commands::receipt::run(last, &ctx),
        Some(Commands::Explain { path }) => commands::explain::run(&path, &ctx),
        Some(Commands::Doctor { need }) => commands::doctor::run(need, grant_ref, &ctx),
        Some(Commands::Plan { need, mode }) => commands::plan::run(&need, &mode, &ctx),
        Some(Commands::Apply { plan_hash }) => commands::apply::run(&plan_hash, grant_ref, &ctx),
        Some(Commands::Guard { exec, need }) => {
            commands::guard::run(&exec, need.as_deref(), grant_ref, &ctx)
        }
        Some(Commands::Undo) => commands::undo::run(&ctx),
        Some(Commands::Watch { action }) => match action {
            WatchAction::Install => commands::watch::install(&ctx),
            WatchAction::Uninstall => commands::watch::uninstall(&ctx),
            WatchAction::Status => commands::watch::status(&ctx),
            WatchAction::Run => commands::watch::run(&ctx),
        },
        Some(Commands::Status) => commands::status::run(&ctx),
        Some(Commands::Selfcheck { measurement }) => commands::selfcheck::run(measurement, &ctx),
        Some(Commands::Profile { action }) => match action {
            ProfileAction::Get => commands::profile_cmd::get(&ctx),
            ProfileAction::Set { assignment } => commands::profile_cmd::set(&assignment, &ctx),
            ProfileAction::Edit => commands::profile_cmd::edit(&ctx),
        },
        Some(Commands::Grant { action }) => match action {
            GrantAction::Keygen { out, pub_out } => {
                commands::grant_cmd::keygen(&out, pub_out.as_deref(), &ctx)
            }
            GrantAction::Issue {
                category,
                max_bytes,
                recovery_ceiling,
                min_confidence,
                path_scope,
                expires_in,
                priv_key,
                out,
            } => commands::grant_cmd::issue(
                &category,
                &max_bytes,
                &recovery_ceiling,
                min_confidence,
                path_scope.as_deref(),
                &expires_in,
                &priv_key,
                out.as_deref(),
                &ctx,
            ),
            GrantAction::Show => commands::grant_cmd::show(&ctx),
        },
    }
}

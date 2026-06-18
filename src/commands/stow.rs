//! `diskspace stow` — the cloud-OFFLOAD advisor + opt-in actuator.
//!
//! OFFLOAD IS NOT DELETE. `stow` frees LOCAL disk by moving a file's bytes to the
//! cloud while keeping the data fully recoverable. Every action it can take is
//! reversible: an evicted iCloud file re-downloads on next open; a Maestral-excluded
//! Dropbox path re-syncs when you un-exclude it. `stow` NEVER deletes a local file
//! inside `~/Dropbox` (the official app would propagate that delete to the cloud =
//! DATA LOSS) and NEVER sets the `com.dropbox.ignored` xattr (which REMOVES the file
//! from the cloud and frees no local space). Those two forbidden operations appear
//! NOWHERE in this command or the crate.
//!
//! HOW it offloads depends entirely on which cloud client owns the path — the policy
//! lives in [`crate::core::cloud`]. `stow` is the command layer over it.
//!
//! `stow <path>` detects the provider + the SAFE offload mechanism, then:
//!   - iCloud: run `brctl evict <path>` (behind `--yes`; report bytes freed).
//!   - classic Dropbox: when Maestral is the ACTIVE client, offer `maestral excluded
//!     add <path>` (behind `--yes`); ELSE ADVISE the exact Finder "Make online-only"
//!     steps + the GB it would free, taking NO filesystem action.
//!   - file-provider Dropbox: ADVISE (eviction is fragile on macOS 14.4+).
//!   - none: explain `stow` only applies to cloud-synced data.
//!
//! `stow` (no path) is the ADVISOR: reuse the `hunt`/`classify` Offload candidates
//! that live under a cloud root and are LOCALLY stored, group them by provider, TOTAL
//! the reclaimable-without-deleting GB, and print a table. Read-only.
//!
//! INVARIANTS: never sudo; HOME-scoped; `stow` DEFAULTS to SUGGEST and only acts
//! (`brctl evict` / `maestral excluded add`) with `--yes`, never silently; honest
//! accounting (real on-disk bytes); `--json` mirrors every form.

use anyhow::Result;
use console::Style;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::cloud::{self, CloudProvider, OffloadMechanism};
use crate::core::history::{self, ActionKind, Entry as HistEntry};
use crate::output::{self, Context};
use crate::profile;

/// `stow` entry point. `path = None` runs the read-only cloud-offload ADVISOR;
/// `path = Some` stows one path (acting only behind `--yes`).
pub fn run(path: Option<&str>, yes: bool, ctx: &Context) -> Result<()> {
    match path {
        Some(p) => stow_one(p, yes, ctx),
        None => stow_advisor(ctx),
    }
}

// ===========================================================================
// `stow <path>` — one path, provider-aware offload.
// ===========================================================================

fn stow_one(raw_path: &str, yes: bool, ctx: &Context) -> Result<()> {
    let path = expand_tilde(raw_path);
    if !path.exists() {
        if ctx.json {
            println!(
                "{}",
                serde_json::json!({ "error": "path_not_found", "path": path })
            );
        } else {
            eprintln!("\n  Path not found: {}\n", path.display());
        }
        std::process::exit(1);
    }

    let provider = cloud::detect_provider(&path);
    let mechanism = cloud::offload_mechanism(provider, mechanism_needs_maestral(provider));
    let on_disk = cloud::is_locally_stored(&path);
    let size = on_disk_size(&path);

    // Nothing to offload if every byte is already online-only — the scanner skips
    // these placeholders, and so must we (offloading what's already offloaded is a
    // no-op that would only confuse the user).
    if provider != CloudProvider::None && !on_disk {
        return report_already_offloaded(&path, provider, ctx);
    }

    match mechanism {
        OffloadMechanism::ICloudEvict => {
            act_or_suggest_command(&path, provider, mechanism, size, yes, ctx)
        }
        OffloadMechanism::MaestralExclude => {
            act_or_suggest_command(&path, provider, mechanism, size, yes, ctx)
        }
        OffloadMechanism::AdviseFinder => advise_finder(&path, size, ctx),
        OffloadMechanism::AdviseFragileEvict => advise_fragile_evict(&path, size, ctx),
        OffloadMechanism::NotApplicable => not_applicable(&path, ctx),
    }
}

/// Whether the provider's mechanism selection needs the (best-effort) Maestral
/// active-client probe. We only PROBE for classic Dropbox — for iCloud and the
/// file-provider the mechanism is fixed regardless of Maestral, so we skip the
/// process spawn entirely.
fn mechanism_needs_maestral(provider: CloudProvider) -> bool {
    match provider {
        CloudProvider::DropboxClassic => cloud::maestral_active(),
        _ => false,
    }
}

/// The ACTIONABLE path (iCloud evict / Maestral exclude). Behind `--yes` we RUN the
/// argv and record a reversible receipt; without it we SUGGEST the exact command.
fn act_or_suggest_command(
    path: &Path,
    provider: CloudProvider,
    mechanism: OffloadMechanism,
    size: u64,
    yes: bool,
    ctx: &Context,
) -> Result<()> {
    let argv =
        cloud::offload_argv(mechanism, path).expect("actionable mechanism always yields an argv");

    if !yes {
        // SUGGEST-ONLY: print the command we WOULD run + the bytes it would free.
        if ctx.json {
            println!(
                "{}",
                serde_json::json!({
                    "path": path,
                    "provider": provider.label(),
                    "mechanism": mechanism.label(),
                    "status": "suggest",
                    "actionable": true,
                    "command": argv,
                    "reclaimable_bytes": size,
                    "note": "OFFLOAD is reversible — the data stays in the cloud. Re-run with --yes to offload.",
                })
            );
            return Ok(());
        }
        print_header(path, provider, mechanism, size, ctx);
        let cyan = Style::new().cyan().bold();
        let dim = Style::new().dim();
        println!(
            "  {}  would run: {}",
            ctx.style("→", &cyan),
            ctx.style(&argv.join(" "), &dim),
        );
        println!(
            "     {}",
            ctx.style(
                &format!(
                    "frees ~{} locally — the data STAYS in the cloud (reversible). Add --yes to offload.",
                    output::format_bytes(size)
                ),
                &dim,
            )
        );
        if matches!(mechanism, OffloadMechanism::ICloudEvict) {
            println!(
                "     {}",
                ctx.style("(brctl evict is macOS-version-dependent)", &dim)
            );
        }
        println!();
        return Ok(());
    }

    // --yes: RUN the offload. df-delta is the honest measure of bytes actually freed.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let df_before = history::free_bytes(Path::new(&home));

    let output = Command::new(&argv[0]).args(&argv[1..]).output();
    let (ran_ok, stderr) = match &output {
        Ok(o) => (
            o.status.success(),
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
        ),
        Err(e) => (false, e.to_string()),
    };

    let df_after = history::free_bytes(Path::new(&home));
    let actually_freed = match (df_before, df_after) {
        (Some(b), Some(a)) if a > b => Some(a - b),
        _ => None,
    };

    if !ran_ok {
        if ctx.json {
            println!(
                "{}",
                serde_json::json!({
                    "path": path,
                    "provider": provider.label(),
                    "mechanism": mechanism.label(),
                    "status": "failed",
                    "command": argv,
                    "error": stderr,
                })
            );
        } else {
            print_header(path, provider, mechanism, size, ctx);
            let red = Style::new().red().bold();
            println!(
                "  {}  offload command failed: {}",
                ctx.style("✗", &red),
                stderr
            );
            println!();
        }
        std::process::exit(2);
    }

    // Honest receipt: an offload is reversible (the cloud still has it). We record
    // the on-disk size we expected to free and the df-delta we actually observed.
    record_offload_receipt(
        path,
        provider,
        mechanism,
        size,
        df_before,
        df_after,
        actually_freed,
    );

    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "path": path,
                "provider": provider.label(),
                "mechanism": mechanism.label(),
                "status": "offloaded",
                "command": argv,
                "reclaimable_bytes": size,
                "actually_freed_bytes": actually_freed,
                "reversible": true,
            })
        );
        return Ok(());
    }

    let green = Style::new().green().bold();
    let bold = Style::new().bold();
    let dim = Style::new().dim();
    print_header(path, provider, mechanism, size, ctx);
    let freed = actually_freed.unwrap_or(size);
    println!(
        "  {}  {} offloaded to the cloud {}",
        ctx.style("✓", &green),
        ctx.style(&output::format_bytes(freed), &bold),
        ctx.style("(reversible — re-downloads on next open)", &dim),
    );
    println!();
    Ok(())
}

/// AdviseFinder: classic Dropbox under the OFFICIAL app. There is NO safe scriptable
/// offload, so we print the exact Finder steps and TOTAL the GB it would free. We
/// take NO filesystem action — not even with `--yes`.
fn advise_finder(path: &Path, size: u64, ctx: &Context) -> Result<()> {
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "path": path,
                "provider": CloudProvider::DropboxClassic.label(),
                "mechanism": OffloadMechanism::AdviseFinder.label(),
                "status": "advise",
                "actionable": false,
                "reclaimable_bytes": size,
                "steps": finder_steps(),
                "note": "Classic Dropbox under the official app has no safe scriptable offload. Make it online-only in Finder. Smart Sync is a paid feature. diskspace will NEVER delete a local file in ~/Dropbox.",
            })
        );
        return Ok(());
    }
    print_header(
        path,
        CloudProvider::DropboxClassic,
        OffloadMechanism::AdviseFinder,
        size,
        ctx,
    );
    let yellow = Style::new().yellow();
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    println!(
        "  {}  No safe scriptable offload for classic Dropbox under the official app.",
        ctx.style("·", &yellow),
    );
    println!(
        "     {}",
        ctx.style(
            &format!(
                "Making this online-only would free ~{} locally (the file stays in your Dropbox cloud).",
                output::format_bytes(size)
            ),
            &bold,
        )
    );
    println!();
    for (i, step) in finder_steps().iter().enumerate() {
        println!("     {} {}", ctx.style(&format!("{}.", i + 1), &dim), step);
    }
    println!();
    println!(
        "     {}",
        ctx.style(
            "Smart Sync / online-only is a PAID Dropbox feature. diskspace never deletes a local file in ~/Dropbox.",
            &dim,
        )
    );
    println!();
    Ok(())
}

/// AdviseFragileEvict: file-provider Dropbox. Eviction is fragile / removed on macOS
/// 14.4+, so we ADVISE primarily and flag the caveat — we never hard-act here.
fn advise_fragile_evict(path: &Path, size: u64, ctx: &Context) -> Result<()> {
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "path": path,
                "provider": CloudProvider::DropboxFileProvider.label(),
                "mechanism": OffloadMechanism::AdviseFragileEvict.label(),
                "status": "advise",
                "actionable": false,
                "reclaimable_bytes": size,
                "steps": finder_steps(),
                "note": "File-provider Dropbox eviction (brctl/fileproviderctl) is fragile or removed on macOS 14.4+. Prefer the Finder online-only route. diskspace never deletes a local file in Dropbox.",
            })
        );
        return Ok(());
    }
    print_header(
        path,
        CloudProvider::DropboxFileProvider,
        OffloadMechanism::AdviseFragileEvict,
        size,
        ctx,
    );
    let yellow = Style::new().yellow();
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    println!(
        "  {}  File-provider Dropbox: eviction is fragile / removed on macOS 14.4+.",
        ctx.style("·", &yellow),
    );
    println!(
        "     {}",
        ctx.style(
            &format!(
                "Making this online-only would free ~{} locally (it stays in your Dropbox cloud).",
                output::format_bytes(size)
            ),
            &bold,
        )
    );
    println!();
    for (i, step) in finder_steps().iter().enumerate() {
        println!("     {} {}", ctx.style(&format!("{}.", i + 1), &dim), step);
    }
    println!();
    Ok(())
}

/// Not under any recognized cloud root — `stow` does not apply. Explain that.
fn not_applicable(path: &Path, ctx: &Context) -> Result<()> {
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "path": path,
                "provider": CloudProvider::None.label(),
                "mechanism": OffloadMechanism::NotApplicable.label(),
                "status": "not_applicable",
                "note": "stow offloads CLOUD-synced data to free local space. This path is not under iCloud or Dropbox. For local-only data use `diskspace classify` / `diskspace detect`.",
            })
        );
        return Ok(());
    }
    print_header(
        path,
        CloudProvider::None,
        OffloadMechanism::NotApplicable,
        0,
        ctx,
    );
    let dim = Style::new().dim();
    let cyan = Style::new().cyan().bold();
    println!(
        "  {}  Not under iCloud or Dropbox — stow only offloads cloud-synced data.",
        ctx.style("·", &dim),
    );
    println!(
        "  {}  for local-only data: {}",
        ctx.style("→", &cyan),
        ctx.style("diskspace classify <path>  /  diskspace detect", &dim),
    );
    println!();
    Ok(())
}

/// Every byte is already online-only — nothing to offload.
fn report_already_offloaded(path: &Path, provider: CloudProvider, ctx: &Context) -> Result<()> {
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "path": path,
                "provider": provider.label(),
                "status": "already_offloaded",
                "reclaimable_bytes": 0,
                "note": "This path is already online-only (no local bytes). Nothing to offload.",
            })
        );
        return Ok(());
    }
    let dim = Style::new().dim();
    println!();
    println!(
        "  {}  {} is already online-only — no local bytes to offload.",
        ctx.style("☁", &dim),
        path.display(),
    );
    println!();
    Ok(())
}

// ===========================================================================
// `stow` (no path) — the cloud-offload ADVISOR (read-only).
// ===========================================================================

/// One advisor row: an Offload-strategy candidate under a cloud root.
struct AdvisorRow {
    path: PathBuf,
    provider: CloudProvider,
    mechanism: OffloadMechanism,
    bytes: u64,
}

fn stow_advisor(ctx: &Context) -> Result<()> {
    // Cache-ONLY and staleness-tolerant: the advisor must never block on a live walk
    // of $HOME. A stale long-tail picture is fine for advice; no cache => advise scan.
    let rows = match crate::commands::hunt::analyze_unruled_cached(50, 500) {
        Some(r) => r,
        None => {
            if ctx.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "candidates": [],
                        "reclaimable_without_deleting_bytes": 0,
                        "count": 0,
                        "note": "No scan cache — run `diskspace scan` first, then `diskspace stow`.",
                    })
                );
            } else {
                println!(
                    "\n  No scan cache yet — run `diskspace scan` first, then `diskspace stow`.\n"
                );
            }
            return Ok(());
        }
    };
    let prof = profile::load().unwrap_or_default();

    // Keep only Offload-strategy rows that are (a) under a cloud root and (b) still
    // locally stored — i.e. genuinely reclaimable-without-deleting.
    let mut advisor: Vec<AdvisorRow> = Vec::new();
    for r in &rows {
        let is_offload = matches!(r.strategy, Some(crate::core::classify::Strategy::Offload));
        if !is_offload {
            continue;
        }
        let provider = cloud::detect_provider(&r.path);
        if provider == CloudProvider::None {
            continue;
        }
        if !cloud::is_locally_stored(&r.path) {
            continue;
        }
        let mechanism = cloud::offload_mechanism(provider, mechanism_needs_maestral(provider));
        advisor.push(AdvisorRow {
            path: r.path.clone(),
            provider,
            mechanism,
            bytes: r.unruled_bytes,
        });
    }
    advisor.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    let total: u64 = advisor.iter().map(|r| r.bytes).sum();
    let _ = &prof; // profile reserved for future per-provider policy; not branched on yet.

    if ctx.json {
        let out: Vec<_> = advisor
            .iter()
            .map(|r| {
                serde_json::json!({
                    "path": r.path,
                    "provider": r.provider.label(),
                    "mechanism": r.mechanism.label(),
                    "actionable": r.mechanism.is_actionable(),
                    "size_bytes": r.bytes,
                    "action": advisor_action_hint(r),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "candidates": out,
                "reclaimable_without_deleting_bytes": total,
                "count": advisor.len(),
                "note": "OFFLOAD frees local space while keeping the data in the cloud — fully reversible, never a deletion.",
            })
        );
        return Ok(());
    }

    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let cyan = Style::new().cyan().bold();
    let magenta = Style::new().magenta();
    let green = Style::new().green().bold();

    println!();
    println!(
        "  {}",
        ctx.style(
            &output::rule("stow  ·  cloud offload (reversible, never deletion)", 64),
            &dim
        )
    );
    println!();

    if advisor.is_empty() {
        println!(
            "  {}",
            ctx.style(
                "No cloud-synced offload candidates found. Run `diskspace scan` first, or your large data is local (try `diskspace classify`).",
                &dim,
            )
        );
        println!();
        return Ok(());
    }

    for r in &advisor {
        println!(
            "  {} {:>9}  {:<22} {:<20}  {}",
            ctx.style("☁", &cyan),
            ctx.style(&output::format_bytes(r.bytes), &bold),
            ctx.style(r.provider.label(), &cyan),
            ctx.style(r.mechanism.label(), &magenta),
            ctx.style(&r.path.display().to_string(), &dim),
        );
        println!(
            "      {} {}",
            ctx.style("↳", &dim),
            ctx.style(&advisor_action_hint(r), &dim),
        );
    }

    println!();
    println!(
        "  {}  {} reclaimable WITHOUT deleting anything {}",
        ctx.style("→", &green),
        ctx.style(&output::format_bytes(total), &bold),
        ctx.style(
            "(offload keeps the data in the cloud — fully reversible)",
            &dim
        ),
    );
    println!(
        "  {}  {}",
        ctx.style("→", &cyan),
        ctx.style(
            "stow one with: diskspace stow <path>   (add --yes to offload)",
            &dim
        ),
    );
    println!();
    Ok(())
}

/// The next command for an advisor row: the exact offload command for an actionable
/// mechanism, or the Finder-advice pointer for an advise-only one.
fn advisor_action_hint(r: &AdvisorRow) -> String {
    match cloud::offload_argv(r.mechanism, &r.path) {
        Some(argv) => format!(
            "diskspace stow {} --yes   (runs: {})",
            r.path.display(),
            argv.join(" ")
        ),
        None => format!(
            "diskspace stow {}   (Finder: Make online-only — advice only)",
            r.path.display()
        ),
    }
}

// ===========================================================================
// Shared rendering / helpers
// ===========================================================================

/// The exact Finder steps to make a Dropbox file online-only. Shared by the classic
/// and file-provider advice so both name the SAME route.
fn finder_steps() -> Vec<&'static str> {
    vec![
        "Open the file's folder in Finder.",
        "Right-click the file (or folder).",
        "Choose \"Make online-only\" (Dropbox Smart Sync).",
    ]
}

/// Print the path / provider / mechanism / size header shared by every single-path
/// form.
fn print_header(
    path: &Path,
    provider: CloudProvider,
    mechanism: OffloadMechanism,
    size: u64,
    ctx: &Context,
) {
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let cyan = Style::new().cyan().bold();
    let magenta = Style::new().magenta();

    println!();
    println!("  {}", ctx.style(&output::rule("stow", 56), &dim));
    println!();
    println!(
        "  {:<12} {}",
        ctx.style("path", &bold),
        ctx.style(&path.display().to_string(), &dim)
    );
    println!(
        "  {:<12} {}",
        ctx.style("provider", &bold),
        ctx.style(provider.label(), &cyan)
    );
    println!(
        "  {:<12} {}",
        ctx.style("mechanism", &bold),
        ctx.style(mechanism.label(), &magenta)
    );
    if size > 0 {
        println!(
            "  {:<12} {}",
            ctx.style("reclaimable", &bold),
            ctx.style(&format!("~{}", output::format_bytes(size)), &dim)
        );
    }
    println!();
}

/// Record a reversible offload receipt in the history ledger. An offload keeps the
/// data in the cloud, so `reversible = true` and the undo is provider-specific (the
/// re-download / un-exclude the user performs in Finder or the cloud client).
fn record_offload_receipt(
    path: &Path,
    provider: CloudProvider,
    mechanism: OffloadMechanism,
    size: u64,
    df_before: Option<u64>,
    df_after: Option<u64>,
    actually_freed: Option<u64>,
) {
    let mut context = serde_json::Map::new();
    context.insert(
        "provider".into(),
        serde_json::Value::String(provider.label().into()),
    );
    context.insert(
        "mechanism".into(),
        serde_json::Value::String(mechanism.label().into()),
    );
    context.insert("via".into(), serde_json::Value::String("stow".into()));
    let undo = match mechanism {
        OffloadMechanism::ICloudEvict => {
            Some("open the file to re-download it from iCloud".to_string())
        }
        OffloadMechanism::MaestralExclude => {
            Some(format!("maestral excluded remove {}", path.display()))
        }
        _ => None,
    };
    history::append(&HistEntry {
        ts: chrono::Utc::now(),
        command: ActionKind::Offload,
        candidate_id: None,
        rule_id: Some(format!("stow:{}", provider.label())),
        path: path.to_path_buf(),
        size_bytes: size,
        df_before,
        df_after,
        actually_freed,
        reversible: true,
        undo_cmd: undo,
        rule_confidence: None,
        context,
    });
}

/// On-disk size of `path` for the reclaimable estimate. Reuses the airlock store's
/// recursive size, which is fine for the advisory total. (The hunt advisor uses the
/// already-computed on-disk unruled bytes from the scan cache instead.)
fn on_disk_size(path: &Path) -> u64 {
    crate::core::airlock_store::dir_size(path)
}

/// Expand a leading `~/` (or bare `~`) to `$HOME`. Mirrors `classify`/`explain`.
fn expand_tilde(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
        PathBuf::from(home).join(rest)
    } else if raw == "~" {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into()))
    } else {
        PathBuf::from(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::MutexGuard;
    use std::time::SystemTime;

    /// Synthetic temp tree, cleaned on drop. NEVER touches the real `$HOME` cloud
    /// roots and NEVER runs `brctl` or `maestral`.
    struct TempTree {
        root: PathBuf,
    }
    impl TempTree {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "diskspace-stow-{}-{}-{}",
                tag,
                std::process::id(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }
        fn dir(&self, rel: &str) -> PathBuf {
            let p = self.root.join(rel);
            fs::create_dir_all(&p).unwrap();
            p
        }
        fn file(&self, dir: &Path, name: &str, n: usize) -> PathBuf {
            use std::io::Write;
            let p = dir.join(name);
            let mut f = fs::File::create(&p).unwrap();
            f.write_all(&vec![0u8; n]).unwrap();
            f.flush().unwrap();
            p
        }
    }
    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// Override `$HOME` for the duration of the guard, holding the crate-wide lock.
    struct HomeOverride {
        _guard: MutexGuard<'static, ()>,
        prev: Option<std::ffi::OsString>,
    }
    impl HomeOverride {
        fn set(home: &Path) -> Self {
            let guard = crate::core::HOME_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let prev = std::env::var_os("HOME");
            std::env::set_var("HOME", home);
            Self {
                _guard: guard,
                prev,
            }
        }
    }
    impl Drop for HomeOverride {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    /// stow on a synthetic CLASSIC-Dropbox path advises Finder steps + a GB total and
    /// takes NO filesystem action — the file is left exactly where it was.
    #[test]
    fn classic_dropbox_advises_finder_and_takes_no_action() {
        let t = TempTree::new("classic");
        let dropbox = t.dir("Dropbox");
        fs::create_dir_all(dropbox.join(".dropbox")).unwrap();
        let photos = t.dir("Dropbox/Photos");
        let f = t.file(&photos, "vacation.raw", 64 * 1024);

        let _home = HomeOverride::set(&t.root);
        // Detection + mechanism: classic Dropbox WITHOUT maestral active → AdviseFinder.
        let provider = cloud::detect_provider(&f);
        assert_eq!(provider, CloudProvider::DropboxClassic);
        // AdviseFinder is NOT actionable — it constructs no offload command.
        let mech = cloud::offload_mechanism(provider, false);
        assert_eq!(mech, OffloadMechanism::AdviseFinder);
        assert!(cloud::offload_argv(mech, &f).is_none());

        // The advised reclaimable total is the file's real on-disk size (> 0).
        let size = on_disk_size(&photos);
        assert!(size > 0, "advisor totals the GB it would free");

        // The advise path runs cleanly and leaves the file in place.
        let ctx = json_ctx();
        advise_finder(&photos, size, &ctx).unwrap();
        assert!(f.exists(), "advise NEVER deletes or moves the local file");

        // The Finder steps name the online-only route and the paid caveat lives in
        // the human/JSON note, not as a real command.
        let steps = finder_steps();
        assert!(steps.iter().any(|s| s.contains("online-only")));
    }

    /// stow on a synthetic iCLOUD path constructs the `brctl evict` argv (gated; NOT
    /// executed in this test — we only assert the command that WOULD run).
    #[test]
    fn icloud_path_constructs_brctl_evict_argv_not_executed() {
        let t = TempTree::new("icloud");
        let md = t.dir("Library/Mobile Documents/com~apple~CloudDocs/Big");
        let f = t.file(&md, "render.mov", 128 * 1024);

        let _home = HomeOverride::set(&t.root);
        let provider = cloud::detect_provider(&f);
        assert_eq!(provider, CloudProvider::ICloud);
        let mech = cloud::offload_mechanism(provider, false);
        assert_eq!(mech, OffloadMechanism::ICloudEvict);

        // The COMMAND we would run — asserted, never spawned.
        let argv = cloud::offload_argv(mech, &f).expect("evict is actionable");
        assert_eq!(argv[0], "brctl");
        assert_eq!(argv[1], "evict");
        assert_eq!(argv[2], f.to_string_lossy());
        // The file is untouched: building the argv does not run it.
        assert!(f.exists());
    }

    /// stow on a synthetic classic-Dropbox path WITH maestral active constructs the
    /// `maestral excluded add` argv (gated; not executed).
    #[test]
    fn classic_dropbox_with_maestral_constructs_exclude_argv() {
        let t = TempTree::new("maestral");
        let dropbox = t.dir("Dropbox");
        fs::create_dir_all(dropbox.join(".dropbox")).unwrap();
        let arch = t.dir("Dropbox/Archive");
        let f = t.file(&arch, "old.zip", 32 * 1024);

        let _home = HomeOverride::set(&t.root);
        let provider = cloud::detect_provider(&f);
        assert_eq!(provider, CloudProvider::DropboxClassic);
        // Mechanism WHEN maestral is the active client (we pass the flag directly so
        // no real `maestral` is ever spawned).
        let mech = cloud::offload_mechanism(provider, true);
        assert_eq!(mech, OffloadMechanism::MaestralExclude);
        let argv = cloud::offload_argv(mech, &f).expect("exclude is actionable");
        assert_eq!(
            argv,
            vec!["maestral", "excluded", "add", &*f.to_string_lossy()]
        );
        assert!(f.exists(), "constructing the argv does not run it");
    }

    /// A non-cloud path → NotApplicable; stow explains it offloads only cloud data.
    #[test]
    fn non_cloud_path_is_not_applicable() {
        let t = TempTree::new("noncloud");
        let d = t.dir("Code/project/target");
        let f = t.file(&d, "build.o", 4 * 1024);
        let _home = HomeOverride::set(&t.root);
        let provider = cloud::detect_provider(&f);
        assert_eq!(provider, CloudProvider::None);
        let mech = cloud::offload_mechanism(provider, false);
        assert_eq!(mech, OffloadMechanism::NotApplicable);
        assert!(cloud::offload_argv(mech, &f).is_none());
        // not_applicable renders cleanly.
        not_applicable(&f, &json_ctx()).unwrap();
    }

    /// The advisor groups Offload candidates by provider and TOTALS the reclaimable
    /// GB. We drive it via the pure row construction (no scan cache needed): an
    /// iCloud row + a classic-Dropbox row sum into the headline total, and the per-row
    /// action hint names the right next step.
    #[test]
    fn advisor_rows_total_reclaimable_and_hint_per_provider() {
        let t = TempTree::new("advisor");
        // iCloud candidate (actionable evict).
        let ic = t.dir("Library/Mobile Documents/com~apple~CloudDocs/A");
        let icf = t.file(&ic, "a.mov", 50 * 1024);
        // classic Dropbox candidate (advise-only).
        let dropbox = t.dir("Dropbox");
        fs::create_dir_all(dropbox.join(".dropbox")).unwrap();
        let db = t.dir("Dropbox/B");
        let dbf = t.file(&db, "b.raw", 30 * 1024);

        let _home = HomeOverride::set(&t.root);

        let rows = [
            AdvisorRow {
                path: icf.clone(),
                provider: cloud::detect_provider(&icf),
                mechanism: OffloadMechanism::ICloudEvict,
                bytes: 50 * 1024,
            },
            AdvisorRow {
                path: dbf.clone(),
                provider: cloud::detect_provider(&dbf),
                mechanism: OffloadMechanism::AdviseFinder,
                bytes: 30 * 1024,
            },
        ];
        let total: u64 = rows.iter().map(|r| r.bytes).sum();
        assert_eq!(
            total,
            80 * 1024,
            "advisor totals reclaimable-without-deleting"
        );

        assert_eq!(rows[0].provider, CloudProvider::ICloud);
        assert_eq!(rows[1].provider, CloudProvider::DropboxClassic);

        // The iCloud row's hint names the real evict command; the Dropbox row's hint
        // points at the Finder online-only advice (no command).
        let ic_hint = advisor_action_hint(&rows[0]);
        assert!(
            ic_hint.contains("brctl evict"),
            "iCloud hint runs evict: {ic_hint}"
        );
        assert!(ic_hint.contains("--yes"));
        let db_hint = advisor_action_hint(&rows[1]);
        assert!(
            db_hint.contains("Make online-only") && !db_hint.contains("brctl"),
            "classic Dropbox hint is advice-only: {db_hint}"
        );
    }

    /// expand_tilde mirrors classify: `~/` → $HOME, absolute passes through.
    #[test]
    fn expand_tilde_handles_home_and_absolute() {
        let _guard = crate::core::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", "/tmp/fake-stow-home");
        assert_eq!(
            expand_tilde("~/Dropbox/x"),
            PathBuf::from("/tmp/fake-stow-home/Dropbox/x")
        );
        assert_eq!(expand_tilde("/abs/p"), PathBuf::from("/abs/p"));
        match prev {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }

    fn json_ctx() -> Context {
        Context {
            json: true,
            yes: false,
            no_color: true,
            verbose: false,
            quiet: false,
        }
    }
}

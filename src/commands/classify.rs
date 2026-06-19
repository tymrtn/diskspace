//! `diskspace classify` — label the opaque "unknown" residual and, with consent,
//! take the SAFE ACTION for what it found.
//!
//! `hunt` surfaces the largest TRULY-unruled directories; this command answers the
//! next question — "what IS that, and what's the safe thing to do?" — by running
//! the [`classify`](crate::core::classify) signature classifier and, on `--yes`,
//! EXECUTING the safest action for the inferred strategy:
//!
//!   * [`Strategy::Repack`] → the in-place `git gc` safe action (loss-free).
//!   * [`Strategy::Reclaim`] → the EXISTING reversible airlock, by path, behind the
//!     SAME hard pressure-test gate every reclaim path uses.
//!   * [`Strategy::Offload`] → RECOMMEND `diskspace stow <path>` (the cloud-offload
//!     command) — `classify` prints the command, it does NOT offload; `stow` owns the
//!     provider-specific, reversible offload policy.
//!   * [`Strategy::Review`] / [`Strategy::Keep`] → never act; inspect-first guidance.
//!
//! Two forms:
//!   * `classify <path>` — classify one dir and (with `--yes`) act on it.
//!   * `classify`        — classify the top unruled hunt rows into a table (read-only).
//!
//! INVARIANTS honored here: never sudo; HOME-scoped; the pressure-test stays the
//! hard gate for the Reclaim/airlock path; classify and git-repack DEFAULT to
//! SUGGEST and only act with confirmation / `--yes`; honest accounting (the repack
//! reports the REAL measured before/after, never the classifier's estimate). `--json`
//! mirrors every form.

use anyhow::{Context as _, Result};
use console::Style;
use std::path::{Path, PathBuf};

use crate::core::airlock_store;
use crate::core::classify::{self, Classification, Strategy};
use crate::core::history::{self, ActionKind, Entry as HistEntry};
use crate::core::repack;
use crate::output::{self, Context};
use crate::profile;

/// `classify` entry point. `path = None` runs the read-only top-unruled table;
/// `path = Some` classifies one directory and (with `--yes`) acts on it.
pub fn run(path: Option<&str>, yes: bool, ctx: &Context) -> Result<()> {
    match path {
        Some(p) => classify_one(p, yes, ctx),
        None => classify_top(ctx),
    }
}

// ===========================================================================
// `classify <path>` — one directory, with optional safe action.
// ===========================================================================

fn classify_one(raw_path: &str, yes: bool, ctx: &Context) -> Result<()> {
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

    let prof = profile::load().unwrap_or_default();
    let c = classify::classify_dir(&path, &prof);

    // SUGGEST-ONLY unless --yes: print the classification and the recommended
    // command, then stop. (Confirmation here is the explicit `--yes`; we do not
    // prompt interactively for the action so the suggest/act split stays crisp.)
    if !yes {
        return report_classification(&path, &c, ctx);
    }

    // --yes: EXECUTE the safe action for the strategy.
    match c.strategy {
        Strategy::Repack => act_repack(&path, &c, ctx),
        Strategy::Reclaim => act_reclaim(&path, &c, &prof, ctx),
        Strategy::Offload => act_offload_suggest(&path, &c, ctx),
        Strategy::Review | Strategy::Keep => act_none(&path, &c, ctx),
    }
}

/// Print the classification + recommended action WITHOUT acting (the default).
fn report_classification(path: &Path, c: &Classification, ctx: &Context) -> Result<()> {
    if ctx.json {
        println!("{}", classification_json(path, c, "suggest", None));
        return Ok(());
    }
    print_classification_block(path, c, ctx);
    let hint = classify::action_hint(c.strategy, path);
    let cyan = Style::new().cyan().bold();
    let dim = Style::new().dim();
    println!("  {}  {}", ctx.style("→", &cyan), ctx.style(&hint, &dim));
    println!();
    Ok(())
}

// ---- the SAFE actions -----------------------------------------------------

/// Repack: run the in-place `git gc` safe action and report the REAL before/after.
fn act_repack(path: &Path, c: &Classification, ctx: &Context) -> Result<()> {
    // Pre-flight first so a non-git / dirty dir gives a clean refusal (not a panic).
    match repack::preflight(path) {
        Ok(_repo) => {}
        Err(refusal) => {
            if ctx.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "action": "repack",
                        "status": "refused",
                        "error": refusal.token(),
                        "detail": refusal.to_string(),
                        "path": path,
                    })
                );
            } else {
                print_classification_block(path, c, ctx);
                let red = Style::new().red().bold();
                println!("  {}  repack refused — {}", ctx.style("✗", &red), refusal);
                println!();
            }
            std::process::exit(2);
        }
    }

    let outcome = repack::run_repack(path).context("running git gc")?;

    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "action": "repack",
                "status": "done",
                "repo": outcome.repo,
                "git_size_before": outcome.git_size_before,
                "git_size_after": outcome.git_size_after,
                "reclaimed_bytes": outcome.reclaimed_bytes,
                "git_output": outcome.git_output,
                "signature": c.signature.label(),
                "strategy": c.strategy.label(),
            })
        );
        return Ok(());
    }

    let green = Style::new().green().bold();
    let bold = Style::new().bold();
    let dim = Style::new().dim();
    print_classification_block(path, c, ctx);
    println!(
        "  {}  {} reclaimed by git gc  {}",
        ctx.style("✓", &green),
        ctx.style(&output::format_bytes(outcome.reclaimed_bytes), &bold),
        ctx.style(
            &format!(
                "({} → {})",
                output::format_bytes(outcome.git_size_before),
                output::format_bytes(outcome.git_size_after)
            ),
            &dim,
        ),
    );
    println!(
        "     {}",
        ctx.style(&format!("repo: {}", outcome.repo.display()), &dim)
    );
    // In verbose mode show git's own gc output (it's already captured; this also
    // gives the user the raw transcript when the byte delta looks surprising).
    if ctx.verbose && !outcome.git_output.is_empty() {
        for line in outcome.git_output.lines() {
            println!("     {}", ctx.style(line, &dim));
        }
    }
    println!();
    Ok(())
}

/// Reclaim: hand the path to the EXISTING reversible airlock, behind the SAME hard
/// pressure-test gate every reclaim path uses. Nothing here bypasses that gate.
fn act_reclaim(
    path: &Path,
    c: &Classification,
    prof: &profile::Profile,
    ctx: &Context,
) -> Result<()> {
    // THE HARD GATE. A synthetic candidate id ties the receipt to this action; the
    // pressure-test reads the path itself, so the id is purely a label.
    let synthetic_id = format!("classify-reclaim-{}", file_tag(path));
    let check = crate::commands::check::pressure_test(&synthetic_id, path, prof)?;
    if !check.safe {
        if ctx.json {
            println!(
                "{}",
                serde_json::json!({
                    "action": "reclaim",
                    "status": "refused",
                    "error": "pressure_test_failed",
                    "path": path,
                    "check": check,
                })
            );
        } else {
            print_classification_block(path, c, ctx);
            crate::commands::check::render_check_result_pub(&check, ctx);
            eprintln!("  Reclaim aborted — path did not pass the pressure test.\n");
        }
        std::process::exit(2);
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let df_before = history::free_bytes(Path::new(&home));

    let (entry, kind) =
        airlock_store::airlock_path(&synthetic_id, path, prof.preferences.airlock_retention_days)?;
    let mut manifest = airlock_store::load_manifest()?;
    manifest.entries.push(entry.clone());
    airlock_store::save_manifest(&manifest)?;

    let df_after = history::free_bytes(Path::new(&home));
    let actually_freed = match (kind, df_before, df_after) {
        (airlock_store::MoveKind::CopyRemove, Some(b), Some(a)) if a > b => Some(a - b),
        _ => None,
    };
    let mut ctx_map = serde_json::Map::new();
    ctx_map.insert(
        "move_kind".into(),
        serde_json::Value::String(
            match kind {
                airlock_store::MoveKind::Rename => "rename",
                airlock_store::MoveKind::CopyRemove => "copy_remove",
            }
            .into(),
        ),
    );
    ctx_map.insert("via".into(), serde_json::Value::String("classify".into()));
    history::append(&HistEntry {
        ts: chrono::Utc::now(),
        command: ActionKind::Airlock,
        candidate_id: Some(synthetic_id),
        rule_id: Some(format!("classify:{}", c.signature.label())),
        path: path.to_path_buf(),
        size_bytes: entry.size_bytes,
        df_before,
        df_after,
        actually_freed,
        reversible: true,
        undo_cmd: Some(format!("diskspace restore {}", entry.id)),
        rule_confidence: None,
        context: ctx_map,
    });

    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "action": "reclaim",
                "status": "airlocked",
                "entry": entry,
                "move_kind": match kind {
                    airlock_store::MoveKind::Rename => "rename",
                    airlock_store::MoveKind::CopyRemove => "copy_remove",
                },
                "actually_freed": kind == airlock_store::MoveKind::CopyRemove,
                "signature": c.signature.label(),
                "strategy": c.strategy.label(),
            })
        );
        return Ok(());
    }

    let green = Style::new().green().bold();
    let yellow = Style::new().yellow();
    let bold = Style::new().bold();
    let dim = Style::new().dim();
    print_classification_block(path, c, ctx);
    match kind {
        airlock_store::MoveKind::CopyRemove => println!(
            "  {}  {} freed (airlocked, reversible)",
            ctx.style("✓", &green),
            ctx.style(&output::format_bytes(entry.size_bytes), &bold),
        ),
        airlock_store::MoveKind::Rename => println!(
            "  {}  {} staged for purge  {}",
            ctx.style("◐", &yellow),
            ctx.style(&output::format_bytes(entry.size_bytes), &bold),
            ctx.style("(same-volume rename — bytes freed at purge)", &dim),
        ),
    }
    println!(
        "     restore with: diskspace restore {}",
        ctx.style(&entry.id, &dim)
    );
    println!();
    Ok(())
}

/// Offload: hand off to `stow`, the cloud-OFFLOAD command. `classify` itself never
/// offloads — offloading is provider-specific (iCloud evict vs. Dropbox Finder
/// advice) and `stow` owns that policy. We RECOMMEND the real `diskspace stow`
/// command (the next step), honest that the bytes are moved to the cloud (reversible),
/// not deleted. Nothing is moved here.
fn act_offload_suggest(path: &Path, c: &Classification, ctx: &Context) -> Result<()> {
    if ctx.json {
        println!(
            "{}",
            classification_json(
                path,
                c,
                "suggest",
                Some(
                    "offload is reversible (data stays in the cloud) — run `diskspace stow <path>`"
                )
            )
        );
        return Ok(());
    }
    print_classification_block(path, c, ctx);
    let cyan = Style::new().cyan().bold();
    let dim = Style::new().dim();
    println!(
        "  {}  recommended: {}",
        ctx.style("→", &cyan),
        ctx.style(&format!("diskspace stow {}", path.display()), &dim),
    );
    println!(
        "     {}",
        ctx.style(
            "(stow offloads cloud-synced data to free local space — reversible, never a deletion)",
            &dim
        )
    );
    println!();
    Ok(())
}

/// Review / Keep: never act. Print the inspect-first guidance.
fn act_none(path: &Path, c: &Classification, ctx: &Context) -> Result<()> {
    if ctx.json {
        println!(
            "{}",
            classification_json(
                path,
                c,
                "no_action",
                Some("strategy is review/keep — never a blind action")
            )
        );
        return Ok(());
    }
    print_classification_block(path, c, ctx);
    let yellow = Style::new().yellow();
    let dim = Style::new().dim();
    println!(
        "  {}  {}",
        ctx.style("·", &yellow),
        ctx.style(&classify::action_hint(c.strategy, path), &dim),
    );
    println!();
    Ok(())
}

// ===========================================================================
// `classify` (no path) — the top unruled table (read-only).
// ===========================================================================

fn classify_top(ctx: &Context) -> Result<()> {
    // Reuse the SAME cache-first hunt analysis, already classified.
    let rows = crate::commands::hunt::analyze_unruled(15, 500, false, ctx)?;

    if ctx.json {
        let out: Vec<_> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "path": r.path,
                    "size_bytes": r.unruled_bytes,
                    "unruled_bytes": r.unruled_bytes,
                    "total_bytes": r.total_bytes,
                    "signature": r.signature.map(|s| s.label()),
                    "strategy": r.strategy.map(|s| s.label()),
                    "action": r.strategy.map(|s| classify::action_hint(s, &r.path)),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let cyan = Style::new().cyan().bold();
    let magenta = Style::new().magenta();

    println!();
    println!(
        "  {}",
        ctx.style(
            &output::rule("classify  ·  the unrule'd residual", 64),
            &dim
        )
    );
    println!();

    if rows.is_empty() {
        println!(
            "  {}",
            ctx.style(
                "Nothing large and unruled to classify. Run `diskspace survey` first if you expected results.",
                &dim,
            )
        );
        println!();
        return Ok(());
    }

    for r in &rows {
        let size_str = output::format_bytes(r.unruled_bytes);
        let sig = r.signature.map(|s| s.label()).unwrap_or("unknown");
        let strat = r.strategy.map(|s| s.label()).unwrap_or("review");
        println!(
            "  {} {:>9}  {:<16} {:<8}  {}",
            ctx.style("◇", &magenta),
            ctx.style(&size_str, &bold),
            ctx.style(sig, &cyan),
            ctx.style(strat, &magenta),
            ctx.style(&r.path.display().to_string(), &dim),
        );
        if let Some(s) = r.strategy {
            println!(
                "      {} {}",
                ctx.style("↳", &dim),
                ctx.style(&classify::action_hint(s, &r.path), &dim),
            );
        }
    }

    println!();
    println!(
        "  {}  {}",
        ctx.style("→", &cyan),
        ctx.style("act on one with: diskspace classify <path> --yes", &dim),
    );
    println!();
    Ok(())
}

// ===========================================================================
// Shared rendering / helpers
// ===========================================================================

/// Print the signature / strategy / size / est-savings / reasoning block shared by
/// every single-path form (suggest and every action).
fn print_classification_block(path: &Path, c: &Classification, ctx: &Context) {
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let cyan = Style::new().cyan().bold();
    let magenta = Style::new().magenta();

    println!();
    println!("  {}", ctx.style(&output::rule("classify", 56), &dim));
    println!();
    println!(
        "  {:<12} {}",
        ctx.style("path", &bold),
        ctx.style(&path.display().to_string(), &dim)
    );
    println!(
        "  {:<12} {}",
        ctx.style("signature", &bold),
        ctx.style(c.signature.label(), &cyan)
    );
    println!(
        "  {:<12} {}",
        ctx.style("strategy", &bold),
        ctx.style(c.strategy.label(), &magenta)
    );
    if let Some(est) = c.est_savings_bytes {
        println!(
            "  {:<12} {}",
            ctx.style("est savings", &bold),
            ctx.style(&format!("~{}", output::format_bytes(est)), &dim)
        );
    }
    println!(
        "  {:<12} {}",
        ctx.style("why", &bold),
        ctx.style(&c.reasoning, &dim)
    );
    println!();
}

/// One JSON object for the suggest / no-action single-path forms.
fn classification_json(
    path: &Path,
    c: &Classification,
    status: &str,
    note: Option<&str>,
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "path": path,
        "status": status,
        "signature": c.signature.label(),
        "strategy": c.strategy.label(),
        "reasoning": c.reasoning,
        "action": classify::action_hint(c.strategy, path),
    });
    if let Some(est) = c.est_savings_bytes {
        v["est_savings_bytes"] = serde_json::json!(est);
    }
    if let Some(n) = note {
        v["note"] = serde_json::json!(n);
    }
    v
}

/// Expand a leading `~/` (or bare `~`) to `$HOME`. Mirrors how `explain` accepts a
/// tilde path. Absolute / relative paths pass through unchanged.
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

/// A filesystem-safe tag derived from a path's final component, for the synthetic
/// candidate id. Falls back to "dir" for a path with no usable name.
fn file_tag(path: &Path) -> String {
    path.file_name()
        .map(|n| {
            n.to_string_lossy()
                .chars()
                .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
                .collect::<String>()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "dir".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::classify::Signature;
    use std::fs;
    use std::io::Write;
    use std::time::SystemTime;

    struct TempTree {
        root: PathBuf,
    }
    impl TempTree {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "diskspace-classifycmd-{}-{}-{}",
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
        fn file(&self, dir: &Path, name: &str, n: usize) {
            let p = dir.join(name);
            let mut f = fs::File::create(&p).unwrap();
            f.write_all(&vec![0u8; n]).unwrap();
            f.flush().unwrap();
        }
    }
    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn prof() -> profile::Profile {
        profile::Profile::default()
    }

    /// classify on a synthetic git pack dir returns the right signature + strategy
    /// + the executable action hint (git gc).
    #[test]
    fn classifies_gitpack_to_repack_with_action() {
        let t = TempTree::new("gitpack");
        let pack = t.dir("Clef/.git/objects/pack");
        t.file(&pack, "pack-abc.pack", 64 * 1024);
        let c = classify::classify_dir(&pack, &prof());
        assert_eq!(c.signature, Signature::GitPack);
        assert_eq!(c.strategy, Strategy::Repack);
        let hint = classify::action_hint(c.strategy, &pack);
        assert!(
            hint.contains("git gc"),
            "the repack action hint names git gc: {hint}"
        );
    }

    /// classify on a model-checkpoint dir → Offload, and the action hint RECOMMENDS
    /// stow (never claims to offload — stow is the next pass).
    #[test]
    fn classifies_model_to_offload_recommend_stow() {
        let t = TempTree::new("model");
        let blobs = t.dir("checkpoints/models--ACE-Step--x/blobs");
        t.file(&blobs, "0a1b2c3d", 16 * 1024);
        let c = classify::classify_dir(&blobs, &prof());
        assert_eq!(c.strategy, Strategy::Offload);
        let hint = classify::action_hint(c.strategy, &blobs);
        assert!(
            hint.starts_with("recommended:") && hint.contains("diskspace stow"),
            "offload only RECOMMENDS stow, never claims to offload: {hint}"
        );
    }

    /// classify on an OrbStack VM-disk dir → Reclaim, action hint names the
    /// reversible airlock.
    #[test]
    fn classifies_vmdisk_to_reclaim_airlock() {
        let t = TempTree::new("vmdisk");
        let data = t.dir("Group Containers/HUAQ24HBR6.dev.orbstack/data");
        t.file(&data, "disk.img", 32 * 1024);
        let c = classify::classify_dir(&data, &prof());
        assert_eq!(c.strategy, Strategy::Reclaim);
        let hint = classify::action_hint(c.strategy, &data);
        assert!(
            hint.contains("airlock"),
            "reclaim hint names the reversible airlock: {hint}"
        );
    }

    /// The JSON object for a suggest carries signature, strategy, action, and (for a
    /// GitPack) the est-savings estimate.
    #[test]
    fn suggest_json_has_signature_strategy_action() {
        let t = TempTree::new("json");
        let pack = t.dir("repo/.git/objects/pack");
        t.file(&pack, "pack-x.pack", 100 * 1024);
        let c = classify::classify_dir(&pack, &prof());
        let v = classification_json(&pack, &c, "suggest", None);
        assert_eq!(v["signature"], "git-pack");
        assert_eq!(v["strategy"], "repack");
        assert!(v["action"].as_str().unwrap().contains("git gc"));
        assert!(
            v["est_savings_bytes"].is_number(),
            "a GitPack suggest reports an est-savings estimate"
        );
    }

    /// `expand_tilde` expands a leading `~/` to $HOME; absolute paths pass through.
    #[test]
    fn expand_tilde_handles_home_and_absolute() {
        let _guard = crate::core::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("HOME");
        // SAFETY: serialized by HOME_TEST_LOCK; restored below.
        unsafe {
            std::env::set_var("HOME", "/tmp/fake-home");
        }
        assert_eq!(
            expand_tilde("~/Code/x"),
            PathBuf::from("/tmp/fake-home/Code/x")
        );
        assert_eq!(expand_tilde("/abs/path"), PathBuf::from("/abs/path"));
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            match prev {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    /// `file_tag` produces a filesystem-safe synthetic-id fragment.
    #[test]
    fn file_tag_is_sanitized() {
        assert_eq!(file_tag(Path::new("/a/b/My Repo.git")), "My-Repo-git");
        assert_eq!(file_tag(Path::new("/")), "dir");
    }
}

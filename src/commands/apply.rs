//! `diskspace apply <plan_hash>` — the TOCTOU-safe second half of two-phase
//! recovery. Loads a plan that `plan` content-addressed and persisted, then
//! RE-VALIDATES everything LIVE before touching the filesystem:
//!
//!   1. **Hash integrity** — recompute the canonical hash of the loaded steps and
//!      refuse if it differs from the requested hash (a tampered or stale file).
//!   2. **Re-stat** — every target must still exist and its size must be within
//!      10% of the planned size (refuse on disappearance or >10% growth/shrink —
//!      the path the user reviewed is not the path on disk anymore).
//!   3. **Live pressure-test** — RE-RUN the HARD gate (`check::pressure_test`) for
//!      every step. A plan captured a point-in-time `safe == true`; we NEVER trust
//!      that cached result. If the gate now says unsafe, refuse and exit 2.
//!
//! These checks are **all-or-nothing**: any single drift refuses the WHOLE apply
//! (no partial execution; a future `--partial` could relax this). There is NO
//! `--force` — drift is a hard stop, by design (LOCKED invariant). Only after all
//! steps clear every check does `apply` hand the re-validated plan to
//! `doctor::execute_plan`, which runs the existing airlock / immediate-delete
//! paths and appends a history receipt per action. Consent is the existing
//! pressure-test path — `apply` introduces no autonomy and no grant tokens.

use anyhow::Result;
use std::path::Path;

use crate::commands::check;
use crate::commands::doctor::{self, Plan};
use crate::commands::plan as plan_cmd;
use crate::core::history;
use crate::output::Context;
use crate::profile;

/// Fraction of the planned size a target may drift (grow or shrink) at re-stat
/// time before `apply` refuses. 10% — a node_modules that doubled, or a download
/// that was half-deleted, is not the thing the user reviewed.
const SIZE_DRIFT_TOLERANCE: f64 = 0.10;

/// Why an apply refused. Surfaced verbatim in the JSON `reason` and the human
/// message so an agent can branch on the failure class.
#[derive(Debug)]
enum Refusal {
    /// The recomputed hash of the loaded steps != the requested hash.
    HashMismatch { expected: String, actual: String },
    /// A target no longer exists on disk.
    Missing { path: String },
    /// A target's current size drifted beyond tolerance from the planned size.
    SizeDrift {
        path: String,
        planned: u64,
        actual: u64,
    },
    /// The live pressure-test now reports the step unsafe.
    Unsafe { path: String, candidate_id: String },
}

impl Refusal {
    fn reason(&self) -> String {
        match self {
            Refusal::HashMismatch { expected, actual } => format!(
                "plan hash mismatch: file recomputes to {} but {} was requested (tampered or stale plan)",
                actual, expected
            ),
            Refusal::Missing { path } => {
                format!("target no longer exists: {} (refusing — plan is stale)", path)
            }
            Refusal::SizeDrift {
                path,
                planned,
                actual,
            } => format!(
                "target size drifted >{:.0}%: {} planned {} bytes, now {} bytes (refusing)",
                SIZE_DRIFT_TOLERANCE * 100.0,
                path,
                planned,
                actual
            ),
            Refusal::Unsafe {
                path,
                candidate_id,
            } => format!(
                "live pressure-test now UNSAFE for {} ({}) — refusing to act on a stale-safe plan",
                path, candidate_id
            ),
        }
    }

    /// Process exit code. An unsafe gate result is exit 2 (the same code
    /// `check`/`doctor` use for "gate says no"); every other refusal is exit 1.
    fn exit_code(&self) -> i32 {
        match self {
            Refusal::Unsafe { .. } => 2,
            _ => 1,
        }
    }
}

/// Current on-disk size of `path` using the SAME basis the scanner (and therefore
/// the persisted plan's `size_bytes`) used: allocated on-disk blocks (`blocks*512`)
/// on unix, logical length elsewhere. This MUST match `scanner::scan`'s sizing or
/// the drift check compares two different bases (allocated-blocks at plan time vs
/// apparent-len at apply time) and either false-refuses a stable target or masks a
/// real change — e.g. a `node_modules` of thousands of small files reads far larger
/// in allocated blocks than in apparent length. We deliberately do NOT reuse
/// `airlock_store::dir_size` (which is `metadata.len()` apparent-len): that basis is
/// fine for "what airlock will move" but wrong for re-validating a scanner-sized plan.
///
/// Mirrors `scanner::file_on_disk_bytes`: a cloud-only placeholder (len > 4096 but
/// 0 allocated blocks — iCloud evicted / Dropbox online-only) reports 0, exactly as
/// the scan skipped it, so a placeholder never reads as drift.
fn current_size(path: &Path) -> u64 {
    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return 0,
    };
    if md.file_type().is_symlink() {
        // Scanner skips symlinks; a target that became a symlink contributes 0.
        return 0;
    }
    if md.is_file() {
        return file_on_disk_bytes(&md);
    }
    // Directory: recurse with the same allocated-blocks sizing, skipping symlinks.
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            total += current_size(&entry.path());
        }
    }
    total
}

/// On-disk bytes for a single file, matching `scanner::file_on_disk_bytes`:
/// `blocks*512` on unix (the allocation the scanner counted), logical len
/// elsewhere; a cloud-only placeholder (len > 4096, 0 blocks) reports 0.
fn file_on_disk_bytes(md: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if md.len() > 4096 && md.blocks() == 0 {
            return 0; // iCloud/Dropbox online-only placeholder — no disk used
        }
        md.blocks() * 512
    }
    #[cfg(not(unix))]
    {
        md.len()
    }
}

/// Re-validate a loaded plan LIVE against the current filesystem. Returns `Ok(())`
/// when every step still exists, is within size tolerance, and re-passes the HARD
/// pressure-test. Returns the FIRST [`Refusal`] otherwise (all-or-nothing).
fn revalidate(
    plan: &Plan,
    requested_hash: &str,
    prof: &profile::Profile,
) -> Result<Result<(), Refusal>> {
    // 1. Hash integrity — the file must hash to exactly what was asked for.
    let actual_hash = plan_cmd::compute_plan_hash(&plan.steps);
    if actual_hash != requested_hash {
        return Ok(Err(Refusal::HashMismatch {
            expected: requested_hash.to_string(),
            actual: actual_hash,
        }));
    }

    for step in &plan.steps {
        // 2a. Re-stat — must still exist.
        if !step.path.exists() {
            return Ok(Err(Refusal::Missing {
                path: step.path.display().to_string(),
            }));
        }
        // 2b. Size drift — current size must be within tolerance of planned size.
        let now = current_size(&step.path);
        let planned = step.size_bytes;
        let allowed = (planned as f64 * SIZE_DRIFT_TOLERANCE).max(0.0);
        let delta = now.abs_diff(planned) as f64;
        if delta > allowed {
            return Ok(Err(Refusal::SizeDrift {
                path: step.path.display().to_string(),
                planned,
                actual: now,
            }));
        }
        // 3. LIVE pressure-test — re-run the HARD gate; never trust the cached one.
        let live = check::pressure_test(&step.candidate_id, &step.path, prof)?;
        if !live.safe {
            return Ok(Err(Refusal::Unsafe {
                path: step.path.display().to_string(),
                candidate_id: step.candidate_id.clone(),
            }));
        }
    }
    Ok(Ok(()))
}

pub fn run(plan_hash: &str, ctx: &Context) -> Result<()> {
    let prof = profile::load()?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let home_path = Path::new(&home);

    // Load the persisted plan. A missing/unparseable file is a refusal, not a panic.
    let plan = match plan_cmd::load_plan(plan_hash) {
        Ok(p) => p,
        Err(e) => {
            emit_refusal_msg(ctx, &format!("could not load plan {}: {}", plan_hash, e));
            std::process::exit(1);
        }
    };

    // RE-VALIDATE EVERYTHING LIVE (hash, re-stat, size drift, pressure-test).
    match revalidate(&plan, plan_hash, &prof)? {
        Ok(()) => {}
        Err(refusal) => {
            let reason = refusal.reason();
            if ctx.json {
                let payload = serde_json::json!({
                    "applied": false,
                    "plan_hash": plan_hash,
                    "reason": reason,
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                eprintln!("  Refusing to apply: {}", reason);
            }
            std::process::exit(refusal.exit_code());
        }
    }

    // All steps cleared every live check — execute the re-validated plan through
    // the SAME executor doctor uses (airlock / immediate + history receipts).
    let df_before = history::free_bytes(home_path).unwrap_or(0);
    let need_bytes = df_before.saturating_add(plan.need_bytes);
    let outcome = doctor::execute_plan(&plan, &prof, ctx, df_before, need_bytes, home_path)?;

    if ctx.json {
        let payload = serde_json::json!({
            "applied": true,
            "plan_hash": plan_hash,
            "free_before": outcome.df_before,
            "free_after": outcome.df_after,
            "actually_freed": outcome.actually_freed,
            "freed_staged": outcome.freed_bytes,
            "items": outcome.items,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        use console::Style;
        let bold = Style::new().bold();
        let green = Style::new().green().bold();
        println!();
        println!(
            "  {}  applied {} step(s) — {} actually freed",
            ctx.style("✓", &green),
            plan.steps.len(),
            ctx.style(&crate::output::format_bytes(outcome.actually_freed), &bold),
        );
        println!();
    }

    Ok(())
}

fn emit_refusal_msg(ctx: &Context, reason: &str) {
    if ctx.json {
        // Best-effort; if this fails there's nothing more to do before exit.
        let payload = serde_json::json!({ "applied": false, "reason": reason });
        if let Ok(s) = serde_json::to_string_pretty(&payload) {
            println!("{}", s);
        }
    } else {
        eprintln!("  Refusing to apply: {}", reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::doctor::{Plan, PlanStep};
    use crate::commands::plan as plan_cmd;
    use crate::core::candidate::CheckResult;
    use crate::core::HOME_TEST_LOCK;
    use chrono::Utc;
    use std::fs;
    use std::path::PathBuf;

    /// A throwaway `$HOME` under the OS temp dir, cleaned on drop. Mirrors the
    /// doctor test harness: while alive, `$HOME` points here so `profile::data_dir`
    /// (plans, airlock, history) resolves under the tempdir and never touches the
    /// real `~/.diskspace`. Construct ONLY while holding `HOME_TEST_LOCK`.
    struct TempHome {
        path: PathBuf,
        prev_home: Option<std::ffi::OsString>,
    }
    impl TempHome {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "diskspace-apply-test-{}-{}-{}",
                tag,
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            fs::create_dir_all(&p).unwrap();
            let prev_home = std::env::var_os("HOME");
            // SAFETY: serialized by HOME_TEST_LOCK; restored on drop.
            unsafe {
                std::env::set_var("HOME", &p);
            }
            fs::create_dir_all(p.join(".diskspace")).unwrap();
            Self { path: p, prev_home }
        }
    }
    impl Drop for TempHome {
        fn drop(&mut self) {
            // SAFETY: serialized by HOME_TEST_LOCK; restores the original value.
            unsafe {
                match &self.prev_home {
                    Some(h) => std::env::set_var("HOME", h),
                    None => std::env::remove_var("HOME"),
                }
            }
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// Backdate a path's mtime/atime ~120 days into the past via `touch -t` so the
    /// liveness pressure-check (no writes in last 24h) passes for a freshly-created
    /// test fixture. Best-effort; the format `[[CC]YY]MMDDhhmm` is the POSIX touch
    /// stamp accepted by macOS/BSD touch.
    fn backdate(path: &Path) {
        let _ = std::process::Command::new("touch")
            .arg("-t")
            .arg("202601010000") // 2026-01-01 00:00 — well over 24h before "now"
            .arg(path)
            .status();
    }

    fn quiet_ctx() -> Context {
        Context {
            json: true,
            yes: true,
            no_color: true,
            verbose: false,
            quiet: true,
        }
    }

    /// Build a real on-disk target dir of `size` bytes under `$HOME`, old enough
    /// to clear the liveness/recency pressure checks, and return a one-step plan
    /// (airlock) plus its hash. The candidate_id is `manual-<leaf>` so the live
    /// pressure-test runs purely off the path (restat/liveness/policy/recency),
    /// not off any rule lookup.
    fn make_plan(home: &Path, leaf: &str, size: usize) -> (Plan, String, PathBuf) {
        let target = home.join("proj").join(leaf);
        fs::create_dir_all(&target).unwrap();
        let blob = target.join("blob.bin");
        fs::write(&blob, vec![0u8; size]).unwrap();

        // Backdate the blob's mtime/atime well past the 24h liveness window so the
        // LIVE pressure-test's liveness check (no writes in 24h) passes. The
        // doctor tests fake this through ScannedEntry timestamps; here the gate
        // re-stats the REAL file, so we must touch the real mtime. `touch -t` with
        // a fixed old timestamp is portable on macOS/BSD.
        backdate(&blob);
        backdate(&target);

        let actual = current_size(&target);
        let step = PlanStep {
            candidate_id: format!("manual-{}", leaf),
            rule_id: "manual".into(),
            path: target.clone(),
            size_bytes: actual,
            confidence: 0.9,
            mode: "airlock".into(),
            reversible: true,
            pressure: CheckResult::gate(format!("manual-{}", leaf), true, 1.0, vec![]),
            consequence_contract: None,
        };
        let hash = plan_cmd::compute_plan_hash(std::slice::from_ref(&step));
        let plan = Plan {
            plan_hash: hash.clone(),
            need_bytes: actual,
            steps: vec![step],
            projected_freed: actual,
            created_at: Utc::now(),
        };
        (plan, hash, target)
    }

    #[test]
    fn revalidate_refuses_on_hash_mismatch() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("hashmismatch");
        let prof = profile::Profile::default();
        let (plan, hash, _t) = make_plan(&h.path, "nm", 4096);

        // Ask apply to validate this plan against a DIFFERENT hash than it hashes
        // to → must refuse with HashMismatch (exit-1 class).
        let bogus = format!("{}deadbeef", &hash[..hash.len() - 8]);
        match revalidate(&plan, &bogus, &prof).unwrap() {
            Err(Refusal::HashMismatch { .. }) => {}
            other => panic!("expected HashMismatch, got {:?}", other.map(|_| "Ok")),
        }
    }

    #[test]
    fn revalidate_refuses_when_target_deleted_between_plan_and_apply() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("deleted");
        let prof = profile::Profile::default();
        let (plan, hash, target) = make_plan(&h.path, "nm", 4096);

        // Mutate the world: delete the target after planning.
        fs::remove_dir_all(&target).unwrap();

        match revalidate(&plan, &hash, &prof).unwrap() {
            Err(Refusal::Missing { .. }) => {}
            other => panic!("expected Missing, got {:?}", other.map(|_| "Ok")),
        }
    }

    #[test]
    fn revalidate_refuses_when_target_grows_beyond_tolerance() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("grow");
        let prof = profile::Profile::default();
        let (plan, hash, target) = make_plan(&h.path, "nm", 10_000);

        // Grow the target far past 10% (double it) after planning.
        fs::write(target.join("more.bin"), vec![0u8; 20_000]).unwrap();

        match revalidate(&plan, &hash, &prof).unwrap() {
            Err(Refusal::SizeDrift { .. }) => {}
            other => panic!("expected SizeDrift, got {:?}", other.map(|_| "Ok")),
        }
    }

    #[test]
    fn revalidate_refuses_when_pressure_test_now_unsafe() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("unsafe");
        let (plan, hash, target) = make_plan(&h.path, "nm", 4096);

        // Make the LIVE pressure-test fail without changing size/existence: a
        // never_touch policy block flips the gate to unsafe. The cached pressure
        // in the plan still says safe — apply must NOT trust it.
        let mut prof = profile::Profile::default();
        let pat = format!("{}/proj/nm", h.path.display());
        prof.paths.never_touch.push(pat);

        // Sanity: target still exists and size unchanged, so only the gate differs.
        assert!(target.exists());

        match revalidate(&plan, &hash, &prof).unwrap() {
            Err(Refusal::Unsafe { .. }) => {}
            other => panic!("expected Unsafe, got {:?}", other.map(|_| "Ok")),
        }
    }

    #[test]
    fn clean_revalidate_passes_and_execute_plan_airlocks() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("clean");
        let prof = profile::Profile::default();
        let (plan, hash, target) = make_plan(&h.path, "nm", 4096);

        // Clean world: revalidate must pass.
        assert!(
            matches!(revalidate(&plan, &hash, &prof).unwrap(), Ok(())),
            "an unmodified target within tolerance and passing the live gate must validate"
        );

        // And executing it airlocks the target away (proving apply's executor path
        // is the same airlock path doctor uses, with a receipt).
        let df_before = history::free_bytes(&h.path).unwrap_or(0);
        let outcome = doctor::execute_plan(
            &plan,
            &prof,
            &quiet_ctx(),
            df_before,
            df_before + plan.need_bytes,
            &h.path,
        )
        .unwrap();
        assert!(!target.exists(), "execute_plan airlocked the target away");
        assert_eq!(outcome.freed_bytes, plan.steps[0].size_bytes);

        let hist = history::tail(10).unwrap();
        assert!(
            hist.iter().any(|e| e.path == target),
            "a history receipt was appended for the applied step"
        );
    }

    /// `current_size` measures on-disk ALLOCATED blocks (`blocks*512`), the SAME
    /// basis the scanner uses to size `ScannedEntry.size_bytes` and therefore the
    /// plan's `size_bytes` — NOT apparent length (`metadata.len()`). This is the
    /// fix for the size-drift basis mismatch: a file's allocated bytes are a
    /// multiple of the 512-byte block (rounded up from its length), so for a small
    /// file `current_size` is the rounded-up block allocation, not the raw length.
    #[cfg(unix)]
    #[test]
    fn current_size_uses_allocated_blocks_basis_like_the_scanner() {
        use std::os::unix::fs::MetadataExt;
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("basis");
        let dir = h.path.join("proj");
        fs::create_dir_all(&dir).unwrap();
        // 1 byte: apparent len is 1, but the file occupies at least one 512-byte
        // block on disk — so the two bases DIVERGE, which is exactly the mismatch.
        let f = dir.join("tiny.bin");
        fs::write(&f, [0u8; 1]).unwrap();

        let md = std::fs::metadata(&f).unwrap();
        let expected_blocks = md.blocks() * 512;
        assert_eq!(
            current_size(&f),
            expected_blocks,
            "current_size must be allocated blocks*512 (scanner basis), not len()"
        );
        // And it must NOT equal the apparent length for this file (proving the
        // drift check no longer compares plan allocated-blocks vs apply apparent-len).
        assert_ne!(
            current_size(&f),
            md.len(),
            "allocated-blocks basis differs from apparent-len for a 1-byte file"
        );
    }

    /// A cloud-only placeholder (apparent len > 4096 but 0 allocated blocks) reads
    /// as 0 — matching the scanner, which skips placeholders — so it never trips a
    /// false size-drift. We can't fabricate a real evicted file portably, so we
    /// assert the file-level helper directly via the same predicate the scanner
    /// uses: len>4096 && blocks==0 → 0. Here we just assert a normal small file is
    /// NOT treated as a placeholder (blocks>0), guarding the predicate's polarity.
    #[cfg(unix)]
    #[test]
    fn ordinary_file_is_not_mistaken_for_a_cloud_placeholder() {
        use std::os::unix::fs::MetadataExt;
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("placeholder");
        let f = h.path.join("real.bin");
        fs::write(&f, vec![0u8; 8192]).unwrap();
        let md = std::fs::metadata(&f).unwrap();
        assert!(md.blocks() > 0, "a real 8KiB file allocates blocks");
        assert!(
            current_size(&f) > 0,
            "an ordinary file with allocated blocks is sized, not zeroed as a placeholder"
        );
    }
}

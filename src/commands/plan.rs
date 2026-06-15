//! `diskspace plan --need <size> [--mode airlock|immediate]` — the TOCTOU-safe
//! first half of two-phase recovery.
//!
//! `plan` does the SELECTION (scan → candidates → pressure-test → greedy pick) by
//! reusing `doctor::build_plan` verbatim, content-addresses the result, persists
//! it under `~/.diskspace/plans/<hash>.json`, and prints the plan as JSON with an
//! `apply_cmd`. It NEVER touches the target filesystem — no airlock, no delete.
//! Actuation is `apply`, which re-validates everything live before acting.
//!
//! ## Why the hash excludes the pressure result
//!
//! The `plan_hash` is a content address of the *intended actions* — the canonical
//! tuple `(candidate_id, path, size_bytes, mode)` for each step, sorted by
//! `candidate_id`. It is deliberately computed over ONLY those stable fields and
//! NOT over the captured `pressure` result, `created_at`, or `projected_freed`.
//! The pressure-test is a point-in-time observation that `apply` RE-RUNS live; if
//! it were folded into the hash, two plans proposing the identical actions could
//! hash differently merely because the gate's confidence decayed between runs, and
//! `apply`'s hash check would reject a structurally-identical plan. The hash
//! answers "are these the same actions?", and the live re-validation in `apply`
//! answers "are they still safe right now?". Keeping those two concerns separate
//! is the whole point of the split.

use anyhow::{Context as _, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::commands::doctor::{self, Mode, Plan, PlanStep};
use crate::core::history;
use crate::output::Context;
use crate::profile;

/// `~/.diskspace/plans` — where persisted, content-addressed plans live.
pub fn plans_dir() -> PathBuf {
    profile::data_dir().join("plans")
}

/// Path to a persisted plan by its content hash.
pub fn plan_path(plan_hash: &str) -> PathBuf {
    plans_dir().join(format!("{}.json", plan_hash))
}

/// Compute the canonical content hash of a plan: SHA-256 over each step's
/// `(candidate_id, path, size_bytes, mode)` ONLY, with steps sorted by
/// `candidate_id` so ordering never changes the address. The time-varying
/// pressure result, `created_at`, and `projected_freed` are intentionally
/// EXCLUDED (see module docs) so the same intended actions always hash the same.
pub fn compute_plan_hash(steps: &[PlanStep]) -> String {
    // Sort a view of the steps by candidate_id so plan order can't perturb the
    // address. We hash a copy of the canonical tuples, never the live Vec order.
    let mut canon: Vec<(&str, String, u64, &str)> = steps
        .iter()
        .map(|s| {
            (
                s.candidate_id.as_str(),
                s.path.to_string_lossy().to_string(),
                s.size_bytes,
                s.mode.as_str(),
            )
        })
        .collect();
    canon.sort_by(|a, b| a.0.cmp(b.0));

    let mut hasher = Sha256::new();
    for (candidate_id, path, size_bytes, mode) in &canon {
        // Length-prefix + NUL-delimit each field so no concatenation collision is
        // possible (e.g. an id ending where a path begins). Deterministic bytes.
        hasher.update((candidate_id.len() as u64).to_le_bytes());
        hasher.update(candidate_id.as_bytes());
        hasher.update(b"\0");
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(b"\0");
        hasher.update(size_bytes.to_le_bytes());
        hasher.update(b"\0");
        hasher.update((mode.len() as u64).to_le_bytes());
        hasher.update(mode.as_bytes());
        hasher.update(b"\0");
    }
    format!("{:x}", hasher.finalize())
}

/// Persist a plan to `~/.diskspace/plans/<hash>.json`. Returns the path written.
pub fn persist_plan(plan: &Plan) -> Result<PathBuf> {
    let dir = plans_dir();
    std::fs::create_dir_all(&dir).context("creating plans dir")?;
    let path = plan_path(&plan.plan_hash);
    let json = serde_json::to_string_pretty(plan)?;
    std::fs::write(&path, json).with_context(|| format!("writing plan {}", path.display()))?;
    Ok(path)
}

/// Load a persisted plan by hash. Errors if the file is missing or unparseable.
pub fn load_plan(plan_hash: &str) -> Result<Plan> {
    let path = plan_path(plan_hash);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("no plan found at {}", path.display()))?;
    serde_json::from_str(&content).with_context(|| format!("parsing plan {}", path.display()))
}

pub fn run(need: &str, mode: &str, ctx: &Context) -> Result<()> {
    let prof = profile::load()?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let home_path = Path::new(&home);

    let need_bytes = match doctor::parse_size(need) {
        Some(b) => b,
        None => {
            if ctx.json {
                println!(
                    r#"{{"planned":false,"reason":"could not parse --need '{}'"}}"#,
                    need
                );
            } else {
                eprintln!("  Could not parse --need '{}'. Try e.g. 20G, 500M.", need);
            }
            std::process::exit(1);
        }
    };

    let exec_mode = Mode::from_str(mode);
    let df_before = history::free_bytes(home_path).unwrap_or(0);

    // The delta still to recover (build_plan accumulates against THIS, exactly as
    // doctor does after subtracting current free space).
    let to_recover = need_bytes.saturating_sub(df_before);

    // SELECTION ONLY — build_plan scans, pressure-tests every candidate, keeps the
    // safe survivors, and greedily picks the smallest set. It NEVER actuates.
    let mut plan = doctor::build_plan(to_recover, exec_mode, &prof, home_path, ctx)?;

    // Content-address the intended actions and persist.
    plan.plan_hash = compute_plan_hash(&plan.steps);
    let saved_to = persist_plan(&plan)?;

    let apply_cmd = format!("diskspace apply {}", plan.plan_hash);

    if ctx.json {
        let payload = serde_json::json!({
            "planned": true,
            "plan_hash": plan.plan_hash,
            "need_bytes": need_bytes,
            "free_before": df_before,
            "to_recover": to_recover,
            "mode": exec_mode.as_str(),
            "projected_freed": plan.projected_freed,
            "steps": plan.steps,
            "saved_to": saved_to,
            "apply_cmd": apply_cmd,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        use console::Style;
        let dim = Style::new().dim();
        let bold = Style::new().bold();
        let yellow = Style::new().yellow();
        let green = Style::new().green().bold();
        println!();
        println!(
            "  {}  {} step(s), projected {} (mode: {})",
            ctx.style("plan", &bold),
            plan.steps.len(),
            ctx.style(&crate::output::format_bytes(plan.projected_freed), &green),
            exec_mode.as_str(),
        );
        for s in &plan.steps {
            println!(
                "  {}  {:>9}  {}",
                ctx.style("•", &yellow),
                ctx.style(&crate::output::format_bytes(s.size_bytes), &bold),
                ctx.style(&s.path.display().to_string(), &dim),
            );
        }
        println!();
        println!(
            "  {}  {}",
            ctx.style("apply:", &bold),
            ctx.style(&apply_cmd, &dim),
        );
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::doctor::{Plan, PlanStep};
    use crate::core::candidate::CheckResult;
    use chrono::Utc;

    fn step(candidate_id: &str, path: &str, size: u64, mode: &str) -> PlanStep {
        PlanStep {
            candidate_id: candidate_id.into(),
            rule_id: "rule".into(),
            path: PathBuf::from(path),
            size_bytes: size,
            confidence: 0.9,
            mode: mode.into(),
            reversible: mode == "airlock",
            pressure: CheckResult::gate(candidate_id.into(), true, 1.0, vec![]),
            consequence_contract: None,
        }
    }

    #[test]
    fn plan_hash_is_stable_for_same_actions() {
        let a = vec![
            step("c1", "/a", 100, "airlock"),
            step("c2", "/b", 200, "airlock"),
        ];
        // Same actions, but built in the opposite order AND with a different
        // captured pressure confidence — the hash must be identical.
        let mut b = vec![
            step("c2", "/b", 200, "airlock"),
            step("c1", "/a", 100, "airlock"),
        ];
        b[0].pressure = CheckResult::gate("c2".into(), true, 0.5, vec![]);
        b[0].confidence = 0.1;

        assert_eq!(
            compute_plan_hash(&a),
            compute_plan_hash(&b),
            "hash is over canonical (id,path,size,mode) sorted by id — order and \
             the time-varying pressure/confidence must NOT change it"
        );
    }

    #[test]
    fn plan_hash_changes_when_one_canonical_field_changes() {
        let base = vec![step("c1", "/a", 100, "airlock")];
        let h0 = compute_plan_hash(&base);

        // size drift by one byte
        let changed_size = vec![step("c1", "/a", 101, "airlock")];
        assert_ne!(h0, compute_plan_hash(&changed_size), "size is in the hash");

        // path change
        let changed_path = vec![step("c1", "/a2", 100, "airlock")];
        assert_ne!(h0, compute_plan_hash(&changed_path), "path is in the hash");

        // mode change
        let changed_mode = vec![step("c1", "/a", 100, "immediate")];
        assert_ne!(h0, compute_plan_hash(&changed_mode), "mode is in the hash");

        // candidate_id change
        let changed_id = vec![step("c9", "/a", 100, "airlock")];
        assert_ne!(h0, compute_plan_hash(&changed_id), "id is in the hash");
    }

    #[test]
    fn persist_then_load_roundtrips_via_tempbase() {
        // Use the doctor TempHome pattern indirectly: override HOME to a tempdir
        // so plans_dir() resolves under it. We don't have the doctor lock here, so
        // guard with the shared HOME_TEST_LOCK to serialize against other $HOME
        // overriders.
        let _g = crate::core::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut tmp = std::env::temp_dir();
        tmp.push(format!(
            "diskspace-plan-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let prev = std::env::var_os("HOME");
        // SAFETY: serialized by HOME_TEST_LOCK; restored below.
        unsafe {
            std::env::set_var("HOME", &tmp);
        }

        let steps = vec![step("c1", "/a", 100, "airlock")];
        let hash = compute_plan_hash(&steps);
        let plan = Plan {
            plan_hash: hash.clone(),
            need_bytes: 100,
            steps,
            projected_freed: 100,
            created_at: Utc::now(),
        };
        persist_plan(&plan).unwrap();
        let loaded = load_plan(&hash).unwrap();
        assert_eq!(loaded.plan_hash, hash);
        assert_eq!(loaded.steps.len(), 1);
        assert_eq!(compute_plan_hash(&loaded.steps), hash);

        // SAFETY: serialized by HOME_TEST_LOCK; restores the previous value.
        unsafe {
            match prev {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

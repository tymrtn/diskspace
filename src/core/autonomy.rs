//! The single unattended reclaim path.
//!
//! Every delete diskspace performs WITHOUT a human at the keyboard goes through
//! [`reclaim`]. There is deliberately no second path: the watch tick, and any
//! future automatic cleanup, hand their candidates here and get back a receipt
//! of what was moved or removed and, per refused candidate, which stage said no.
//!
//! The gate, in order, for every candidate:
//!
//! 1. `policy`: the user's standing opt-in (`preferences.watch_autoreclaim`).
//! 2. `tier`: confidence floor + regenerable recovery class (`auto` /
//!    `redownload` / `rebuild`). Grants may RELAX this tier in `actuation`
//!    builds; they never widen this path.
//! 3. `pressure-test`: `check::pressure_test`, the floor every delete shares.
//! 4. `gate`: `safety::autonomous_gate`, the extra unattended checks (symlinks,
//!    containment, cloud sync, protected content).
//! 5. `execute`: airlock (reversible) or, under disk pressure, delete.
//!
//! Free space is measured before and after so the receipt carries ACTUAL
//! recovery, never an estimate: a same-volume airlock rename frees nothing until
//! purge, and the outcome says so.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::commands::check;
use crate::core::airlock_store;
use crate::core::candidate::Candidate;
use crate::core::history::{self, ActionKind, Entry};
use crate::core::safety;
use crate::profile::Profile;

/// Confidence floor for the regenerable tier — matches the manual `reclaim`
/// command's floor. Below this, nothing is touched unattended.
pub const MIN_CONFIDENCE: f32 = 0.85;

/// Recovery classes in the regenerable tier. These come back on their own
/// (`auto`) or on next use with no project-breaking step (`redownload`,
/// `rebuild`). `recreate` (venvs / node_modules — a project won't run until
/// manually reinstalled), `manual` and `irreversible` are excluded.
pub const SAFE_RECOVERY: &[&str] = &["auto", "redownload", "rebuild"];

/// Pure tier filter. A candidate with no consequence metadata is NOT eligible
/// (fail-closed — recovery semantics we cannot read are not regenerable).
pub fn is_regenerable_tier(confidence: f32, recovery: Option<&str>) -> bool {
    confidence >= MIN_CONFIDENCE && matches!(recovery, Some(r) if SAFE_RECOVERY.contains(&r))
}

/// What the unattended path does with a candidate that clears the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Move into `~/.diskspace/airlock` (reversible with `diskspace restore`).
    Airlock,
    /// Remove outright. Only under disk pressure, where staging frees nothing.
    Delete,
}

/// Same rule `doctor` uses: below `preferences.disk_pressure_threshold_gb` of
/// free space, a same-volume airlock would free nothing, so delete.
pub fn disposition_for(free_bytes: u64, prof: &Profile) -> Disposition {
    let threshold =
        (prof.preferences.disk_pressure_threshold_gb as f64 * 1024.0 * 1024.0 * 1024.0) as u64;
    if free_bytes < threshold {
        Disposition::Delete
    } else {
        Disposition::Airlock
    }
}

/// One unattended reclaim run.
pub struct Request<'a> {
    pub home: &'a Path,
    pub prof: &'a Profile,
    /// The user's standing consent. `false` refuses every candidate at `policy`.
    pub opt_in: bool,
    pub disposition: Disposition,
    /// Why this run happened (`"watch-urgent"`, ...). Recorded in every receipt.
    pub trigger: &'a str,
    /// Incident this run belongs to, for deduplication across ticks.
    pub incident_id: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Refusal {
    pub candidate_id: String,
    pub path: PathBuf,
    pub stage: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Action {
    pub candidate_id: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub disposition: Disposition,
    /// Airlock entry id (`diskspace restore <id>`), when airlocked.
    pub airlock_id: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Outcome {
    pub actions: Vec<Action>,
    pub refusals: Vec<Refusal>,
    /// Sum of candidate sizes acted on — an ESTIMATE from the scan.
    pub bytes_estimated: u64,
    /// Free bytes on `home`'s volume before and after, as the OS reports them.
    pub df_before: Option<u64>,
    pub df_after: Option<u64>,
    /// `df_after - df_before`, saturating. The only number that is actual recovery.
    pub actually_freed: Option<u64>,
}

/// Run the unattended gate over `candidates` and act on the survivors.
pub fn reclaim(candidates: &[Candidate], req: &Request) -> Outcome {
    let mut out = Outcome::default();
    let refuse = |out: &mut Outcome, c: &Candidate, stage: &'static str, reason: String| {
        out.refusals.push(Refusal {
            candidate_id: c.id.clone(),
            path: c.path.clone(),
            stage,
            reason,
        });
    };

    if !req.opt_in {
        for c in candidates {
            refuse(
                &mut out,
                c,
                "policy",
                "autonomous cleanup is off (preferences.watch_autoreclaim)".into(),
            );
        }
        return out;
    }

    out.df_before = history::free_bytes(req.home);

    for c in candidates {
        let recovery = c.consequences.as_ref().map(|q| q.recovery.as_str());
        if !is_regenerable_tier(c.confidence, recovery) {
            refuse(
                &mut out,
                c,
                "tier",
                format!(
                    "confidence {:.2} / recovery {} is outside the regenerable tier",
                    c.confidence,
                    recovery.unwrap_or("unknown")
                ),
            );
            continue;
        }

        match check::pressure_test(&c.id, &c.path, req.prof) {
            Ok(r) if r.safe => {}
            Ok(r) => {
                let failed: Vec<String> = r
                    .steps
                    .iter()
                    .filter(|s| !s.passed)
                    .map(|s| format!("{}: {}", s.name, s.note))
                    .collect();
                refuse(&mut out, c, "pressure-test", failed.join("; "));
                continue;
            }
            Err(e) => {
                refuse(&mut out, c, "pressure-test", e.to_string());
                continue;
            }
        }

        let steps = safety::autonomous_gate(&c.path, req.home);
        if !safety::autonomous_gate_passed(&steps) {
            let failed: Vec<String> = steps
                .iter()
                .filter(|s| !s.passed)
                .map(|s| format!("{}: {}", s.name, s.note))
                .collect();
            refuse(&mut out, c, "gate", failed.join("; "));
            continue;
        }

        match execute(c, req) {
            Ok(action) => {
                out.bytes_estimated += c.size_bytes;
                out.actions.push(action);
            }
            Err(e) => refuse(&mut out, c, "execute", e.to_string()),
        }
    }

    out.df_after = history::free_bytes(req.home);
    out.actually_freed = out
        .df_before
        .zip(out.df_after)
        .map(|(before, after)| after.saturating_sub(before));
    out
}

/// Airlock or delete one gated survivor and append its receipt.
fn execute(c: &Candidate, req: &Request) -> anyhow::Result<Action> {
    let mut context = serde_json::Map::new();
    context.insert("auto".into(), serde_json::Value::Bool(true));
    context.insert("trigger".into(), req.trigger.into());
    context.insert("incident_id".into(), req.incident_id.into());

    let (command, reversible, undo_cmd, airlock_id) = match req.disposition {
        Disposition::Airlock => {
            let (entry, kind) = airlock_store::airlock_path(
                &c.id,
                &c.path,
                req.prof.preferences.airlock_retention_days,
            )?;
            let mut manifest = airlock_store::load_manifest()?;
            manifest.entries.push(entry.clone());
            airlock_store::save_manifest(&manifest)?;
            context.insert("disposition".into(), "airlock".into());
            context.insert(
                "move_kind".into(),
                match kind {
                    airlock_store::MoveKind::Rename => "rename",
                    airlock_store::MoveKind::CopyRemove => "copy_remove",
                }
                .into(),
            );
            (
                ActionKind::Airlock,
                true,
                Some(format!("diskspace restore {}", entry.id)),
                Some(entry.id),
            )
        }
        Disposition::Delete => {
            if c.path.is_dir() {
                std::fs::remove_dir_all(&c.path)?;
            } else {
                std::fs::remove_file(&c.path)?;
            }
            context.insert("disposition".into(), "delete".into());
            (ActionKind::Reclaim, false, None, None)
        }
    };

    history::append(&Entry {
        ts: chrono::Utc::now(),
        command,
        candidate_id: Some(c.id.clone()),
        rule_id: Some(c.rule_id.clone()),
        path: c.path.clone(),
        size_bytes: c.size_bytes,
        df_before: None,
        df_after: None,
        actually_freed: None,
        reversible,
        undo_cmd,
        rule_confidence: Some(c.confidence),
        context,
    });

    Ok(Action {
        candidate_id: c.id.clone(),
        path: c.path.clone(),
        size_bytes: c.size_bytes,
        disposition: req.disposition,
        airlock_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::candidate::Category;
    use crate::core::rules::Consequences;
    use crate::core::HomeGuard;

    struct TempHome {
        path: PathBuf,
        _guard: HomeGuard,
    }
    impl TempHome {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "diskspace-autonomy-{}-{}-{}",
                tag,
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            std::fs::create_dir_all(&p).unwrap();
            let path = std::fs::canonicalize(&p).unwrap();
            let guard = HomeGuard::set(&path);
            Self {
                path,
                _guard: guard,
            }
        }
        fn cache(&self, name: &str) -> PathBuf {
            let p = self.path.join("Library/Caches").join(name);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("blob.tmp"), vec![b'x'; 4096]).unwrap();
            age(&p);
            p
        }
    }

    fn age(root: &Path) {
        crate::core::backdate_files(root);
    }
    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn cand(path: &Path, confidence: f32, recovery: Option<&str>) -> Candidate {
        Candidate {
            id: format!("cand-{}", path.file_name().unwrap().to_string_lossy()),
            rule_id: "test-rule".into(),
            path: path.to_path_buf(),
            size_bytes: 4096,
            category: Category::AppCache,
            confidence,
            reason: "test".into(),
            domain: None,
            modified: None,
            accessed: None,
            consequences: recovery.map(|r| Consequences {
                recovery: r.into(),
                rebuild_seconds: None,
                impact: "test".into(),
                recovery_cmd: None,
            }),
            consequence_contract: None,
            metrics: None,
            reference_url: None,
        }
    }

    fn request<'a>(home: &'a TempHome, prof: &'a Profile, disposition: Disposition) -> Request<'a> {
        Request {
            home: &home.path,
            prof,
            opt_in: true,
            disposition,
            trigger: "test-trigger",
            incident_id: "incident-1",
        }
    }

    fn last_history() -> Entry {
        history::tail(1).unwrap().pop().expect("a history entry")
    }

    #[test]
    fn tier_filter_matches_manual_reclaim_floor() {
        assert!(is_regenerable_tier(0.90, Some("auto")));
        assert!(is_regenerable_tier(0.85, Some("redownload")));
        assert!(is_regenerable_tier(0.88, Some("rebuild")));
        assert!(!is_regenerable_tier(0.99, Some("recreate")));
        assert!(!is_regenerable_tier(0.99, Some("manual")));
        assert!(!is_regenerable_tier(0.99, Some("irreversible")));
        assert!(!is_regenerable_tier(0.50, Some("auto")));
        assert!(!is_regenerable_tier(0.99, None));
    }

    #[test]
    fn disposition_follows_pressure_threshold() {
        let mut prof = Profile::default();
        prof.preferences.disk_pressure_threshold_gb = 5.0;
        let five_gb = 5u64 * 1024 * 1024 * 1024;
        assert_eq!(disposition_for(five_gb - 1, &prof), Disposition::Delete);
        assert_eq!(disposition_for(five_gb, &prof), Disposition::Airlock);
        assert_eq!(disposition_for(five_gb * 10, &prof), Disposition::Airlock);
    }

    #[test]
    fn without_opt_in_nothing_is_touched() {
        let home = TempHome::new("optout");
        let prof = Profile::default();
        let p = home.cache("example");
        let mut req = request(&home, &prof, Disposition::Delete);
        req.opt_in = false;
        let out = reclaim(&[cand(&p, 0.95, Some("auto"))], &req);
        assert!(out.actions.is_empty());
        assert_eq!(out.refusals.len(), 1);
        assert_eq!(out.refusals[0].stage, "policy");
        assert!(p.exists(), "candidate must be untouched");
    }

    /// A grant on disk changes nothing here, in ANY build: the unattended path
    /// never consults grants. A below-tier candidate stays refused.
    #[test]
    fn below_tier_is_refused_even_with_a_grant_on_disk() {
        let home = TempHome::new("tier");
        let prof = Profile::default();
        std::fs::create_dir_all(home.path.join(".diskspace")).unwrap();
        std::fs::write(
            home.path.join(".diskspace/grant.json"),
            r#"{"schema_version":1,"category":"AgentAutonomy","recovery_class_ceiling":"Manual","max_bytes":1000000000,"min_confidence":0.1,"path_scope":null,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","nonce":"n","signature":"00"}"#,
        )
        .unwrap();
        let low = home.cache("low-confidence");
        let recreate = home.cache("venv-like");
        let req = request(&home, &prof, Disposition::Delete);
        let out = reclaim(
            &[
                cand(&low, 0.70, Some("auto")),
                cand(&recreate, 0.99, Some("recreate")),
            ],
            &req,
        );
        assert!(out.actions.is_empty());
        assert_eq!(out.refusals.len(), 2);
        assert!(out.refusals.iter().all(|r| r.stage == "tier"));
        assert!(low.exists() && recreate.exists());
    }

    #[test]
    fn protected_content_is_refused_at_the_gate() {
        let home = TempHome::new("gate");
        let prof = Profile::default();
        let p = home.cache("with-secret");
        std::fs::write(p.join(".env"), b"TOKEN=x").unwrap();
        age(&p);
        let req = request(&home, &prof, Disposition::Delete);
        let out = reclaim(&[cand(&p, 0.95, Some("auto"))], &req);
        assert!(out.actions.is_empty());
        assert_eq!(out.refusals[0].stage, "gate");
        assert!(out.refusals[0].reason.contains("credentials"));
        assert!(p.exists());
    }

    #[test]
    fn database_is_refused_by_the_pressure_test() {
        let home = TempHome::new("db");
        let prof = Profile::default();
        let p = home.cache("with-db");
        std::fs::write(p.join("state.sqlite"), b"SQLite format 3\0").unwrap();
        age(&p);
        let req = request(&home, &prof, Disposition::Delete);
        let out = reclaim(&[cand(&p, 0.95, Some("auto"))], &req);
        assert!(out.actions.is_empty());
        assert_eq!(out.refusals[0].stage, "pressure-test");
        assert!(p.exists());
    }

    #[test]
    fn airlock_disposition_stages_reversibly_and_records_receipt() {
        let home = TempHome::new("airlock");
        let prof = Profile::default();
        let p = home.cache("staged");
        let req = request(&home, &prof, Disposition::Airlock);
        let out = reclaim(&[cand(&p, 0.95, Some("rebuild"))], &req);
        assert_eq!(out.refusals.len(), 0, "{:?}", out.refusals);
        assert_eq!(out.actions.len(), 1);
        assert!(!p.exists(), "original path must be gone");
        let airlock_id = out.actions[0].airlock_id.clone().expect("airlock id");
        let manifest = airlock_store::load_manifest().unwrap();
        let entry = manifest
            .entries
            .iter()
            .find(|e| e.id == airlock_id)
            .expect("manifest entry");
        assert!(entry.airlock_path.exists(), "bytes must still be on disk");
        assert_eq!(entry.original_path, p);
        assert_eq!(out.bytes_estimated, 4096);
        assert!(out.df_before.is_some() && out.df_after.is_some());
        assert!(out.actually_freed.is_some());

        let h = last_history();
        assert!(matches!(h.command, ActionKind::Airlock));
        assert!(h.reversible);
        assert_eq!(
            h.undo_cmd.as_deref(),
            Some(format!("diskspace restore {}", airlock_id).as_str())
        );
        assert_eq!(h.context["auto"], serde_json::Value::Bool(true));
        assert_eq!(h.context["trigger"], "test-trigger");
        assert_eq!(h.context["incident_id"], "incident-1");
        assert_eq!(h.context["disposition"], "airlock");
    }

    #[test]
    fn delete_disposition_removes_and_records_irreversible_receipt() {
        let home = TempHome::new("delete");
        let prof = Profile::default();
        let p = home.cache("doomed");
        let req = request(&home, &prof, Disposition::Delete);
        let out = reclaim(&[cand(&p, 0.95, Some("auto"))], &req);
        assert_eq!(out.refusals.len(), 0, "{:?}", out.refusals);
        assert_eq!(out.actions.len(), 1);
        assert_eq!(out.actions[0].disposition, Disposition::Delete);
        assert!(out.actions[0].airlock_id.is_none());
        assert!(!p.exists());

        let h = last_history();
        assert!(matches!(h.command, ActionKind::Reclaim));
        assert!(!h.reversible);
        assert_eq!(h.context["disposition"], "delete");
        assert_eq!(h.context["incident_id"], "incident-1");
    }
}

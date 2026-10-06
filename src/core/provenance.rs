//! Provenance: who produced an artifact, and whether they still need it.
//!
//! Agents and build tools leave artifacts whose owner is somewhere else on the
//! disk: a cargo `build-dir` keyed by a hash of its workspace path, a git
//! worktree whose repository lives in another directory. Size and age say
//! nothing about whether the producer is still around. This module reads the
//! evidence the artifact itself carries and answers one question per candidate:
//!
//! * [`Liveness::Active`]: the producer still needs it (uncommitted or
//!   unpushed work). The unattended gate refuses these outright.
//! * [`Liveness::Present`]: the producer exists and can regenerate it. Neutral.
//! * [`Liveness::Orphaned`]: nothing needs it any more. Confidence rises by at
//!   most [`ORPHAN_BOOST`]; every other gate still applies.
//! * [`Liveness::Unknown`]: the evidence could not be read. Neutral.
//!
//! Every probe is read-only and bounded: a few `stat`s, one small file read,
//! and for worktrees two `git` invocations against that worktree only.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

/// Most an orphaned artifact's confidence may rise.
pub const ORPHAN_BOOST: f32 = 0.10;
/// Confidence ceiling after the boost (matches `detect`'s own cap).
const CONFIDENCE_CAP: f32 = 0.99;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Producer {
    CargoWorkspace,
    GitRepository,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Liveness {
    Active,
    Present,
    Orphaned,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub producer: Producer,
    /// Where the producer lives (workspace root, repository root) when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_path: Option<PathBuf>,
    pub liveness: Liveness,
    /// Human-readable facts the verdict rests on, in the order they were found.
    pub evidence: Vec<String>,
}

/// What the last survey knows about workspaces on this disk: every `Cargo.toml`
/// it saw, indexed by the hash cargo would use for its `build-dir`.
#[derive(Debug, Default)]
pub struct Index {
    by_hash: HashMap<String, PathBuf>,
    manifests_seen: usize,
}

impl Index {
    /// Hash every manifest that still exists. One deleted since the survey
    /// hashes to nothing, which is exactly what leaves its build dir orphaned.
    pub fn from_manifests(manifests: &[PathBuf]) -> Self {
        let mut by_hash = HashMap::new();
        for m in manifests.iter().filter(|m| m.is_file()) {
            if let Some(root) = m.parent() {
                by_hash.insert(cargo_workspace_hash(m), root.to_path_buf());
            }
        }
        Self {
            by_hash,
            manifests_seen: manifests.len(),
        }
    }
}

/// The `XX/YYYYYYYYYYYYYY` cargo substitutes for `{workspace-path-hash}`:
/// `StableSipHasher128` over the canonicalized root manifest path, low 64 bits,
/// little-endian hex, split 2 + 14.
pub fn cargo_workspace_hash(manifest: &Path) -> String {
    let real = std::fs::canonicalize(manifest).unwrap_or_else(|_| manifest.to_path_buf());
    let mut hasher = rustc_stable_hash::StableSipHasher128::new();
    real.hash(&mut hasher);
    let hex: String = Hasher::finish(&hasher)
        .to_le_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("{}/{}", &hex[..2], &hex[2..])
}

/// Read the evidence for `path`. `None` when the path carries none.
pub fn probe(path: &Path, index: &Index) -> Option<Provenance> {
    probe_git_worktree(path).or_else(|| probe_cargo_target(path, index))
}

/// Confidence after provenance: orphaned artifacts rise by [`ORPHAN_BOOST`],
/// capped; everything else is unchanged.
pub fn adjust_confidence(confidence: f32, prov: &Provenance) -> f32 {
    match prov.liveness {
        Liveness::Orphaned => (confidence + ORPHAN_BOOST).min(CONFIDENCE_CAP),
        _ => confidence,
    }
}

/// A `target` directory: beside its `Cargo.toml`, or in cargo's hashed
/// `build-dir` layout (`<base>/<2 hex>/<14 hex>/target`).
fn probe_cargo_target(path: &Path, index: &Index) -> Option<Provenance> {
    if path.file_name()? != "target" {
        return None;
    }
    let parent = path.parent()?;
    if parent.join("Cargo.toml").is_file() {
        return Some(Provenance {
            producer: Producer::CargoWorkspace,
            producer_path: Some(parent.to_path_buf()),
            liveness: Liveness::Present,
            evidence: vec!["Cargo.toml beside target".into()],
        });
    }
    let hash = format!(
        "{}/{}",
        parent.parent()?.file_name()?.to_str()?,
        parent.file_name()?.to_str()?
    );
    if !is_hash_layout(&hash) {
        return None;
    }
    let mut prov = Provenance {
        producer: Producer::CargoWorkspace,
        producer_path: None,
        liveness: Liveness::Unknown,
        evidence: vec![format!("cargo build-dir {}", hash)],
    };
    if index.manifests_seen == 0 {
        prov.evidence
            .push("no survey on record to match the workspace hash against".into());
        return Some(prov);
    }
    match index.by_hash.get(&hash) {
        Some(root) => {
            prov.evidence.push(format!(
                "workspace {} hashes to this build dir",
                root.display()
            ));
            prov.producer_path = Some(root.clone());
            prov.liveness = Liveness::Present;
        }
        None => {
            prov.evidence.push(format!(
                "no workspace among {} surveyed manifest(s) hashes to this build dir",
                index.manifests_seen
            ));
            prov.liveness = Liveness::Orphaned;
        }
    }
    Some(prov)
}

fn is_hash_layout(s: &str) -> bool {
    let Some((a, b)) = s.split_once('/') else {
        return false;
    };
    let hex = |t: &str| {
        t.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    };
    a.len() == 2 && b.len() == 14 && hex(a) && hex(b)
}

/// A linked git worktree: `.git` is a FILE pointing into the parent
/// repository's `.git/worktrees/<name>`.
fn probe_git_worktree(path: &Path) -> Option<Provenance> {
    let dot_git = path.join(".git");
    if !dot_git.is_file() {
        return None;
    }
    let content = std::fs::read_to_string(&dot_git).ok()?;
    let gitdir = content
        .lines()
        .find_map(|l| l.strip_prefix("gitdir:"))
        .map(|s| PathBuf::from(s.trim()))?;
    let gitdir = if gitdir.is_absolute() {
        gitdir
    } else {
        path.join(gitdir)
    };
    // <repo>/.git/worktrees/<name>  →  <repo>
    let repo = gitdir
        .ancestors()
        .find(|a| a.file_name().is_some_and(|n| n == ".git"))
        .and_then(Path::parent)
        .map(Path::to_path_buf);
    let mut prov = Provenance {
        producer: Producer::GitRepository,
        producer_path: repo.clone(),
        liveness: Liveness::Unknown,
        evidence: vec![format!(
            "git worktree of {}",
            repo.as_deref().unwrap_or(&gitdir).display()
        )],
    };
    if !gitdir.is_dir() {
        prov.evidence
            .push("parent repository missing; uncommitted work cannot be assessed".into());
        return Some(prov);
    }
    let Some(status) = git(path, &["status", "--porcelain", "--untracked-files=normal"]) else {
        prov.evidence.push("git status failed".into());
        return Some(prov);
    };
    let dirty = status.lines().filter(|l| !l.trim().is_empty()).count();
    if dirty > 0 {
        prov.evidence
            .push(format!("{} uncommitted change(s)", dirty));
        prov.liveness = Liveness::Active;
        return Some(prov);
    }
    match git(path, &["rev-list", "--count", "HEAD", "--not", "--remotes"])
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        None => prov
            .evidence
            .push("could not count unpushed commits".into()),
        Some(n) if n > 0 => {
            prov.evidence
                .push(format!("{} commit(s) not on any remote", n));
            prov.liveness = Liveness::Active;
        }
        Some(_) => {
            prov.evidence
                .push("clean; every commit is on a remote".into());
            prov.liveness = Liveness::Orphaned;
        }
    }
    Some(prov)
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "diskspace-prov-{}-{}-{}",
                tag,
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(std::fs::canonicalize(&p).unwrap())
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
            .args(args)
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A repository with one commit and a worktree checked out beside it on a
    /// new branch, as `git worktree add` creates by default.
    fn repo_with_worktree(tmp: &Tmp) -> (PathBuf, PathBuf) {
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        std::fs::write(repo.join("a.txt"), "a").unwrap();
        git(&repo, &["add", "a.txt"]);
        git(&repo, &["commit", "-q", "-m", "init"]);
        let wt = tmp.path().join("wt");
        git(&repo, &["worktree", "add", "-q", wt.to_str().unwrap()]);
        (repo, wt)
    }

    #[test]
    fn cargo_workspace_hash_matches_cargo() {
        // Value produced by cargo 1.97's own implementation for this literal
        // path (which does not exist, so canonicalize falls back to it).
        assert_eq!(
            cargo_workspace_hash(Path::new("/w/Cargo.toml")),
            "7e/8c78ca00f75ef2"
        );
    }

    #[test]
    fn target_beside_a_manifest_is_present() {
        let tmp = Tmp::new("beside");
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(ws.join("target")).unwrap();
        std::fs::write(ws.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
        let p = probe(&ws.join("target"), &Index::default()).expect("evidence");
        assert_eq!(p.producer, Producer::CargoWorkspace);
        assert_eq!(p.liveness, Liveness::Present);
        assert_eq!(p.producer_path.as_deref(), Some(ws.as_path()));
    }

    #[test]
    fn build_dir_hashing_to_a_surveyed_manifest_is_present() {
        let tmp = Tmp::new("hash-hit");
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let manifest = ws.join("Cargo.toml");
        std::fs::write(&manifest, "[package]\nname='x'\n").unwrap();
        let build = tmp
            .path()
            .join("cargo-build")
            .join(cargo_workspace_hash(&manifest))
            .join("target");
        std::fs::create_dir_all(&build).unwrap();

        let idx = Index::from_manifests(&[manifest]);
        let p = probe(&build, &idx).expect("evidence");
        assert_eq!(p.producer, Producer::CargoWorkspace);
        assert_eq!(p.liveness, Liveness::Present);
        assert_eq!(p.producer_path.as_deref(), Some(ws.as_path()));
    }

    #[test]
    fn build_dir_with_no_matching_manifest_is_orphaned() {
        let tmp = Tmp::new("hash-miss");
        let other = tmp.path().join("other").join("Cargo.toml");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        std::fs::write(&other, "[package]\nname='y'\n").unwrap();
        let build = tmp
            .path()
            .join("cargo-build")
            .join("0c")
            .join("a4d1336e85fe5d")
            .join("target");
        std::fs::create_dir_all(&build).unwrap();

        let p = probe(&build, &Index::from_manifests(&[other])).expect("evidence");
        assert_eq!(p.liveness, Liveness::Orphaned);
        assert!(
            p.evidence.iter().any(|e| e.contains("no workspace")),
            "{:?}",
            p.evidence
        );
    }

    #[test]
    fn build_dir_without_a_survey_is_unknown() {
        let tmp = Tmp::new("no-survey");
        let build = tmp
            .path()
            .join("cargo-build")
            .join("0c")
            .join("a4d1336e85fe5d")
            .join("target");
        std::fs::create_dir_all(&build).unwrap();
        let p = probe(&build, &Index::default()).expect("evidence");
        assert_eq!(p.liveness, Liveness::Unknown);
    }

    #[test]
    fn dirty_worktree_is_active() {
        let tmp = Tmp::new("dirty");
        let (repo, wt) = repo_with_worktree(&tmp);
        std::fs::write(wt.join("wip.txt"), "unsaved").unwrap();
        let p = probe(&wt, &Index::default()).expect("evidence");
        assert_eq!(p.producer, Producer::GitRepository);
        assert_eq!(p.liveness, Liveness::Active);
        assert_eq!(p.producer_path.as_deref(), Some(repo.as_path()));
        assert!(
            p.evidence.iter().any(|e| e.contains("uncommitted")),
            "{:?}",
            p.evidence
        );
    }

    #[test]
    fn worktree_with_unpushed_commits_is_active() {
        let tmp = Tmp::new("unpushed");
        let (_repo, wt) = repo_with_worktree(&tmp);
        let p = probe(&wt, &Index::default()).expect("evidence");
        assert_eq!(p.liveness, Liveness::Active);
        assert!(
            p.evidence.iter().any(|e| e.contains("not on any remote")),
            "{:?}",
            p.evidence
        );
    }

    #[test]
    fn clean_fully_pushed_worktree_is_orphaned() {
        let tmp = Tmp::new("pushed");
        let (repo, wt) = repo_with_worktree(&tmp);
        let remote = tmp.path().join("remote.git");
        git(
            tmp.path(),
            &["init", "-q", "--bare", remote.to_str().unwrap()],
        );
        git(
            &repo,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        git(&wt, &["push", "-q", "-u", "origin", "HEAD"]);
        let p = probe(&wt, &Index::default()).expect("evidence");
        assert_eq!(p.liveness, Liveness::Orphaned, "{:?}", p.evidence);
    }

    #[test]
    fn worktree_whose_repository_is_gone_is_unknown() {
        let tmp = Tmp::new("gone");
        let wt = tmp.path().join("wt");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(
            wt.join(".git"),
            format!(
                "gitdir: {}\n",
                tmp.path().join("missing/.git/worktrees/wt").display()
            ),
        )
        .unwrap();
        let p = probe(&wt, &Index::default()).expect("evidence");
        assert_eq!(p.producer, Producer::GitRepository);
        assert_eq!(p.liveness, Liveness::Unknown);
    }

    #[test]
    fn plain_directory_has_no_provenance() {
        let tmp = Tmp::new("plain");
        assert!(probe(tmp.path(), &Index::default()).is_none());
    }

    #[test]
    fn orphaned_boosts_confidence_by_at_most_ten_points() {
        let orphan = Provenance {
            producer: Producer::CargoWorkspace,
            producer_path: None,
            liveness: Liveness::Orphaned,
            evidence: vec![],
        };
        let active = Provenance {
            liveness: Liveness::Active,
            ..orphan.clone()
        };
        assert!((adjust_confidence(0.78, &orphan) - 0.88).abs() < 1e-6);
        assert!((adjust_confidence(0.95, &orphan) - 0.99).abs() < 1e-6);
        assert_eq!(adjust_confidence(0.78, &active), 0.78);
    }
}

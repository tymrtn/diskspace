//! The `git gc` SAFE ACTION — the one strategy [`crate::core::classify::Strategy::Repack`]
//! executes in place. A `.git/objects/pack` store is the single highest-value
//! signature on the test disk (a 41.5 GB pack + a 12.5 GB pack), and unlike every
//! other strategy it reclaims bytes WITHOUT moving or deleting any user data: git
//! regenerates the packed objects from the same commits, so `git gc` is loss-free.
//!
//! That makes it the only signature we can act on directly rather than airlock or
//! offload. But "loss-free" is only true on a CLEAN repo — running `gc` while a
//! rebase/merge/cherry-pick is in progress, or while another git process holds the
//! repo, can drop the in-progress state. So this module is deliberately paranoid:
//!
//!   1. It walks UP from the pack dir to the nearest ancestor that actually IS a
//!      git repo (a `.git` dir or a bare repo). A non-git dir is REFUSED.
//!   2. It refuses a repo with a rebase/merge/cherry-pick/bisect in progress
//!      (the marker files git itself writes under `.git`).
//!   3. It measures the `.git` size before AND after and reports the REAL delta —
//!      never the classifier's estimate.
//!   4. It routes the result through a [`history`] receipt, same as airlock/reclaim.
//!
//! It NEVER sudos, NEVER touches anything outside the located repo, and (per the
//! command layer) only runs with confirmation or `--yes`. The repo discovery and
//! the dirty/in-progress refusal are pure and unit-tested; the `git gc` invocation
//! is exercised against a THROWAWAY temp repo, never a real user repo.

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::airlock_store::dir_size;
use crate::core::history::{self, ActionKind, Entry as HistEntry};
use crate::profile;

/// Why a repack was refused before it ran. Each maps to a clear user message and a
/// distinct JSON `error` token; none of them ever runs `git gc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepackRefusal {
    /// No enclosing git repo found walking up from the path.
    NotAGitRepo,
    /// The repo has a rebase / merge / cherry-pick / bisect / am in progress.
    /// Running `gc` here could drop that in-progress state.
    OperationInProgress(String),
    /// `git` itself isn't on PATH, or the discovery I/O failed.
    GitUnavailable(String),
}

impl std::fmt::Display for RepackRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepackRefusal::NotAGitRepo => {
                write!(f, "no git repository found at or above this path")
            }
            RepackRefusal::OperationInProgress(op) => {
                write!(f, "a git {op} is in progress — finish or abort it first")
            }
            RepackRefusal::GitUnavailable(e) => write!(f, "git is unavailable: {e}"),
        }
    }
}

impl RepackRefusal {
    /// Stable token for the JSON `error` field.
    pub fn token(&self) -> &'static str {
        match self {
            RepackRefusal::NotAGitRepo => "not_a_git_repo",
            RepackRefusal::OperationInProgress(_) => "git_operation_in_progress",
            RepackRefusal::GitUnavailable(_) => "git_unavailable",
        }
    }
}

/// The outcome of a successful repack: which repo, the real before/after `.git`
/// size, and the bytes actually reclaimed.
#[derive(Debug, Clone)]
pub struct RepackOutcome {
    /// The repo the `git gc` ran in (the dir that CONTAINS `.git`, or the bare repo).
    pub repo: PathBuf,
    /// `.git` size before `gc`, in bytes.
    pub git_size_before: u64,
    /// `.git` size after `gc`, in bytes.
    pub git_size_after: u64,
    /// Bytes the `.git` dir shrank (`before - after`, saturating). The HONEST,
    /// measured figure — never the classifier's estimate.
    pub reclaimed_bytes: u64,
    /// Trimmed `git gc` stdout+stderr (for the human report / JSON).
    pub git_output: String,
}

/// Find the nearest ancestor of `start` (inclusive) that is a git repo, returning
/// the repo's WORK-TREE root (the dir containing `.git`) — or the repo path itself
/// for a bare repo. Pure filesystem checks, no `git` invocation, no recursion into
/// children. Returns `None` if no ancestor is a repo.
///
/// `start` is typically a `.git/objects/pack` dir, so the repo is usually two
/// levels up; but we walk all the way to the filesystem root to be safe.
pub fn find_enclosing_repo(start: &Path) -> Option<PathBuf> {
    for ancestor in start.ancestors() {
        // Work-tree repo: `<ancestor>/.git` is a directory (or a gitdir-link file).
        let dot_git = ancestor.join(".git");
        if dot_git.is_dir() || dot_git.is_file() {
            return Some(ancestor.to_path_buf());
        }
        // Bare repo: the dir itself looks like a git dir (has HEAD + objects).
        if is_bare_repo(ancestor) {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

/// A bare repo has no `.git` subdir but IS one: a `HEAD` file and an `objects` dir
/// directly inside. We only treat a dir as bare when BOTH are present, to avoid
/// false positives on a plain `objects/` directory.
fn is_bare_repo(dir: &Path) -> bool {
    dir.join("HEAD").is_file() && dir.join("objects").is_dir()
}

/// The `.git` directory for a located repo: `<repo>/.git` for a work-tree repo, or
/// the repo path itself for a bare repo. This is what we size before/after.
fn git_dir(repo: &Path) -> PathBuf {
    let dot_git = repo.join(".git");
    if dot_git.is_dir() {
        dot_git
    } else {
        // Bare repo (or a `.git` gitdir-link file we can't cheaply follow): size the
        // repo dir itself. For a bare repo this IS the object store.
        repo.to_path_buf()
    }
}

/// The in-progress git operations whose marker files (under `.git`) mean `gc` is
/// UNSAFE. Each tuple is `(marker relative to .git, human name)`. Checked purely by
/// file existence — no `git status` parse needed for the refusal itself.
const IN_PROGRESS_MARKERS: &[(&str, &str)] = &[
    ("rebase-merge", "rebase"),
    ("rebase-apply", "rebase/am"),
    ("MERGE_HEAD", "merge"),
    ("CHERRY_PICK_HEAD", "cherry-pick"),
    ("REVERT_HEAD", "revert"),
    ("BISECT_LOG", "bisect"),
];

/// Is a rebase / merge / cherry-pick / revert / bisect in progress in `repo`?
/// Returns `Some(op_name)` for the FIRST marker found, else `None`. Pure file
/// existence checks under the repo's git dir.
pub fn operation_in_progress(repo: &Path) -> Option<String> {
    let gdir = repo.join(".git");
    // Work-tree repo markers live under `.git`; a bare repo keeps them at its root.
    let base = if gdir.is_dir() {
        gdir
    } else {
        repo.to_path_buf()
    };
    for (marker, name) in IN_PROGRESS_MARKERS {
        if base.join(marker).exists() {
            return Some((*name).to_string());
        }
    }
    None
}

/// Decide whether a repack MAY run for the pack at `pack_path`, WITHOUT running it.
/// Returns the located repo on success, or a [`RepackRefusal`] explaining why not.
/// Pure (no `git gc`) — the command layer calls this to print the plan, and
/// [`run_repack`] calls it again as its own pre-flight so the gate can't be skipped.
pub fn preflight(pack_path: &Path) -> std::result::Result<PathBuf, RepackRefusal> {
    let repo = find_enclosing_repo(pack_path).ok_or(RepackRefusal::NotAGitRepo)?;
    if let Some(op) = operation_in_progress(&repo) {
        return Err(RepackRefusal::OperationInProgress(op));
    }
    Ok(repo)
}

/// Run the SAFE `git gc` action for the pack at `pack_path`.
///
/// Re-runs [`preflight`] (so the dirty/non-git gate can NEVER be bypassed), sizes
/// the git dir, runs `git -C <repo> gc`, sizes it again, appends a history receipt
/// with the REAL before/after, and returns the measured [`RepackOutcome`]. The
/// command layer is responsible for confirmation / `--yes` BEFORE calling this.
pub fn run_repack(pack_path: &Path) -> Result<RepackOutcome> {
    let repo = preflight(pack_path).map_err(|r| anyhow!("{r}"))?;
    run_repack_in(&repo)
}

/// Repo-rooted core of [`run_repack`], split out so tests can drive it with a repo
/// they built directly (a throwaway temp git repo) without first synthesizing a
/// `.git/objects/pack` path. Still re-checks the in-progress gate. The receipt
/// lands in the REAL ledger (`~/.diskspace`); tests must use [`run_repack_in_to`]
/// with a tempdir so they never pollute the user's ledger.
pub fn run_repack_in(repo: &Path) -> Result<RepackOutcome> {
    run_repack_in_to(repo, &profile::data_dir())
}

/// Like [`run_repack_in`], but writes the history receipt under `history_base`
/// (the base-dir seam, mirroring `history`'s own pattern) instead of the real
/// `~/.diskspace`. Production passes [`profile::data_dir`]; tests pass a tempdir so
/// the `git-repack` receipt never lands in (or races on) the developer's/CI's real
/// ledger. The git repo it operates on is unaffected by this argument.
pub fn run_repack_in_to(repo: &Path, history_base: &Path) -> Result<RepackOutcome> {
    if let Some(op) = operation_in_progress(repo) {
        return Err(anyhow!("{}", RepackRefusal::OperationInProgress(op)));
    }

    let gdir = git_dir(repo);
    let before = dir_size(&gdir);

    // `git -C <repo> gc` — repacks loose objects and prunes the unreachable ones git
    // already considers safe to drop. ARGV form (never a shell); HOME-scoped repo.
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("gc")
        .output()
        .map_err(|e| anyhow!("{}", RepackRefusal::GitUnavailable(e.to_string())))?;

    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    let combined = combined.trim().to_string();

    if !output.status.success() {
        return Err(anyhow!(
            "git gc failed in {}: {}",
            repo.display(),
            if combined.is_empty() {
                "no output".into()
            } else {
                combined.clone()
            }
        ));
    }

    let after = dir_size(&gdir);
    let reclaimed = before.saturating_sub(after);

    // Receipt: a repack is NOT reversible in the airlock sense (you can't "un-gc"),
    // but it IS loss-free, so we record it as a Reclaim-class action with the real
    // df-free measured savings noted in context. No `undo_cmd` — there is nothing to
    // undo and nothing was deleted that the user would want back.
    let mut ctx_map = serde_json::Map::new();
    ctx_map.insert(
        "action".into(),
        serde_json::Value::String("git-repack".into()),
    );
    ctx_map.insert(
        "git_size_before".into(),
        serde_json::Value::Number(before.into()),
    );
    ctx_map.insert(
        "git_size_after".into(),
        serde_json::Value::Number(after.into()),
    );
    history::append_to_base(
        history_base,
        &HistEntry {
            ts: chrono::Utc::now(),
            command: ActionKind::Reclaim,
            candidate_id: None,
            rule_id: Some("git-repack".into()),
            path: repo.to_path_buf(),
            size_bytes: reclaimed,
            df_before: None,
            df_after: None,
            actually_freed: Some(reclaimed),
            reversible: false,
            undo_cmd: None,
            rule_confidence: None,
            context: ctx_map,
        },
    );

    Ok(RepackOutcome {
        repo: repo.to_path_buf(),
        git_size_before: before,
        git_size_after: after,
        reclaimed_bytes: reclaimed,
        git_output: combined,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::SystemTime;

    /// A throwaway dir under the OS temp dir, cleaned up on drop. NEVER the real
    /// `$HOME`/`~/.diskspace`; the git tests here `git init` a fresh repo inside it.
    struct TempTree {
        root: PathBuf,
    }
    impl TempTree {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "diskspace-repack-{}-{}-{}",
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
    }
    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// `true` when a `git` binary is on PATH. The repack-execution tests SKIP (pass
    /// trivially) when git is missing so CI without git doesn't spuriously fail; the
    /// pure discovery/refusal tests don't need git at all.
    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn git(repo: &Path, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .expect("git invocation")
    }

    /// Build a throwaway git repo with a commit and some loose objects, returning
    /// its work-tree root. Configures a local identity so `commit` works in CI.
    fn init_repo_with_loose_objects(t: &TempTree) -> PathBuf {
        let repo = t.dir("repo");
        assert!(git(&repo, &["init", "-q"]).status.success(), "git init");
        git(&repo, &["config", "user.email", "t@example.com"]);
        git(&repo, &["config", "user.name", "Test"]);
        git(&repo, &["config", "commit.gpgsign", "false"]);

        // Create several commits, each adding a file — this writes loose objects
        // that `git gc` will pack, so `.git` shrinks (or at least repacks cleanly).
        for i in 0..8 {
            let f = repo.join(format!("file{i}.txt"));
            // Distinct, compressible-but-nonzero content per file → distinct blobs.
            fs::write(&f, format!("content number {i}\n").repeat(64)).unwrap();
            git(&repo, &["add", "."]);
            git(&repo, &["commit", "-q", "-m", &format!("commit {i}")]);
        }
        repo
    }

    // ---- repo discovery (pure, no git needed) --------------------------------

    #[test]
    fn finds_repo_from_pack_path() {
        let t = TempTree::new("find");
        // Synthesize a work-tree repo layout: <root>/myrepo/.git/objects/pack
        let pack = t.dir("myrepo/.git/objects/pack");
        fs::write(pack.join("pack-abc.pack"), b"x").unwrap();
        let repo = t.dir("myrepo"); // the dir CONTAINING .git
        let found = find_enclosing_repo(&pack).expect("repo found from pack path");
        assert_eq!(found, repo, "walks up to the dir containing .git");
    }

    #[test]
    fn non_git_dir_has_no_enclosing_repo() {
        let t = TempTree::new("nongit");
        let d = t.dir("just/some/dirs");
        assert!(
            find_enclosing_repo(&d).is_none(),
            "a plain directory tree is not a git repo"
        );
    }

    #[test]
    fn bare_repo_is_discovered() {
        let t = TempTree::new("bare");
        // Bare repo: HEAD + objects directly in the dir, no `.git` subdir.
        let bare = t.dir("thing.git");
        fs::write(bare.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        t.dir("thing.git/objects");
        let inner = t.dir("thing.git/objects/pack");
        let found = find_enclosing_repo(&inner).expect("bare repo discovered");
        assert_eq!(found, bare);
    }

    // ---- in-progress refusal (pure, no git needed) ---------------------------

    #[test]
    fn rebase_in_progress_is_detected() {
        let t = TempTree::new("rebase");
        let repo = t.dir("r");
        t.dir("r/.git");
        // Simulate a rebase-in-progress by writing git's own marker dir.
        t.dir("r/.git/rebase-merge");
        assert_eq!(
            operation_in_progress(&repo).as_deref(),
            Some("rebase"),
            "a rebase-merge marker means an operation is in progress"
        );
    }

    #[test]
    fn merge_in_progress_is_detected() {
        let t = TempTree::new("merge");
        let repo = t.dir("r");
        t.dir("r/.git");
        fs::write(repo.join(".git/MERGE_HEAD"), b"deadbeef\n").unwrap();
        assert_eq!(operation_in_progress(&repo).as_deref(), Some("merge"));
    }

    #[test]
    fn clean_repo_has_no_operation_in_progress() {
        let t = TempTree::new("clean");
        let repo = t.dir("r");
        t.dir("r/.git");
        assert!(operation_in_progress(&repo).is_none());
    }

    // ---- preflight refusals --------------------------------------------------

    #[test]
    fn preflight_refuses_non_git_dir() {
        let t = TempTree::new("pf-nongit");
        let d = t.dir("nope");
        match preflight(&d) {
            Err(RepackRefusal::NotAGitRepo) => {}
            other => panic!("expected NotAGitRepo, got {other:?}"),
        }
    }

    #[test]
    fn preflight_refuses_repo_with_rebase_in_progress() {
        let t = TempTree::new("pf-rebase");
        let pack = t.dir("r/.git/objects/pack");
        t.dir("r/.git/rebase-apply"); // simulate `git am`/rebase in progress
        match preflight(&pack) {
            Err(RepackRefusal::OperationInProgress(op)) => assert_eq!(op, "rebase/am"),
            other => panic!("expected OperationInProgress, got {other:?}"),
        }
    }

    // ---- the actual git gc (throwaway temp repo only) ------------------------

    #[test]
    fn repack_shrinks_or_packs_a_real_temp_repo() {
        if !git_available() {
            eprintln!("(skipping: git not on PATH)");
            return;
        }
        let t = TempTree::new("gc");
        let repo = init_repo_with_loose_objects(&t);

        // Route the history receipt into a TEMPDIR base, not the real `~/.diskspace`.
        // Without this seam every `cargo test` run that has git on PATH would write a
        // real `git-repack` line into the developer's/CI's actual ledger (and race
        // other tests that mutate $HOME). The git repo itself is untouched by this.
        let hist_base = t.dir("hist");

        // Before gc the repo has loose objects; after gc they're packed. We assert
        // gc SUCCEEDS and produces a pack (the honest before/after is reported; the
        // exact byte delta varies, but a pack dir must now exist).
        let out = run_repack_in_to(&repo, &hist_base).expect("gc on a clean temp repo succeeds");
        assert_eq!(out.repo, repo);
        assert!(
            out.git_size_before > 0,
            ".git had measurable size before gc"
        );
        let pack_dir = repo.join(".git/objects/pack");
        let has_pack = fs::read_dir(&pack_dir)
            .map(|rd| {
                rd.flatten()
                    .any(|e| e.path().extension().map(|x| x == "pack").unwrap_or(false))
            })
            .unwrap_or(false);
        assert!(has_pack, "git gc produced a pack file");
        // The reported after-size is the real measured size of the repacked .git.
        assert_eq!(out.git_size_after, dir_size(&repo.join(".git")));

        // The receipt MUST have landed in the tempdir base (proving the seam routed
        // it away from the real `~/.diskspace`). We don't assert on the real ledger
        // — the point is the write went HERE.
        let receipt = hist_base.join("history.jsonl");
        assert!(
            receipt.is_file(),
            "git-repack receipt was written into the tempdir history base, not ~/.diskspace"
        );
        let body = fs::read_to_string(&receipt).unwrap();
        assert!(
            body.contains("git-repack"),
            "the receipt names the git-repack action"
        );
    }

    #[test]
    fn repack_refuses_non_git_dir_at_runtime() {
        let t = TempTree::new("gc-nongit");
        let d = t.dir("plain");
        let err = run_repack(&d).unwrap_err();
        assert!(
            err.to_string().contains("no git repository"),
            "run_repack refuses a non-git dir: {err}"
        );
    }

    #[test]
    fn repack_refuses_repo_with_simulated_rebase() {
        if !git_available() {
            eprintln!("(skipping: git not on PATH)");
            return;
        }
        let t = TempTree::new("gc-rebase");
        let repo = init_repo_with_loose_objects(&t);
        // Simulate a rebase-in-progress AFTER init by dropping git's marker dir.
        fs::create_dir_all(repo.join(".git/rebase-merge")).unwrap();
        let err = run_repack_in(&repo).unwrap_err();
        assert!(
            err.to_string().contains("rebase"),
            "run_repack_in refuses a repo mid-rebase: {err}"
        );
    }
}

//! Signature classifier — the heuristic that labels the opaque "unknown" residual.
//!
//! `hunt` (Pass 2) surfaces the largest TRULY-unruled directories from the scan
//! cache, but they arrive UNLABELED: on a real disk that residual was ~540 GB of
//! git packs, a VM disk image, model checkpoints, RAW audio stems, db backups, and
//! editor state — each wanting a DIFFERENT safe action. A blanket rule can't cover
//! them (the paths are user-specific), so this module reads a directory's STRUCTURE
//! and gives it a [`Signature`] plus the [`Strategy`] (the safe action class) that
//! makes it actionable.
//!
//! DESIGN CONSTRAINT — cheap first, light sample second, NEVER a full walk:
//!   1. Path-name / structure patterns are checked FIRST (string ops, zero I/O):
//!      a `.git/objects/pack` tail, a `models--*/blobs` HuggingFace layout, a
//!      `db_backups` / `Backups` name, an `Application Support/.../globalStorage`
//!      tail, etc. These catch the headline cases for free.
//!   2. Only if the name is inconclusive do we take a LIGHT on-disk sample:
//!      `read_dir` a BOUNDED number of entries (see [`SAMPLE_ENTRY_CAP`]), tally
//!      file extensions, note the newest mtime, and check for a `.git` child. This
//!      is O(entries-in-one-dir), capped — it is NOT recursive and never descends
//!      the whole tree (that is the scanner's job, already done).
//!
//! Every classification is ADVISORY. It never gates the pressure-test, never widens
//! a candidate, and the strategy it recommends is the SAFEST class for the
//! signature (re-packable / reversible / re-downloadable), defaulting to `Review`
//! whenever the evidence is thin.
//!
//! STEP B has now wired the production callers in (the `classify` command, the
//! git-repack safe action, and the hunt-row tag), so the module no longer carries a
//! blanket `dead_code` allow — every item below has a live caller.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::SystemTime;

use crate::profile::Profile;

/// What a directory *is*, inferred from its name/structure and a light on-disk
/// sample. This vocabulary is deliberately small and action-oriented — each
/// variant maps to exactly one [`Strategy`] (the safe action class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Signature {
    /// A git object-pack store (`.git/objects/pack`). Re-packable: `git gc`
    /// typically reclaims a meaningful fraction with ZERO data loss.
    GitPack,
    /// A virtual-machine / container disk image store (OrbStack data, Docker.raw,
    /// a Claude vm_bundle, a `*.vmdk`/`*.qcow2`). Reclaimable when the VM is unused.
    VmDisk,
    /// A re-downloadable model checkpoint / weights blob store (HuggingFace
    /// `models--*/blobs`, `*.safetensors`, `*.gguf`, `*.ckpt`).
    ModelCheckpoint,
    /// A backup directory (`db_backups`, `Backups`, `*.bak`, dated archive dumps).
    Backup,
    /// Raw, un-rendered media masters (RAW audio stems, `*.wav`/`*.aiff` masters,
    /// camera RAW `*.cr2`/`*.arw`, `*_RAW` suffix dirs). Offloadable cold storage.
    MediaRaw,
    /// Application state / session store (`Application Support/.../globalStorage`,
    /// a `state.vscdb`, an editor's workspace state). Reviewable — losing it resets
    /// app state, so never a blind reclaim.
    AppState,
    /// A generic large dataset (a directory dominated by data files — `*.parquet`,
    /// `*.csv`, `*.jsonl`, `*.npz`) with no more specific signature.
    Dataset,
    /// A large directory whose newest mtime is older than [`INACTIVE_AFTER_DAYS`]:
    /// cold by age regardless of content type. Offloadable.
    Inactive,
    /// None of the above matched with enough confidence. Always routes to `Review`.
    Unknown,
}

impl Signature {
    /// Lowercase, kebab-case label (matches the serde wire form). Stable token for
    /// the hunt tag, the `classify` table, and JSON consumers.
    pub fn label(&self) -> &'static str {
        match self {
            Signature::GitPack => "git-pack",
            Signature::VmDisk => "vm-disk",
            Signature::ModelCheckpoint => "model-checkpoint",
            Signature::Backup => "backup",
            Signature::MediaRaw => "media-raw",
            Signature::AppState => "app-state",
            Signature::Dataset => "dataset",
            Signature::Inactive => "inactive",
            Signature::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// The SAFE ACTION class a signature maps to. This is the action vocabulary the
/// `classify` command executes (with confirmation / `--yes`) and that the hunt tag
/// advertises. Every strategy is the SAFEST recovery class for its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Strategy {
    /// Re-pack in place (`git gc` / `git repack`). Reclaims bytes with no data
    /// loss — git regenerates the packed objects. SAFE, but only on a clean repo.
    Repack,
    /// Hand to the existing reversible airlock (reclaim-if-unused). The hard
    /// pressure-test still gates it; nothing here bypasses that.
    Reclaim,
    /// Move to cold/cloud storage (the forthcoming `stow`). Re-downloadable or
    /// archival data that need not live on the fast disk.
    Offload,
    /// Inspect before acting — the signature is reviewable (app state, backups you
    /// may still need) or the evidence is thin. NEVER a blind delete.
    Review,
    /// Leave it. Reserved for paths the profile marks never-touch.
    Keep,
}

impl Strategy {
    /// Lowercase label (matches the serde wire form).
    pub fn label(&self) -> &'static str {
        match self {
            Strategy::Repack => "repack",
            Strategy::Reclaim => "reclaim",
            Strategy::Offload => "offload",
            Strategy::Review => "review",
            Strategy::Keep => "keep",
        }
    }
}

/// The exact next command a user (or agent) should run to act on `path` given its
/// strategy. Shared by the `hunt` row hint and the `classify` output so both name
/// the SAME recommended action. Honest about the not-yet-shipped `stow`: an
/// Offload says "recommended" (a suggestion), never "offloaded".
pub fn action_hint(strategy: Strategy, path: &Path) -> String {
    let p = path.display();
    match strategy {
        Strategy::Repack => format!("diskspace classify {p} --yes  (runs git gc)"),
        Strategy::Reclaim => format!("diskspace classify {p} --yes  (reversible airlock)"),
        // `stow` lands in the NEXT pass — recommend it, do NOT claim to offload.
        Strategy::Offload => format!("recommended: diskspace stow {p}"),
        Strategy::Review => format!("inspect first: du -sh {p}/*"),
        Strategy::Keep => "profile marks this never-touch — left as is".to_string(),
    }
}

impl std::fmt::Display for Strategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// The result of classifying one directory. Advisory throughout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classification {
    pub signature: Signature,
    pub strategy: Strategy,
    /// Rough bytes a successful action would reclaim, when we can estimate it.
    /// `None` when the saving depends on user choice (`Review`) or is unknowable
    /// up front. NEVER a promise — `classify` reports real before/after when it
    /// actually acts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub est_savings_bytes: Option<u64>,
    /// One-line, user-facing explanation of WHY this signature/strategy was chosen.
    pub reasoning: String,
}

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Cap on `read_dir` entries the light sample inspects. Keeps the sample O(1) on a
/// directory with millions of children (a blob store, a node_modules) — we only
/// need a representative taste of extensions and the newest mtime, not every file.
const SAMPLE_ENTRY_CAP: usize = 256;

/// A directory whose newest sampled mtime is older than this is "cold by age" and
/// classified [`Signature::Inactive`] when nothing more specific matched. ~12
/// months: a year untouched is a strong offload signal.
const INACTIVE_AFTER_DAYS: u64 = 365;

/// Fraction of a GitPack's size `git gc` typically reclaims. Conservative midpoint
/// of the observed ~30–60% range; the real figure is reported after the repack.
const GITPACK_RECLAIM_FRACTION: f64 = 0.4;

/// A signature is "media-raw"/"dataset"/"model" by extension dominance only when a
/// clear majority of sampled files share the signature's extension family. Avoids
/// labeling a mixed directory off a single stray `.wav`.
const EXT_DOMINANCE: f64 = 0.5;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Classify a single directory. CHEAP path/name/structure checks run first (zero
/// I/O); only if they're inconclusive do we take a LIGHT, bounded on-disk sample.
/// Never a recursive walk.
///
/// The returned [`Classification`] is advisory: it labels the directory and names
/// the SAFEST action class for it, but it neither acts nor gates anything.
pub fn classify_dir(path: &Path, profile: &Profile) -> Classification {
    let size = dir_size_on_disk(path);
    classify_with_size(path, size, profile)
}

/// Classify with a caller-supplied size (so `hunt` can reuse the unruled-byte
/// total it already computed instead of re-summing the directory). Same logic as
/// [`classify_dir`]; that function is just this with an on-the-spot size.
pub fn classify_with_size(path: &Path, size: u64, profile: &Profile) -> Classification {
    // Profile veto FIRST: a never-touch path is `Keep`, full stop — we don't even
    // sample it. (always_safe / never_suggest don't change the *signature*, only
    // downstream action policy, so they're not consulted here.)
    if profile_never_touch(path, profile) {
        return Classification {
            signature: Signature::Unknown,
            strategy: Strategy::Keep,
            est_savings_bytes: None,
            reasoning: "profile marks this path never-touch — left untouched".into(),
        };
    }

    // --- Cheap, zero-I/O path/name/structure heuristics. ------------------
    if let Some(c) = classify_by_path(path, size) {
        return c;
    }

    // --- Light bounded on-disk sample (only when the name didn't decide). --
    classify_by_sample(path, size)
}

// ---------------------------------------------------------------------------
// Step 1: cheap path/name/structure heuristics (no I/O)
// ---------------------------------------------------------------------------

/// Pure string/structure classification from the path alone — no filesystem reads.
/// Returns `Some` when the name is conclusive, `None` to fall through to sampling.
fn classify_by_path(path: &Path, size: u64) -> Option<Classification> {
    let lower = path.to_string_lossy().to_lowercase();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    // GitPack: the canonical `.git/objects/pack` tail (or a bare `objects/pack`
    // under a git dir). The single highest-value signature on the test disk.
    if lower.ends_with(".git/objects/pack")
        || lower.contains(".git/objects/pack/")
        || (name == "pack" && lower.contains("/objects/pack"))
    {
        return Some(Classification {
            signature: Signature::GitPack,
            strategy: Strategy::Repack,
            est_savings_bytes: gitpack_savings(size),
            reasoning:
                "git object-pack store (.git/objects/pack) — `git gc` re-packs it with no data loss"
                    .into(),
        });
    }

    // VmDisk: OrbStack / Docker / Claude vm_bundles, or a virtual-disk image dir.
    if lower.contains("orbstack")
        || lower.contains("vm_bundles")
        || lower.contains("docker.raw")
        || lower.contains("com.docker.docker")
        || lower.contains(".vmwarevm")
        || lower.contains("/virtualbox vms")
        || name.ends_with(".vmdk")
        || name.ends_with(".qcow2")
        || name.ends_with(".vdi")
    {
        return Some(Classification {
            signature: Signature::VmDisk,
            strategy: Strategy::Reclaim,
            // Reclaim hands to the reversible airlock; the gate decides real bytes.
            est_savings_bytes: Some(size),
            reasoning:
                "virtual-machine / container disk image — reclaimable via the reversible airlock if the VM is unused"
                    .into(),
        });
    }

    // ModelCheckpoint — RE-DOWNLOADABLE only. We Offload (and claim full savings)
    // ONLY on a HuggingFace-cache STRUCTURAL signal: a `models--*/blobs` (or
    // `/snapshots`) layout, or a `huggingface/hub` ancestor. Those blobs are
    // re-fetchable from the hub by definition.
    //
    // A bare directory merely NAMED `checkpoints` is deliberately NOT matched here:
    // it is the canonical OUTPUT location for LOCALLY-TRAINED models (PyTorch
    // Lightning, the Keras `ModelCheckpoint` callback, nnU-Net, Ultralytics, RL
    // runs) and is frequently the ONLY copy — not re-downloadable. Calling it
    // Offload with `est_savings = full size` would label precious, irreproducible
    // user data as reclaimable. So a bare `checkpoints/` falls through to sampling:
    // it becomes ModelCheckpoint/Offload ONLY if model-weight extensions
    // (safetensors/gguf/ckpt/pt/…) actually dominate its contents; otherwise it
    // lands on Inactive/Unknown → Review.
    if (lower.contains("models--") && (lower.contains("/blobs") || lower.contains("/snapshots")))
        || lower.contains("huggingface/hub")
    {
        return Some(Classification {
            signature: Signature::ModelCheckpoint,
            strategy: Strategy::Offload,
            est_savings_bytes: Some(size),
            reasoning:
                "HuggingFace model-cache blob store (models--*/blobs) — re-downloadable from the hub, so it can be offloaded to cold storage"
                    .into(),
        });
    }

    // Backup: a backup-named directory or dated db dump store.
    if name == "db_backups"
        || name == "backups"
        || name == "backup"
        || lower.contains("/backups/")
        || lower.contains("db_backups")
        || name.ends_with("_backups")
        || name.ends_with("-backups")
    {
        return Some(Classification {
            signature: Signature::Backup,
            strategy: Strategy::Review,
            est_savings_bytes: None, // Review first — you may still need the backup.
            reasoning:
                "backup directory — review what you still need, then offload the rest to cold storage"
                    .into(),
        });
    }

    // MediaRaw by name: a `*_RAW` / `*-raw` suffix dir is a strong masters signal
    // without sampling.
    if name.ends_with("_raw") || name.ends_with("-raw") || name.ends_with(" raw") {
        return Some(Classification {
            signature: Signature::MediaRaw,
            strategy: Strategy::Offload,
            est_savings_bytes: Some(size),
            reasoning: "raw media masters (name ends with _RAW) — offloadable to cold storage"
                .into(),
        });
    }

    // AppState: `Application Support/.../globalStorage` (VS Code / Cursor family),
    // or an explicit `globalStorage` dir. The `state.vscdb` confirm is in sampling.
    if (lower.contains("application support") && lower.contains("globalstorage"))
        || name == "globalstorage"
    {
        return Some(Classification {
            signature: Signature::AppState,
            strategy: Strategy::Review,
            est_savings_bytes: None, // Losing app state resets the app — review.
            reasoning:
                "application state store (globalStorage) — review before acting; deleting it resets app state"
                    .into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// Step 2: light bounded on-disk sample
// ---------------------------------------------------------------------------

/// What the bounded `read_dir` sample observed. All fields come from at most
/// [`SAMPLE_ENTRY_CAP`] direct children — no recursion.
#[derive(Debug, Default)]
struct Sample {
    /// Lowercase extension -> count, over the sampled FILES.
    ext_counts: HashMap<String, usize>,
    /// Total sampled files (denominator for dominance).
    file_count: usize,
    /// `true` if a `.git` child was seen (the dir itself is a git work-tree root).
    has_git: bool,
    /// `true` if a `state.vscdb` (or `*.vscdb`) child was seen — VS Code/Cursor state.
    has_vscdb: bool,
    /// Newest child mtime observed, for the inactivity check.
    newest_mtime: Option<SystemTime>,
}

impl Sample {
    /// The fraction of sampled files whose extension is in `exts`.
    fn ext_fraction(&self, exts: &[&str]) -> f64 {
        if self.file_count == 0 {
            return 0.0;
        }
        let hits: usize = exts
            .iter()
            .map(|e| self.ext_counts.get(*e).copied().unwrap_or(0))
            .sum();
        hits as f64 / self.file_count as f64
    }
}

/// Read AT MOST [`SAMPLE_ENTRY_CAP`] direct children of `dir`, tallying extensions,
/// the `.git` / `*.vscdb` markers, and the newest mtime. Bounded and non-recursive.
fn sample_dir(dir: &Path) -> Sample {
    let mut s = Sample::default();
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return s,
    };
    for entry in read.flatten().take(SAMPLE_ENTRY_CAP) {
        let name = entry.file_name();
        let name_lossy = name.to_string_lossy();
        let name_lower = name_lossy.to_lowercase();
        // `file_type()` is a cheap dirent read on most platforms (no extra stat).
        let ft = entry.file_type().ok();

        if name_lower == ".git" {
            s.has_git = true;
        }
        if name_lower == "state.vscdb" || name_lower.ends_with(".vscdb") {
            s.has_vscdb = true;
        }

        let is_file = ft.map(|t| t.is_file()).unwrap_or(false);
        if is_file {
            s.file_count += 1;
            // Take the extension off the raw `OsStr` file name (no Cow→Path bound
            // issues), lowercased.
            if let Some(ext) = Path::new(&name)
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
            {
                *s.ext_counts.entry(ext).or_insert(0) += 1;
            }
        }

        // Newest mtime across whatever we sampled — one `metadata()` per sampled
        // entry, still bounded by the cap.
        if let Ok(md) = entry.metadata() {
            if let Ok(m) = md.modified() {
                s.newest_mtime = Some(match s.newest_mtime {
                    Some(cur) if cur >= m => cur,
                    _ => m,
                });
            }
        }
    }
    s
}

/// Classify from the bounded sample (the path name was inconclusive). Order
/// matters: the most specific extension families first, then the age fallback,
/// then `Unknown`.
fn classify_by_sample(path: &Path, size: u64) -> Classification {
    let s = sample_dir(path);

    // A `state.vscdb` child confirms AppState even when the path name didn't
    // (e.g. a renamed editor profile dir).
    if s.has_vscdb {
        return Classification {
            signature: Signature::AppState,
            strategy: Strategy::Review,
            est_savings_bytes: None,
            reasoning:
                "application state store (contains a *.vscdb) — review before acting; deleting it resets app state"
                    .into(),
        };
    }

    // Model weights by extension dominance.
    if s.ext_fraction(&["safetensors", "gguf", "ckpt", "pt", "bin", "onnx"]) >= EXT_DOMINANCE
        && s.file_count > 0
    {
        return Classification {
            signature: Signature::ModelCheckpoint,
            strategy: Strategy::Offload,
            est_savings_bytes: Some(size),
            reasoning:
                "directory dominated by model-weight files (safetensors/gguf/ckpt) — re-downloadable, offloadable"
                    .into(),
        };
    }

    // Raw media masters by extension dominance.
    if s.ext_fraction(&[
        "wav", "aif", "aiff", "flac", "cr2", "arw", "nef", "dng", "raw",
    ]) >= EXT_DOMINANCE
        && s.file_count > 0
    {
        return Classification {
            signature: Signature::MediaRaw,
            strategy: Strategy::Offload,
            est_savings_bytes: Some(size),
            reasoning:
                "directory dominated by raw media masters (wav/aiff/camera-raw) — offloadable to cold storage"
                    .into(),
        };
    }

    // Backup by extension dominance (`*.bak` / `*.dump` / `*.sql` archives).
    if s.ext_fraction(&["bak", "dump", "sql", "tar", "tgz", "gz", "zip"]) >= EXT_DOMINANCE
        && s.file_count > 0
    {
        return Classification {
            signature: Signature::Backup,
            strategy: Strategy::Review,
            est_savings_bytes: None,
            reasoning:
                "directory dominated by archive/backup files (bak/dump/sql/tar) — review, then offload"
                    .into(),
        };
    }

    // Generic dataset by extension dominance.
    if s.ext_fraction(&["parquet", "csv", "jsonl", "npz", "npy", "tfrecord", "arrow"])
        >= EXT_DOMINANCE
        && s.file_count > 0
    {
        return Classification {
            signature: Signature::Dataset,
            strategy: Strategy::Offload,
            est_savings_bytes: Some(size),
            reasoning:
                "directory dominated by dataset files (parquet/csv/jsonl/npz) — offloadable cold data"
                    .into(),
        };
    }

    // Cold-by-age fallback: nothing specific matched, but the newest thing we
    // sampled is older than a year → Inactive (offloadable).
    if is_inactive(&s) {
        return Classification {
            signature: Signature::Inactive,
            strategy: Strategy::Offload,
            est_savings_bytes: Some(size),
            reasoning: format!(
                "large directory untouched for over {} months — cold, offloadable",
                INACTIVE_AFTER_DAYS / 30
            ),
        };
    }

    // Nothing matched: Unknown → always Review (never a blind action).
    Classification {
        signature: Signature::Unknown,
        strategy: Strategy::Review,
        est_savings_bytes: None,
        reasoning: "no signature matched — inspect this directory before acting".into(),
    }
}

/// `true` when the newest sampled mtime is older than [`INACTIVE_AFTER_DAYS`].
/// No sampled mtime (empty/unreadable) is NOT treated as inactive — we can't claim
/// coldness we didn't observe.
fn is_inactive(s: &Sample) -> bool {
    let Some(newest) = s.newest_mtime else {
        return false;
    };
    match SystemTime::now().duration_since(newest) {
        Ok(age) => age.as_secs() > INACTIVE_AFTER_DAYS * 24 * 60 * 60,
        Err(_) => false, // mtime in the future — not inactive.
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Estimated `git gc` reclaim for a pack of `size` bytes: a conservative fraction
/// of the pack size. `None` for a zero-size dir (nothing to reclaim).
fn gitpack_savings(size: u64) -> Option<u64> {
    if size == 0 {
        return None;
    }
    Some((size as f64 * GITPACK_RECLAIM_FRACTION) as u64)
}

/// Does the profile mark `path` (or an ancestor) never-touch? Mirrors the glob /
/// prefix semantics the rest of the tool uses for `never_touch`.
fn profile_never_touch(path: &Path, profile: &Profile) -> bool {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let path_str = path.to_string_lossy();
    profile.paths.never_touch.iter().any(|raw| {
        let expanded = if let Some(rest) = raw.strip_prefix("~/") {
            format!("{}/{}", home, rest)
        } else {
            raw.clone()
        };
        // Glob match OR plain prefix (so `~/Important` shields `~/Important/sub`).
        if let Ok(pat) = glob::Pattern::new(&expanded) {
            if pat.matches_path(path) {
                return true;
            }
        }
        path_str.starts_with(&expanded)
    })
}

/// Directory on-disk byte total (own files plus descendants). Reuses the airlock
/// store's recursive `dir_size`. Only called by [`classify_dir`]; the hunt path
/// supplies its already-computed size via [`classify_with_size`], so this is NOT
/// on the hot path.
fn dir_size_on_disk(path: &Path) -> u64 {
    crate::core::airlock_store::dir_size(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    /// A throwaway dir under the OS temp dir, cleaned up on drop. Synthetic trees
    /// only — these tests NEVER touch the real `$HOME`/`~/.diskspace` and never run
    /// any git command.
    struct TempTree {
        root: PathBuf,
    }
    impl TempTree {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "diskspace-classify-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }
        /// Make `rel` (a sub-path) as a directory and return it.
        fn dir(&self, rel: &str) -> PathBuf {
            let p = self.root.join(rel);
            fs::create_dir_all(&p).unwrap();
            p
        }
        /// Write `n` bytes to `dir/name`.
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

    fn prof() -> Profile {
        Profile::default()
    }

    // ---- Path/name heuristics (zero-I/O) -------------------------------------

    #[test]
    fn gitpack_by_path_is_repack() {
        let t = TempTree::new("gitpack");
        let pack = t.dir("Clef/.git/objects/pack");
        t.file(&pack, "pack-abc.pack", 64 * 1024);
        let c = classify_dir(&pack, &prof());
        assert_eq!(c.signature, Signature::GitPack);
        assert_eq!(c.strategy, Strategy::Repack);
        // ~0.4 * size estimated savings.
        assert!(
            c.est_savings_bytes.unwrap() > 0,
            "gitpack has an estimated saving"
        );
    }

    #[test]
    fn vmdisk_by_orbstack_path_is_reclaim() {
        let t = TempTree::new("vmdisk");
        // Mirror the real OrbStack group-container layout.
        let data = t.dir("Group Containers/HUAQ24HBR6.dev.orbstack/data");
        t.file(&data, "disk.img", 32 * 1024);
        let c = classify_dir(&data, &prof());
        assert_eq!(c.signature, Signature::VmDisk);
        assert_eq!(c.strategy, Strategy::Reclaim);
    }

    #[test]
    fn vm_bundles_path_is_vmdisk() {
        let t = TempTree::new("vmbundle");
        let b = t.dir("Application Support/Claude/vm_bundles");
        t.file(&b, "bundle.bin", 8 * 1024);
        let c = classify_dir(&b, &prof());
        assert_eq!(c.signature, Signature::VmDisk);
        assert_eq!(c.strategy, Strategy::Reclaim);
    }

    #[test]
    fn model_blobs_by_path_is_offload() {
        let t = TempTree::new("model");
        let blobs = t.dir("checkpoints/models--ACE-Step--whatever/blobs");
        t.file(&blobs, "0a1b2c3d", 16 * 1024); // HF blobs are extension-less hashes
        let c = classify_dir(&blobs, &prof());
        assert_eq!(c.signature, Signature::ModelCheckpoint);
        assert_eq!(c.strategy, Strategy::Offload);
        assert_eq!(c.est_savings_bytes, Some(dir_size_on_disk(&blobs)));
    }

    #[test]
    fn bare_checkpoints_dir_of_unique_output_is_not_offloaded() {
        // A dir literally named `checkpoints` full of LOCALLY-TRAINED output that is
        // NOT re-downloadable (no model-weight extensions, recent mtime) must NOT be
        // labeled ModelCheckpoint/Offload with a full-size savings claim. It falls
        // through to sampling → Unknown/Review (the safe default).
        let t = TempTree::new("bare-ckpt");
        let d = t.dir("training_run_42/checkpoints");
        // Unique training artifacts, not re-downloadable weights, no dominant family.
        t.file(&d, "metrics.json", 2 * 1024);
        t.file(&d, "events.log", 2 * 1024);
        t.file(&d, "config.yaml", 2 * 1024);
        let c = classify_dir(&d, &prof());
        assert_ne!(
            c.signature,
            Signature::ModelCheckpoint,
            "a bare `checkpoints` dir of unique training output is NOT a re-downloadable model store"
        );
        assert_ne!(
            c.strategy,
            Strategy::Offload,
            "must not advertise offload (stow) for the only copy of training output"
        );
        assert_eq!(
            c.strategy,
            Strategy::Review,
            "thin-evidence checkpoints dir routes to Review"
        );
        assert_eq!(
            c.est_savings_bytes, None,
            "no confident savings claim on irreproducible user data"
        );
    }

    #[test]
    fn bare_checkpoints_dir_full_of_ckpt_weights_still_offloads_via_sample() {
        // The complement: a bare `checkpoints` dir that REALLY is dominated by
        // model-weight files still classifies ModelCheckpoint/Offload — now via the
        // sampling path (extension dominance), not a blind name match.
        let t = TempTree::new("ckpt-weights");
        let d = t.dir("runs/checkpoints");
        for i in 0..5 {
            t.file(&d, &format!("epoch{i}.ckpt"), 16 * 1024);
        }
        let c = classify_dir(&d, &prof());
        assert_eq!(c.signature, Signature::ModelCheckpoint);
        assert_eq!(c.strategy, Strategy::Offload);
    }

    #[test]
    fn db_backups_name_is_backup_review() {
        let t = TempTree::new("backup");
        let d = t.dir("cursor_bmidotcom/db_backups");
        t.file(&d, "2026-05-01.dump", 12 * 1024);
        let c = classify_dir(&d, &prof());
        assert_eq!(c.signature, Signature::Backup);
        assert_eq!(c.strategy, Strategy::Review);
        // Backups are Review-first: no blind savings promise.
        assert_eq!(c.est_savings_bytes, None);
    }

    #[test]
    fn raw_suffix_dir_is_mediaraw_offload() {
        let t = TempTree::new("rawname");
        // The real disk had `Sweat_Elegy_RAW`, `Sweat_AlmostAlways_RAW`.
        let d = t.dir("Sweat_Elegy_RAW");
        t.file(&d, "stem01.bin", 24 * 1024);
        let c = classify_dir(&d, &prof());
        assert_eq!(c.signature, Signature::MediaRaw);
        assert_eq!(c.strategy, Strategy::Offload);
    }

    #[test]
    fn cursor_global_storage_path_is_appstate_review() {
        let t = TempTree::new("appstate");
        let d = t.dir("Application Support/Cursor/User/globalStorage");
        t.file(&d, "state.vscdb", 10 * 1024);
        let c = classify_dir(&d, &prof());
        assert_eq!(c.signature, Signature::AppState);
        assert_eq!(c.strategy, Strategy::Review);
        assert_eq!(c.est_savings_bytes, None);
    }

    // ---- Light on-disk sample (name inconclusive) ---------------------------

    #[test]
    fn wav_dominated_dir_samples_to_mediaraw() {
        let t = TempTree::new("wavs");
        // A neutrally-named dir full of .wav — only the sample reveals it.
        let d = t.dir("session_masters");
        for i in 0..6 {
            t.file(&d, &format!("take{i}.wav"), 8 * 1024);
        }
        let c = classify_dir(&d, &prof());
        assert_eq!(
            c.signature,
            Signature::MediaRaw,
            "a wav-dominated dir samples to MediaRaw"
        );
        assert_eq!(c.strategy, Strategy::Offload);
    }

    #[test]
    fn safetensors_dominated_dir_samples_to_model() {
        let t = TempTree::new("weights");
        let d = t.dir("downloads/some_weights");
        for i in 0..4 {
            t.file(&d, &format!("model-{i}.safetensors"), 16 * 1024);
        }
        let c = classify_dir(&d, &prof());
        assert_eq!(c.signature, Signature::ModelCheckpoint);
        assert_eq!(c.strategy, Strategy::Offload);
    }

    #[test]
    fn parquet_dominated_dir_samples_to_dataset() {
        let t = TempTree::new("dataset");
        let d = t.dir("warehouse/exports");
        for i in 0..5 {
            t.file(&d, &format!("part-{i}.parquet"), 12 * 1024);
        }
        let c = classify_dir(&d, &prof());
        assert_eq!(c.signature, Signature::Dataset);
        assert_eq!(c.strategy, Strategy::Offload);
    }

    #[test]
    fn vscdb_child_confirms_appstate_when_name_neutral() {
        let t = TempTree::new("vscdb");
        // Neutral dir name; only the *.vscdb child reveals it's app state.
        let d = t.dir("profileXYZ");
        t.file(&d, "state.vscdb", 10 * 1024);
        let c = classify_dir(&d, &prof());
        assert_eq!(c.signature, Signature::AppState);
        assert_eq!(c.strategy, Strategy::Review);
    }

    #[test]
    fn old_mtime_dir_samples_to_inactive() {
        let t = TempTree::new("inactive");
        let d = t.dir("old_project_misc");
        // Mixed, non-dominant content so no extension family wins.
        t.file(&d, "readme.txt", 2 * 1024);
        t.file(&d, "notes.md", 2 * 1024);
        t.file(&d, "image.png", 2 * 1024);

        // Backdate every child's mtime to ~2 years ago via filetime-free utimes.
        let two_years_ago = SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(730 * 24 * 60 * 60))
            .unwrap();
        for name in ["readme.txt", "notes.md", "image.png"] {
            set_mtime(&d.join(name), two_years_ago);
        }

        let c = classify_dir(&d, &prof());
        assert_eq!(
            c.signature,
            Signature::Inactive,
            "an old, mixed-content dir samples to Inactive"
        );
        assert_eq!(c.strategy, Strategy::Offload);
    }

    #[test]
    fn recent_mixed_dir_is_unknown_review() {
        let t = TempTree::new("unknown");
        let d = t.dir("freshly_made_misc");
        // Recent (default mtime = now), mixed content, no dominant family.
        t.file(&d, "a.txt", 1024);
        t.file(&d, "b.md", 1024);
        t.file(&d, "c.png", 1024);
        let c = classify_dir(&d, &prof());
        assert_eq!(c.signature, Signature::Unknown);
        assert_eq!(
            c.strategy,
            Strategy::Review,
            "Unknown always routes to Review (never a blind action)"
        );
        assert_eq!(c.est_savings_bytes, None);
    }

    // ---- Profile veto --------------------------------------------------------

    #[test]
    fn never_touch_path_is_keep() {
        let t = TempTree::new("keep");
        let pack = t.dir("Clef/.git/objects/pack");
        t.file(&pack, "pack-abc.pack", 64 * 1024);

        let mut p = prof();
        // Never-touch the whole Clef tree via an absolute prefix.
        p.paths
            .never_touch
            .push(t.root.join("Clef").to_string_lossy().into_owned());

        let c = classify_dir(&pack, &p);
        assert_eq!(
            c.strategy,
            Strategy::Keep,
            "a never-touch path is Keep even though it's a GitPack"
        );
    }

    // ---- Estimated savings shape --------------------------------------------

    #[test]
    fn gitpack_savings_is_fraction_of_size() {
        // 100 MB pack → ~40 MB estimated (0.4 fraction).
        let est = gitpack_savings(100 * 1024 * 1024).unwrap();
        let want = (100.0 * 1024.0 * 1024.0 * GITPACK_RECLAIM_FRACTION) as u64;
        assert_eq!(est, want);
        // Zero-size pack → no estimate.
        assert_eq!(gitpack_savings(0), None);
    }

    // ---- Serde shape (advisory JSON fields) ---------------------------------

    #[test]
    fn classification_roundtrips_through_json() {
        let c = Classification {
            signature: Signature::GitPack,
            strategy: Strategy::Repack,
            est_savings_bytes: Some(1234),
            reasoning: "test".into(),
        };
        let json = serde_json::to_string(&c).unwrap();
        // Wire form uses the kebab-case labels.
        assert!(json.contains("\"git-pack\""));
        assert!(json.contains("\"repack\""));
        let back: Classification = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signature, Signature::GitPack);
        assert_eq!(back.strategy, Strategy::Repack);
        assert_eq!(back.est_savings_bytes, Some(1234));
    }

    #[test]
    fn est_savings_skipped_when_none() {
        let c = Classification {
            signature: Signature::Unknown,
            strategy: Strategy::Review,
            est_savings_bytes: None,
            reasoning: "x".into(),
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(
            !v.as_object().unwrap().contains_key("est_savings_bytes"),
            "None est_savings is skipped, not serialized as null"
        );
    }

    // -- platform mtime setter (unix) -----------------------------------------

    /// Set a path's mtime via `utimensat` so the inactivity test can backdate a
    /// file without pulling in the `filetime` crate. Unix-only; the inactivity
    /// test is itself unix-gated by relying on this.
    #[cfg(unix)]
    fn set_mtime(path: &Path, when: SystemTime) {
        use std::os::unix::ffi::OsStrExt;
        let secs = when
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as libc_time_t)
            .unwrap_or(0);
        let times = [
            Timeval {
                tv_sec: secs,
                tv_usec: 0,
            },
            Timeval {
                tv_sec: secs,
                tv_usec: 0,
            },
        ];
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: cpath is a valid NUL-terminated path; times is a 2-element array
        // of valid timevals. `utimes` writes nothing back through these pointers.
        unsafe {
            utimes(cpath.as_ptr(), times.as_ptr());
        }
    }

    #[cfg(not(unix))]
    fn set_mtime(_path: &Path, _when: SystemTime) {
        // No-op on non-unix; the inactivity test is unix-gated below.
    }

    // Minimal libc shims so the test doesn't add a dependency. `utimes(2)` is in
    // libSystem/libc and stable across macOS + Linux.
    #[cfg(unix)]
    #[allow(non_camel_case_types)]
    type libc_time_t = i64;

    #[cfg(unix)]
    #[repr(C)]
    struct Timeval {
        tv_sec: libc_time_t,
        tv_usec: i64,
    }

    #[cfg(unix)]
    extern "C" {
        fn utimes(path: *const std::os::raw::c_char, times: *const Timeval) -> std::os::raw::c_int;
    }
}

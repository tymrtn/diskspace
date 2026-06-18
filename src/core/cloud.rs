//! Cloud-provider detection + offload-mechanism selection for the `stow` command.
//!
//! `stow` frees LOCAL disk by moving a file's bytes to the cloud while keeping the
//! data fully recoverable — OFFLOAD, never DELETE. But HOW you offload, and whether
//! it can even be SCRIPTED safely, depends entirely on which cloud client owns the
//! path. This module is the detection + policy layer that answers two questions for
//! a path:
//!
//!   1. WHICH provider owns it? ([`detect_provider`])
//!   2. Given that provider (and whether the Maestral CLI is the active Dropbox
//!      client), WHICH offload mechanism is safe to use? ([`offload_mechanism`])
//!
//! The research rules this encodes are DATA-SAFETY-CRITICAL. The two forbidden,
//! data-LOSS operations — deleting a local file inside a classic `~/Dropbox` (the
//! official app propagates the delete to the cloud) and setting the
//! `com.dropbox.ignored` xattr (which REMOVES the file from the cloud and frees no
//! local space) — appear NOWHERE in this crate. Every mechanism below is reversible.
//!
//!   * CLASSIC `~/Dropbox` (an ancestor holds a `.dropbox` marker): there is NO
//!     supported scriptable "make online-only" via the OFFICIAL Dropbox app — its
//!     HTTP API touches only the CLOUD account, not local sync state. So we ADVISE
//!     (the exact Finder "Make online-only" / Smart Sync steps) and TOTAL the GB it
//!     would free. We NEVER delete a local file here, and NEVER set the ignored xattr.
//!     The ONE exception: if the `maestral` CLI is the ACTIVE sync client (Maestral
//!     REPLACES the official app — they can't both run), `maestral excluded add` IS a
//!     true scriptable offload, offered only behind `--yes`, never silently.
//!
//!   * iCLOUD (`~/Library/Mobile Documents` | `~/Library/CloudStorage/iCloud*`):
//!     `brctl evict <path>` evicts the local copy while keeping it in iCloud — a true
//!     scriptable offload. macOS-version-dependent, so we flag it.
//!
//!   * FILE-PROVIDER Dropbox (`~/Library/CloudStorage/Dropbox*`): eviction
//!     (`brctl`/`fileproviderctl evict`) is fragile / removed on macOS 14.4+, so we
//!     ADVISE primarily and never hard-depend on eviction.
//!
//! Detection is pure string/structure work plus, for `is_locally_stored`, a BOUNDED
//! on-disk sample (never a full walk — that is the scanner's job). Nothing in this
//! module runs `brctl` or `maestral` against user data; `stow` itself gates the real
//! actions behind `--yes`. `maestral_active` only *reads* status, never mutates.

use std::path::{Path, PathBuf};

/// Which cloud sync client owns a path. Drives the offload mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    /// Classic `~/Dropbox` — an ancestor directory contains a `.dropbox` marker
    /// (e.g. `~/Dropbox/.dropbox`). The official app syncs this; offload is
    /// ADVISE-ONLY unless Maestral is the active client. NEVER delete locally here,
    /// NEVER set `com.dropbox.ignored`.
    DropboxClassic,
    /// File-provider Dropbox under `~/Library/CloudStorage/Dropbox*`. Eviction is
    /// fragile / removed on macOS 14.4+, so ADVISE primarily.
    DropboxFileProvider,
    /// iCloud Drive — under `~/Library/Mobile Documents` or
    /// `~/Library/CloudStorage/iCloud*`. `brctl evict` is a true scriptable offload.
    ICloud,
    /// Not under any recognized cloud root. `stow` does not apply.
    None,
}

impl CloudProvider {
    /// Stable, lowercase token for JSON / table output.
    pub fn label(&self) -> &'static str {
        match self {
            CloudProvider::DropboxClassic => "dropbox-classic",
            CloudProvider::DropboxFileProvider => "dropbox-file-provider",
            CloudProvider::ICloud => "icloud",
            CloudProvider::None => "none",
        }
    }
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// The offload mechanism that is SAFE to use for a given provider (and Maestral
/// state). This is the policy table the research rules define — `stow` reads it to
/// decide whether to ACT (behind `--yes`) or merely ADVISE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffloadMechanism {
    /// iCloud: `brctl evict <path>` evicts the local copy, keeps it in iCloud.
    /// Actionable behind `--yes`. macOS-version-dependent.
    ICloudEvict,
    /// Classic Dropbox WITH the Maestral CLI as the active client:
    /// `maestral excluded add <path>` removes the local copy, keeps it in the cloud.
    /// Actionable behind `--yes`, never silently.
    MaestralExclude,
    /// Classic Dropbox WITHOUT Maestral (official app is the client): there is no
    /// safe scriptable offload, so ADVISE the exact Finder "Make online-only" steps
    /// and TOTAL the GB it would free. NEVER act.
    AdviseFinder,
    /// File-provider Dropbox: eviction is fragile / removed on macOS 14.4+. ADVISE
    /// primarily; any evict attempt carries a fragility caveat.
    AdviseFragileEvict,
    /// Not a cloud path — `stow` does not apply.
    NotApplicable,
}

impl OffloadMechanism {
    /// Stable, lowercase token for JSON output.
    pub fn label(&self) -> &'static str {
        match self {
            OffloadMechanism::ICloudEvict => "icloud-evict",
            OffloadMechanism::MaestralExclude => "maestral-exclude",
            OffloadMechanism::AdviseFinder => "advise-finder",
            OffloadMechanism::AdviseFragileEvict => "advise-fragile-evict",
            OffloadMechanism::NotApplicable => "not-applicable",
        }
    }

    /// `true` when this mechanism actually performs a scriptable offload (gated by
    /// `--yes` in the command layer). The ADVISE variants and `NotApplicable` are
    /// suggest-only and never run a command.
    pub fn is_actionable(&self) -> bool {
        matches!(
            self,
            OffloadMechanism::ICloudEvict | OffloadMechanism::MaestralExclude
        )
    }
}

impl std::fmt::Display for OffloadMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Cap on how many entries `is_locally_stored` samples before concluding. Keeps the
/// check O(1) on a directory with millions of children — we only need to find ONE
/// locally-stored file (blocks > 0), not census the whole tree. Bounded, never a
/// recursive walk (that is the scanner's job).
const LOCAL_SAMPLE_CAP: usize = 256;

/// Detect which cloud provider owns `path`, by walking its ancestors.
///
/// Order matters: the iCloud and file-provider checks key off the canonical
/// `~/Library/...` roots, while classic Dropbox is identified STRUCTURALLY (an
/// ancestor directory contains a `.dropbox` marker), which is what distinguishes a
/// real `~/Dropbox` from a directory merely named "Dropbox" somewhere else. Pure
/// path/marker inspection — at most one `exists()` per ancestor, no recursion.
pub fn detect_provider(path: &Path) -> CloudProvider {
    let home = home_dir();

    // iCloud + file-provider roots are exact `~/Library/...` prefixes. Check these
    // first: they are unambiguous and cheaper than the per-ancestor marker probe.
    if let Some(home) = &home {
        let mobile_docs = home.join("Library").join("Mobile Documents");
        let cloud_storage = home.join("Library").join("CloudStorage");

        if path.starts_with(&mobile_docs) {
            return CloudProvider::ICloud;
        }
        // `~/Library/CloudStorage/<Provider...>` — the provider is the FIRST
        // component under CloudStorage (e.g. `Dropbox`, `iCloud Drive`,
        // `iCloudDrive`). Match on its prefix.
        if let Ok(rest) = path.strip_prefix(&cloud_storage) {
            if let Some(first) = rest.components().next() {
                let name = first.as_os_str().to_string_lossy().to_lowercase();
                if name.starts_with("icloud") {
                    return CloudProvider::ICloud;
                }
                if name.starts_with("dropbox") {
                    return CloudProvider::DropboxFileProvider;
                }
            }
        }
    }

    // Classic Dropbox: an ANCESTOR (inclusive) directory contains a `.dropbox`
    // marker. This is the structural signal the official app drops at the sync-root
    // (`~/Dropbox/.dropbox`), so a directory merely NAMED "Dropbox" without the
    // marker is correctly NOT classified classic. One `exists()` per ancestor.
    let mut cur: Option<&Path> = Some(path);
    while let Some(dir) = cur {
        if dir.join(".dropbox").exists() {
            return CloudProvider::DropboxClassic;
        }
        cur = dir.parent();
    }

    CloudProvider::None
}

/// Is any byte of `path` actually stored LOCALLY (on-disk blocks > 0)?
///
/// The scanner already SKIPS online-only placeholders (a file with `len > 4096`
/// but `blocks == 0`). `stow` must likewise only target LOCALLY-stored data — it is
/// meaningless (and the command should refuse) to "offload" something already
/// online-only. For a file this is a single `stat`; for a directory we take a
/// BOUNDED sample (at most [`LOCAL_SAMPLE_CAP`] direct children, one level of
/// recursion into subdirs within the same budget) and return `true` as soon as we
/// find one locally-stored file. Never a full recursive walk.
///
/// On non-unix (no block count) we conservatively report `true` for any existing
/// file — we can't prove it's online-only, so we don't claim it is.
pub fn is_locally_stored(path: &Path) -> bool {
    let mut budget = LOCAL_SAMPLE_CAP;
    locally_stored_sampled(path, &mut budget)
}

/// Bounded helper for [`is_locally_stored`]. Decrements `budget` per entry inspected
/// and stops (returns `false`) when it hits zero without finding a local file.
fn locally_stored_sampled(path: &Path, budget: &mut usize) -> bool {
    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if md.file_type().is_symlink() {
        return false;
    }
    if md.is_file() {
        return file_has_local_blocks(&md);
    }
    if !md.is_dir() {
        return false;
    }

    let read = match std::fs::read_dir(path) {
        Ok(r) => r,
        Err(_) => return false,
    };
    // First pass: cheap, look at direct FILE children before recursing. Collect
    // subdirs to descend into only if no local file was found at this level.
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in read.flatten() {
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        let child = entry.path();
        let cmd = match std::fs::symlink_metadata(&child) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if cmd.file_type().is_symlink() {
            continue;
        }
        if cmd.is_file() {
            if file_has_local_blocks(&cmd) {
                return true;
            }
        } else if cmd.is_dir() {
            subdirs.push(child);
        }
    }
    // No local file directly here — descend into subdirs within the shared budget.
    for sub in subdirs {
        if *budget == 0 {
            return false;
        }
        if locally_stored_sampled(&sub, budget) {
            return true;
        }
    }
    false
}

/// `true` when a file's metadata indicates it occupies real on-disk blocks (i.e. it
/// is NOT an online-only cloud placeholder). Mirrors the scanner's placeholder rule:
/// `len > 4096 && blocks == 0` is a placeholder; anything with `blocks > 0` is local.
fn file_has_local_blocks(md: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // A placeholder reports size but zero allocated blocks. Everything else with
        // blocks > 0 is locally stored. (A genuinely empty 0-byte file has 0 blocks
        // and 0 len — not a placeholder, but also nothing to offload; treat as not
        // locally stored so `stow` skips it.)
        md.blocks() > 0
    }
    #[cfg(not(unix))]
    {
        // No block count available — we can't prove it's online-only, so assume it
        // occupies local space (the safe, non-claiming default).
        let _ = md;
        true
    }
}

/// Best-effort: is the `maestral` CLI installed AND the ACTIVE sync client?
///
/// Maestral is a REPLACEMENT for the official Dropbox app — the two cannot both run
/// against the same folder. We only return `true` when (a) `maestral` resolves on
/// `PATH` and (b) `maestral status` reports a connected/running daemon. We NEVER
/// assume Maestral is active: if the binary is missing, the status call fails, or it
/// reports stopped/disconnected, we return `false`, and `stow` falls back to the
/// ADVISE-Finder path for classic Dropbox (the safe default).
///
/// This only READS status; it never mutates sync state.
pub fn maestral_active() -> bool {
    maestral_active_with(&default_status_probe)
}

/// The outcome of probing the maestral CLI. Separated from the parsing decision so
/// the active-client logic is pure and unit-testable without spawning a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaestralProbe {
    /// `maestral` is not on `PATH` (or could not be spawned at all).
    NotInstalled,
    /// `maestral status` ran; carries the trimmed, lowercased stdout for parsing.
    Status(String),
    /// `maestral` is installed but the status call errored (non-spawn failure).
    ProbeError,
}

/// Pure decision: given a [`MaestralProbe`], is Maestral the active client? Only a
/// successful `status` whose output indicates a connected/running daemon counts.
/// Anything else — not installed, probe error, or a stopped/disconnected/error
/// status — is `false` (never assume active).
fn maestral_is_active(probe: &MaestralProbe) -> bool {
    match probe {
        MaestralProbe::NotInstalled | MaestralProbe::ProbeError => false,
        MaestralProbe::Status(out) => {
            let out = out.to_lowercase();
            // A stopped/disconnected/errored daemon is NOT active — check the
            // negative signals first so an "not connected" line can't false-positive
            // on the substring "connected".
            if out.contains("not connected")
                || out.contains("disconnected")
                || out.contains("not running")
                || out.contains("stopped")
                || out.contains("daemon is not running")
            {
                return false;
            }
            // Positive signals that the daemon owns the folder and is syncing.
            out.contains("connected") || out.contains("syncing") || out.contains("up to date")
        }
    }
}

/// Seam for [`maestral_active`]: takes a probe closure so tests can inject a
/// [`MaestralProbe`] without ever spawning the real CLI.
fn maestral_active_with(probe: &dyn Fn() -> MaestralProbe) -> bool {
    maestral_is_active(&probe())
}

/// Default probe: run `maestral status` and capture its output. Returns
/// [`MaestralProbe::NotInstalled`] when the binary can't be spawned (the common case
/// on a machine without Maestral), never panicking.
fn default_status_probe() -> MaestralProbe {
    use std::process::Command;
    match Command::new("maestral").arg("status").output() {
        Ok(out) => {
            let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
            s.push('\n');
            s.push_str(&String::from_utf8_lossy(&out.stderr));
            MaestralProbe::Status(s.trim().to_lowercase())
        }
        // A missing binary surfaces as a spawn error (NotFound) — treat as
        // not-installed. Any other spawn failure is a probe error (still not active).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => MaestralProbe::NotInstalled,
        Err(_) => MaestralProbe::ProbeError,
    }
}

/// Given a provider and whether Maestral is the active Dropbox client, return the
/// SAFE offload mechanism per the research rules. This is the single source of truth
/// the `stow` command consults to decide ACT-vs-ADVISE.
///
///   * iCloud                       -> [`OffloadMechanism::ICloudEvict`]
///   * classic Dropbox + Maestral   -> [`OffloadMechanism::MaestralExclude`]
///   * classic Dropbox, no Maestral -> [`OffloadMechanism::AdviseFinder`]
///   * file-provider Dropbox        -> [`OffloadMechanism::AdviseFragileEvict`]
///   * None                         -> [`OffloadMechanism::NotApplicable`]
pub fn offload_mechanism(provider: CloudProvider, maestral_active: bool) -> OffloadMechanism {
    match provider {
        CloudProvider::ICloud => OffloadMechanism::ICloudEvict,
        CloudProvider::DropboxClassic => {
            if maestral_active {
                OffloadMechanism::MaestralExclude
            } else {
                OffloadMechanism::AdviseFinder
            }
        }
        CloudProvider::DropboxFileProvider => OffloadMechanism::AdviseFragileEvict,
        CloudProvider::None => OffloadMechanism::NotApplicable,
    }
}

/// The exact ARGV an ACTIONABLE mechanism would run to offload `path`, or `None`
/// for an ADVISE-only mechanism (which runs no command at all).
///
/// This is the single source of truth for the offload command the `stow` command
/// spawns — and the seam the tests assert against. Tests build the argv and check
/// it WITHOUT ever spawning the process, so no `brctl`/`maestral` ever runs against
/// real user data in CI.
///
///   * [`OffloadMechanism::ICloudEvict`]    → `["brctl", "evict", <path>]`
///   * [`OffloadMechanism::MaestralExclude`] → `["maestral", "excluded", "add", <path>]`
///   * every ADVISE / NotApplicable variant  → `None` (no command)
///
/// Note what is ABSENT, by design: no `rm`, no `mv` out of `~/Dropbox`, and no
/// `xattr -w com.dropbox.ignored`. Those are the forbidden data-LOSS operations;
/// they appear in NO branch here or anywhere in the crate.
pub fn offload_argv(mechanism: OffloadMechanism, path: &Path) -> Option<Vec<String>> {
    let p = path.to_string_lossy().into_owned();
    match mechanism {
        OffloadMechanism::ICloudEvict => Some(vec!["brctl".into(), "evict".into(), p]),
        OffloadMechanism::MaestralExclude => {
            Some(vec!["maestral".into(), "excluded".into(), "add".into(), p])
        }
        OffloadMechanism::AdviseFinder
        | OffloadMechanism::AdviseFragileEvict
        | OffloadMechanism::NotApplicable => None,
    }
}

/// `$HOME` as a `PathBuf`, or `None` when unset. Kept private so detection always
/// resolves the same way the rest of the tool does.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::MutexGuard;
    use std::time::SystemTime;

    /// A throwaway temp tree, cleaned on drop. Synthetic only — these tests NEVER
    /// touch the real `$HOME` cloud roots and NEVER run `brctl` or `maestral`.
    struct TempTree {
        root: PathBuf,
    }
    impl TempTree {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "diskspace-cloud-{}-{}-{}",
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

    /// Override `$HOME` to `home` for the duration of the returned guard, holding the
    /// crate-wide `HOME_TEST_LOCK` so parallel test threads don't race on the
    /// process-global env var. Restores the prior `$HOME` on drop.
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

    // ---- detect_provider ----------------------------------------------------

    #[test]
    fn classic_dropbox_detected_via_dotdropbox_marker() {
        let t = TempTree::new("classic");
        // ~/Dropbox/.dropbox marker + a nested file.
        let dropbox = t.dir("Dropbox");
        fs::create_dir_all(dropbox.join(".dropbox")).unwrap();
        let nested = t.dir("Dropbox/Projects/big");
        let f = t.file(&nested, "data.bin", 4096);

        let _home = HomeOverride::set(&t.root);
        assert_eq!(
            detect_provider(&f),
            CloudProvider::DropboxClassic,
            "a file under a tree whose ancestor holds a .dropbox marker is classic Dropbox"
        );
        assert_eq!(
            detect_provider(&dropbox),
            CloudProvider::DropboxClassic,
            "the sync root itself (holding the marker) is classic Dropbox"
        );
    }

    #[test]
    fn dropbox_named_dir_without_marker_is_not_classic() {
        let t = TempTree::new("nomarker");
        // A directory NAMED Dropbox but with NO .dropbox marker is NOT classic —
        // deleting inside it would not propagate to any cloud, but we also must not
        // mis-advise. detect_provider returns None (no marker, not under Library).
        let dropbox = t.dir("Dropbox/sub");
        let f = t.file(&dropbox, "x.bin", 1024);
        let _home = HomeOverride::set(&t.root);
        assert_eq!(
            detect_provider(&f),
            CloudProvider::None,
            "a Dropbox-named dir without the .dropbox marker is NOT classic Dropbox"
        );
    }

    #[test]
    fn icloud_mobile_documents_path_is_icloud() {
        let t = TempTree::new("icloud-md");
        let md = t.dir("Library/Mobile Documents/com~apple~CloudDocs/Docs");
        let f = t.file(&md, "paper.pdf", 8192);
        let _home = HomeOverride::set(&t.root);
        assert_eq!(detect_provider(&f), CloudProvider::ICloud);
    }

    #[test]
    fn icloud_cloudstorage_path_is_icloud() {
        let t = TempTree::new("icloud-cs");
        let cs = t.dir("Library/CloudStorage/iCloud Drive/Notes");
        let f = t.file(&cs, "note.txt", 2048);
        let _home = HomeOverride::set(&t.root);
        assert_eq!(detect_provider(&f), CloudProvider::ICloud);
    }

    #[test]
    fn cloudstorage_dropbox_path_is_file_provider() {
        let t = TempTree::new("dbx-fp");
        let cs = t.dir("Library/CloudStorage/Dropbox/Work");
        let f = t.file(&cs, "deck.key", 4096);
        let _home = HomeOverride::set(&t.root);
        assert_eq!(
            detect_provider(&f),
            CloudProvider::DropboxFileProvider,
            "~/Library/CloudStorage/Dropbox* is the file-provider variant"
        );
    }

    #[test]
    fn unrelated_path_is_none() {
        let t = TempTree::new("none");
        let d = t.dir("Code/project");
        let f = t.file(&d, "main.rs", 1024);
        let _home = HomeOverride::set(&t.root);
        assert_eq!(detect_provider(&f), CloudProvider::None);
    }

    // ---- is_locally_stored --------------------------------------------------

    #[test]
    fn real_file_with_bytes_is_locally_stored() {
        let t = TempTree::new("local");
        let d = t.dir("data");
        let f = t.file(&d, "real.bin", 16 * 1024);
        // A file with actual content has blocks > 0.
        assert!(
            is_locally_stored(&f),
            "a file with real bytes is locally stored"
        );
        // The containing dir, sampled, also reports locally stored.
        assert!(
            is_locally_stored(&d),
            "a dir holding a local file is locally stored"
        );
    }

    #[test]
    fn empty_dir_is_not_locally_stored() {
        let t = TempTree::new("emptydir");
        let d = t.dir("empty");
        assert!(
            !is_locally_stored(&d),
            "an empty directory has no locally-stored bytes to offload"
        );
    }

    #[test]
    fn missing_path_is_not_locally_stored() {
        let t = TempTree::new("missing");
        let p = t.root.join("does-not-exist");
        assert!(!is_locally_stored(&p));
    }

    // ---- offload_mechanism (the research-rule policy table) ------------------

    #[test]
    fn icloud_maps_to_evict_regardless_of_maestral() {
        assert_eq!(
            offload_mechanism(CloudProvider::ICloud, false),
            OffloadMechanism::ICloudEvict
        );
        assert_eq!(
            offload_mechanism(CloudProvider::ICloud, true),
            OffloadMechanism::ICloudEvict,
            "maestral state is irrelevant for iCloud"
        );
    }

    #[test]
    fn classic_dropbox_without_maestral_advises_finder() {
        assert_eq!(
            offload_mechanism(CloudProvider::DropboxClassic, false),
            OffloadMechanism::AdviseFinder,
            "classic Dropbox under the OFFICIAL app has no safe scriptable offload — advise Finder"
        );
        assert!(
            !offload_mechanism(CloudProvider::DropboxClassic, false).is_actionable(),
            "AdviseFinder must never auto-act"
        );
    }

    #[test]
    fn classic_dropbox_with_maestral_excludes() {
        let m = offload_mechanism(CloudProvider::DropboxClassic, true);
        assert_eq!(
            m,
            OffloadMechanism::MaestralExclude,
            "classic Dropbox WITH Maestral active uses `maestral excluded add`"
        );
        assert!(
            m.is_actionable(),
            "MaestralExclude is a real (gated) offload"
        );
    }

    #[test]
    fn file_provider_dropbox_advises_fragile_evict() {
        let m = offload_mechanism(CloudProvider::DropboxFileProvider, false);
        assert_eq!(m, OffloadMechanism::AdviseFragileEvict);
        assert!(
            !m.is_actionable(),
            "file-provider eviction is fragile on 14.4+ — advise, never hard-act"
        );
        // Maestral state does not change the file-provider verdict.
        assert_eq!(
            offload_mechanism(CloudProvider::DropboxFileProvider, true),
            OffloadMechanism::AdviseFragileEvict
        );
    }

    #[test]
    fn none_provider_is_not_applicable() {
        assert_eq!(
            offload_mechanism(CloudProvider::None, false),
            OffloadMechanism::NotApplicable
        );
        assert_eq!(
            offload_mechanism(CloudProvider::None, true),
            OffloadMechanism::NotApplicable
        );
    }

    // ---- maestral_active decision logic (no real CLI spawned) ----------------

    #[test]
    fn maestral_not_installed_is_not_active() {
        assert!(!maestral_is_active(&MaestralProbe::NotInstalled));
        assert!(
            !maestral_active_with(&|| MaestralProbe::NotInstalled),
            "a machine without the maestral binary never reports active"
        );
    }

    #[test]
    fn maestral_probe_error_is_not_active() {
        assert!(!maestral_is_active(&MaestralProbe::ProbeError));
    }

    #[test]
    fn maestral_connected_status_is_active() {
        assert!(maestral_is_active(&MaestralProbe::Status(
            "connected, up to date".into()
        )));
        assert!(maestral_is_active(&MaestralProbe::Status(
            "syncing 3 files".into()
        )));
        assert!(maestral_active_with(&|| MaestralProbe::Status(
            "connected".into()
        )));
    }

    #[test]
    fn maestral_stopped_or_disconnected_status_is_not_active() {
        assert!(!maestral_is_active(&MaestralProbe::Status(
            "daemon is not running".into()
        )));
        assert!(!maestral_is_active(&MaestralProbe::Status(
            "not connected".into()
        )));
        assert!(
            !maestral_is_active(&MaestralProbe::Status("disconnected".into())),
            "a disconnected daemon does not own the folder"
        );
        assert!(
            !maestral_is_active(&MaestralProbe::Status("stopped".into())),
            "a stopped daemon is not active even though we never spawned the real CLI"
        );
    }

    // ---- offload_argv (the command stow WOULD run; never executed here) ------

    #[test]
    fn icloud_evict_argv_is_brctl_evict_path() {
        let p = Path::new("/Users/x/Library/Mobile Documents/com~apple~CloudDocs/big.psd");
        let argv = offload_argv(OffloadMechanism::ICloudEvict, p).expect("evict is actionable");
        assert_eq!(argv[0], "brctl");
        assert_eq!(argv[1], "evict");
        assert_eq!(argv[2], p.to_string_lossy());
        assert_eq!(argv.len(), 3);
    }

    #[test]
    fn maestral_exclude_argv_is_maestral_excluded_add_path() {
        let p = Path::new("/Users/x/Dropbox/Archive/2019");
        let argv =
            offload_argv(OffloadMechanism::MaestralExclude, p).expect("maestral is actionable");
        assert_eq!(
            argv,
            vec!["maestral", "excluded", "add", &*p.to_string_lossy()]
        );
    }

    #[test]
    fn advise_mechanisms_construct_no_command() {
        let p = Path::new("/Users/x/Dropbox/Photos");
        assert!(
            offload_argv(OffloadMechanism::AdviseFinder, p).is_none(),
            "AdviseFinder runs NO command — it only prints Finder steps"
        );
        assert!(offload_argv(OffloadMechanism::AdviseFragileEvict, p).is_none());
        assert!(offload_argv(OffloadMechanism::NotApplicable, p).is_none());
    }

    /// The forbidden data-LOSS operations must appear in NO offload argv: no `rm`,
    /// no move out of Dropbox, and never the `com.dropbox.ignored` xattr.
    #[test]
    fn offload_argv_never_contains_forbidden_operations() {
        let p = Path::new("/Users/x/Dropbox/Important");
        for m in [
            OffloadMechanism::ICloudEvict,
            OffloadMechanism::MaestralExclude,
            OffloadMechanism::AdviseFinder,
            OffloadMechanism::AdviseFragileEvict,
            OffloadMechanism::NotApplicable,
        ] {
            if let Some(argv) = offload_argv(m, p) {
                let joined = argv.join(" ");
                assert!(
                    !joined.contains("com.dropbox.ignored"),
                    "never the ignored xattr"
                );
                assert!(!argv.iter().any(|a| a == "rm"), "never rm");
                assert!(!argv.iter().any(|a| a == "mv"), "never mv");
                assert!(!argv.iter().any(|a| a == "xattr"), "never xattr");
            }
        }
    }

    // ---- label / wire-form stability ----------------------------------------

    #[test]
    fn provider_and_mechanism_labels_are_stable() {
        assert_eq!(CloudProvider::DropboxClassic.label(), "dropbox-classic");
        assert_eq!(
            CloudProvider::DropboxFileProvider.label(),
            "dropbox-file-provider"
        );
        assert_eq!(CloudProvider::ICloud.label(), "icloud");
        assert_eq!(CloudProvider::None.label(), "none");
        assert_eq!(OffloadMechanism::ICloudEvict.label(), "icloud-evict");
        assert_eq!(
            OffloadMechanism::MaestralExclude.label(),
            "maestral-exclude"
        );
        assert_eq!(OffloadMechanism::AdviseFinder.label(), "advise-finder");
        assert_eq!(
            OffloadMechanism::AdviseFragileEvict.label(),
            "advise-fragile-evict"
        );
        assert_eq!(OffloadMechanism::NotApplicable.label(), "not-applicable");
    }
}

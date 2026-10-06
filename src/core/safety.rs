//! Built-in data-safety floor for the actuation gate.
//!
//! The pressure-test gate ([`crate::commands::check::pressure_test`]) consults
//! this module so an autonomous / heuristic / grant-driven deletion can NEVER
//! remove a database or a credential store, even when the user's profile
//! `never_touch` list is empty.
//!
//! The model (see [`crate::commands::check`] `data_safety_check`):
//!   1. A path that is *rule-vouched regenerable* — every matching builtin rule
//!      has a recovery class in {auto, redownload, rebuild, recreate} — is exempt
//!      from the scan. The curator vouched the whole tree (e.g. `node_modules`,
//!      `target`) is rebuildable from a source, so a db inside it is regenerable
//!      too; and scanning a giant cache would be wasteful / falsely refuse it.
//!   2. Everything else (manual/irreversible rules like git worktrees, plus
//!      unruled/heuristic paths) is scanned: a database found at or beneath it
//!      vetoes the deletion (fail-closed; bound-exhaustion also vetoes).
//!   3. EXCEPTION: a *wildcard-free* rule that names the exact database file
//!      (e.g. `~/.screenpipe/db.sqlite`, a regenerable recording buffer) is an
//!      explicit curator decision about that one db and stays deletable. A
//!      *directory* rule never vouches for a database merely nested beneath it.
//!
//! This is the product embodiment of a rule learned the painful way: disk
//! cleanup deletes BUILD CACHES, never databases or application state. The floor
//! runs strictly BEFORE any grant logic, so it is fail-closed and cannot be
//! relaxed by a capability grant.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::core::candidate::CheckStep;
use crate::core::rules::Rule;

/// Filename suffixes marking a file as a database / durable state store. Matched
/// case-insensitively against the file name. Not exhaustive — paired with the
/// leveldb structural check and the SQLite magic-byte sniff below, since suffix
/// matching alone misses leveldb (CURRENT/MANIFEST) and extension-less stores.
pub const DB_SUFFIXES: &[&str] = &[
    ".sqlite",
    ".sqlite3",
    ".sqlite-wal",
    ".sqlite-shm",
    ".sqlite-journal",
    ".sqlite3-wal",
    ".sqlite3-shm",
    ".sqlite3-journal",
    ".db",
    ".db3",
    ".db-wal",
    ".db-shm",
    ".db-journal",
    "-journal",
    ".vscdb",
    ".mdb",
    ".realm",
    ".ldb",
];

/// Recovery classes the curator considers wholesale-regenerable: deleting the
/// tree loses no original data because it rebuilds from a source. A database
/// nested in such a tree is itself regenerable, so these are exempt from the db
/// scan. `manual` and `irreversible` are NOT here — they may hold real data.
pub const REGENERABLE_CLASSES: &[&str] = &["auto", "redownload", "rebuild", "recreate"];

/// Entry budget for the bounded database walk. Beyond it the scan is
/// INCONCLUSIVE and the gate fails closed (refuses the autonomous deletion)
/// rather than guessing safe. The walk has NO depth limit — it descends until
/// the budget is exhausted, so a deeply-nested db cannot hide below a cap that
/// `remove_dir_all` would nonetheless delete.
pub const DB_SCAN_CAP: usize = 200_000;

/// The 16-byte header every SQLite database file begins with.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Credential / key / secret stores: never regenerable, never targeted by a
/// cleanup rule, never overridable by a profile or a grant. Prefix-matched — the
/// directory and everything beneath it.
pub fn builtin_never_touch() -> &'static [&'static str] {
    &[
        "~/.ssh",
        "~/.gnupg",
        "~/.aws",
        "~/.kube",
        "~/Library/Keychains",
    ]
}

/// Does `path`'s file name mark it as a database file?
pub fn is_database_file(path: &Path) -> bool {
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => {
            let lower = name.to_ascii_lowercase();
            DB_SUFFIXES.iter().any(|s| lower.ends_with(s))
        }
        None => false,
    }
}

/// A file with no extension can still be a SQLite database (Chromium `History`,
/// `Cookies`, …). Sniff the magic header for those — bounded to extension-less
/// names so we never open every file in the tree.
fn is_extensionless(name: &str) -> bool {
    !name.contains('.')
}

fn sniff_sqlite(path: &Path) -> bool {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = [0u8; 16];
    f.read_exact(&mut buf).is_ok() && &buf == SQLITE_MAGIC
}

/// Result of scanning a candidate for database content.
#[derive(Debug)]
pub enum DbScan {
    /// No database found within the bounded walk.
    Clean,
    /// A database is the candidate itself, or lives beneath it.
    Found(PathBuf),
    /// The directory exceeded the entry budget before it could be cleared. The
    /// gate treats this as a refusal (fail-closed) for autonomous deletion.
    Inconclusive,
}

/// Is `path` a database (or a leveldb store, or an extension-less SQLite file),
/// or — if a directory — does it contain one within the bounded walk? Symlinks
/// are not followed (avoids escaping the subtree / loops). No depth limit: the
/// reach matches `remove_dir_all`'s unbounded reach.
pub fn database_scan(path: &Path, cap: usize) -> DbScan {
    if is_database_file(path) {
        return DbScan::Found(path.to_path_buf());
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        // Unreadable — the re-stat step handles existence; don't claim a db here.
        Err(_) => return DbScan::Clean,
    };
    if meta.is_file() {
        if let Some(n) = path.file_name().and_then(|n| n.to_str()) {
            if is_extensionless(n) && sniff_sqlite(path) {
                return DbScan::Found(path.to_path_buf());
            }
        }
        return DbScan::Clean;
    }
    if !meta.is_dir() {
        return DbScan::Clean;
    }

    let mut stack: Vec<PathBuf> = vec![path.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        // leveldb stores keep live data in CURRENT + MANIFEST-* even with zero
        // `.ldb` files; detect that directory shape structurally.
        let mut has_current = false;
        let mut has_manifest = false;
        let mut subdirs: Vec<PathBuf> = Vec::new();
        for entry in rd.flatten() {
            seen += 1;
            if seen > cap {
                return DbScan::Inconclusive;
            }
            let name_os = entry.file_name();
            let name = name_os.to_string_lossy();
            if name == "CURRENT" {
                has_current = true;
            } else if name.starts_with("MANIFEST-") {
                has_manifest = true;
            }
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                continue;
            }
            let child = entry.path();
            if ft.is_file() {
                if is_database_file(&child) {
                    return DbScan::Found(child);
                }
                if is_extensionless(&name) && sniff_sqlite(&child) {
                    return DbScan::Found(child);
                }
            } else if ft.is_dir() {
                subdirs.push(child);
            }
        }
        if has_current && has_manifest {
            return DbScan::Found(dir.join("CURRENT"));
        }
        for s in subdirs {
            stack.push(s);
        }
    }
    DbScan::Clean
}

/// Rules whose expanded `path_pattern` matches `path` as a glob.
///
/// A single `*` must NOT cross `/` here: glob's default
/// `require_literal_separator: false` lets `~/Library/Caches/*ShipIt*` over-match
/// a database nested several components below and wrongly exempt it. We evaluate
/// the regenerable-exemption match with `require_literal_separator: true` so `*`
/// stays within one path component. `**` still crosses separators, so the
/// `**/node_modules` / `**/target` exemptions keep working.
fn matching_rules<'a>(path: &Path, rules: &'a [Rule], home: &Path) -> Vec<&'a Rule> {
    let opts = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    rules
        .iter()
        .filter(|r| {
            let expanded = crate::core::scanner::expand_home(&r.path_pattern, home);
            glob::Pattern::new(&expanded)
                .map(|p| p.matches_path_with(path, opts))
                .unwrap_or(false)
        })
        .collect()
}

/// Is `path` vouched wholesale-regenerable? True only when it matches at least
/// one rule AND EVERY matching rule has a regenerable recovery class. If any
/// matching rule is data-bearing (manual/irreversible) or lacks a recovery
/// class, the path is NOT exempt — it gets scanned. Conservative by design.
pub fn is_regenerable_vouched(path: &Path, rules: &[Rule], home: &Path) -> bool {
    let matching = matching_rules(path, rules, home);
    !matching.is_empty()
        && matching.iter().all(|r| {
            r.consequences
                .as_ref()
                .map(|c| REGENERABLE_CLASSES.contains(&c.recovery.as_str()))
                .unwrap_or(false)
        })
}

/// Does a *wildcard-free* rule name this exact path? Such a rule is an explicit
/// curator decision about one concrete file (e.g. `~/.screenpipe/db.sqlite`). A
/// glob or directory pattern never qualifies, so it can never vouch for a
/// database merely nested beneath it.
pub fn rule_names_exact_path(path: &Path, rules: &[Rule], home: &Path) -> bool {
    rules.iter().any(|r| {
        let p = &r.path_pattern;
        let wildcard_free = !p.contains('*') && !p.contains('?') && !p.contains('[');
        wildcard_free && Path::new(&crate::core::scanner::expand_home(p, home)) == path
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    /// Unique scratch dir under the system temp root (no tempfile crate dep, in
    /// keeping with the rest of the suite). Caller removes it.
    fn tmp() -> PathBuf {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("diskspace-safety-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn rule(pattern: &str, recovery: Option<&str>) -> Rule {
        Rule {
            id: "stub".into(),
            category: "test".into(),
            path_pattern: pattern.into(),
            domain: None,
            base_confidence: 0.5,
            reason: "test".into(),
            exclude_if_recent_access_days: None,
            exclude_if_recent_modified_days: None,
            consequences: recovery.map(|r| crate::core::rules::Consequences {
                recovery: r.into(),
                rebuild_seconds: None,
                impact: "test".into(),
                recovery_cmd: None,
            }),
            reference_url: None,
        }
    }

    #[test]
    fn db_suffixes_detected_case_insensitive() {
        assert!(is_database_file(Path::new("/x/foo.sqlite")));
        assert!(is_database_file(Path::new("/x/foo.sqlite-wal")));
        assert!(is_database_file(Path::new("/x/foo.sqlite3-wal")));
        assert!(is_database_file(Path::new("/x/foo.db-journal")));
        assert!(is_database_file(Path::new("/x/rollback-journal")));
        assert!(is_database_file(Path::new("/x/state.vscdb")));
        assert!(is_database_file(Path::new("/x/Logs.DB")));
        assert!(!is_database_file(Path::new("/x/notes.md")));
        assert!(!is_database_file(Path::new("/x/build.log")));
        assert!(!is_database_file(Path::new("/x/index.js")));
    }

    #[test]
    fn scan_finds_nested_database() {
        let d = tmp();
        let nested = d.join("a/b/c");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("codex-dev.db"), b"x").unwrap();
        match database_scan(&d, DB_SCAN_CAP) {
            DbScan::Found(p) => assert!(p.ends_with("codex-dev.db")),
            other => panic!("expected Found, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&d);
    }

    /// Finding #2 regression: a db deeper than the old depth-12 bound must still
    /// be found (the scan now has no depth limit).
    #[test]
    fn scan_finds_database_far_below_old_depth_bound() {
        let d = tmp();
        let mut deep = d.clone();
        for i in 0..18 {
            deep = deep.join(format!("lvl{i}"));
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("buried.sqlite"), b"x").unwrap();
        assert!(
            matches!(database_scan(&d, DB_SCAN_CAP), DbScan::Found(_)),
            "a db 18 levels deep must be found (no depth cap)"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// Finding #4 regression: a leveldb store with NO `.ldb` (only CURRENT +
    /// MANIFEST) must be detected structurally.
    #[test]
    fn scan_detects_leveldb_by_structure() {
        let d = tmp();
        let store = d.join("Local Storage/leveldb");
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join("CURRENT"), b"MANIFEST-000001\n").unwrap();
        fs::write(store.join("MANIFEST-000001"), b"\x00").unwrap();
        fs::write(store.join("000003.log"), b"data").unwrap();
        assert!(
            matches!(database_scan(&d, DB_SCAN_CAP), DbScan::Found(_)),
            "leveldb (CURRENT + MANIFEST) must be detected with no .ldb present"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// Finding #4 regression: an extension-less SQLite file (Chromium History /
    /// Cookies) must be caught by the magic-byte sniff.
    #[test]
    fn scan_detects_extensionless_sqlite_by_magic() {
        let d = tmp();
        let mut content = SQLITE_MAGIC.to_vec();
        content.extend_from_slice(b"rest of the header");
        fs::write(d.join("History"), &content).unwrap();
        assert!(
            matches!(database_scan(&d, DB_SCAN_CAP), DbScan::Found(_)),
            "an extension-less SQLite file must be sniffed"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn scan_clean_build_cache() {
        let d = tmp();
        let nm = d.join("node_modules/pkg/dist");
        fs::create_dir_all(&nm).unwrap();
        fs::write(nm.join("index.js"), b"x").unwrap();
        fs::write(d.join("package.json"), b"{}").unwrap();
        // a plain extension-less text file must NOT false-positive
        fs::write(d.join("LICENSE"), b"MIT").unwrap();
        assert!(matches!(database_scan(&d, DB_SCAN_CAP), DbScan::Clean));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn scan_inconclusive_fails_closed_when_capped() {
        let d = tmp();
        for i in 0..40 {
            fs::write(d.join(format!("f{i}.txt")), b"x").unwrap();
        }
        assert!(matches!(database_scan(&d, 5), DbScan::Inconclusive));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn regenerable_vouched_only_when_all_matching_rules_are_regenerable() {
        let home = Path::new("/home/u");
        // node_modules (redownload) → vouched.
        let redownload = vec![rule("**/node_modules", Some("redownload"))];
        assert!(is_regenerable_vouched(
            Path::new("/home/u/proj/node_modules"),
            &redownload,
            home
        ));
        // worktrees (irreversible) → NOT vouched → will be scanned.
        let irreversible = vec![rule("~/.codex/worktrees", Some("irreversible"))];
        assert!(!is_regenerable_vouched(
            Path::new("/home/u/.codex/worktrees"),
            &irreversible,
            home
        ));
        // unmatched path → not vouched.
        assert!(!is_regenerable_vouched(
            Path::new("/home/u/random"),
            &redownload,
            home
        ));
        // matches a regenerable AND a data-bearing rule → NOT vouched (conservative).
        let mixed = vec![
            rule("**/proj", Some("rebuild")),
            rule("/home/u/proj", Some("manual")),
        ];
        assert!(!is_regenerable_vouched(
            Path::new("/home/u/proj"),
            &mixed,
            home
        ));
    }

    /// Re-verify regression: a single `*` in a regenerable rule must NOT cross
    /// `/` and exempt a database nested several components below (the
    /// `~/Library/Caches/*ShipIt*` over-match). `**` must still cross for the
    /// node_modules exemption.
    #[test]
    fn regenerable_vouched_star_does_not_cross_slash() {
        let home = Path::new("/home/u");
        let shipit = vec![rule("~/Library/Caches/*ShipIt*", Some("auto"))];
        // intended: a DIRECT child of Caches is exempt
        assert!(
            is_regenerable_vouched(
                Path::new("/home/u/Library/Caches/com.foo.ShipIt"),
                &shipit,
                home
            ),
            "a direct ShipIt cache child is still exempt"
        );
        // the hole: a db nested below must NOT be exempted
        assert!(
            !is_regenerable_vouched(
                Path::new("/home/u/Library/Caches/com.foo/com.foo.ShipIt/state.sqlite"),
                &shipit,
                home
            ),
            "a `*` must not cross `/` to exempt a nested database"
        );
        // `**` still crosses for the node_modules exemption
        let nm = vec![rule("**/node_modules", Some("redownload"))];
        assert!(
            is_regenerable_vouched(Path::new("/home/u/a/b/node_modules"), &nm, home),
            "** still crosses separators for the node_modules exemption"
        );
    }

    #[test]
    fn exact_file_rule_names_db_but_directory_glob_does_not() {
        let home = Path::new("/home/u");
        let rules = vec![
            rule("~/.screenpipe/db.sqlite", Some("irreversible")), // exact file
            rule("~/.codex/worktrees", Some("irreversible")),      // directory
            rule("**/node_modules", Some("redownload")),           // glob
        ];
        // the exact-file db rule names its own path
        assert!(rule_names_exact_path(
            Path::new("/home/u/.screenpipe/db.sqlite"),
            &rules,
            home
        ));
        // a db nested under the worktrees DIRECTORY is NOT exact-named
        assert!(!rule_names_exact_path(
            Path::new("/home/u/.codex/worktrees/proj/app.sqlite"),
            &rules,
            home
        ));
        // a glob never exact-names anything
        assert!(!rule_names_exact_path(
            Path::new("/home/u/proj/node_modules"),
            &rules,
            home
        ));
    }
}

// ---------------------------------------------------------------------------
// Autonomous-path hardening
// ---------------------------------------------------------------------------
//
// `check::pressure_test` is the shared floor for every delete path, interactive
// or not. The checks below are the EXTRA ones that only an UNATTENDED delete
// needs, and they are deliberately not folded into `pressure_test`: an
// interactive user surveying `/Volumes/scratch` must still be able to act there,
// while a background tick must not. Keeping them separate also means this
// hardening can only ever make the autonomous path stricter.
//
// What it adds over `pressure_test`:
//   * symlink rejection on the target AND every ancestor under $HOME (a swapped
//     ancestor is the classic TOCTOU escape — `remove_dir_all` would follow the
//     new parent, and `fs::metadata` in `restat_check` follows links);
//   * containment: the resolved path must live strictly beneath the resolved
//     $HOME, so a relative/`..` candidate or a cross-volume path is refused;
//   * cloud-synced exclusion for ANY recognized provider (iCloud, both Dropbox
//     shapes), because a local delete there propagates to every other device;
//   * a bounded content scan that refuses model weights, unique patches, version
//     -controlled source, and credential material.

/// File suffixes that identify trained-model weights. Deleting these "frees"
/// space that can cost hours and gigabytes of download to restore, so the
/// unattended path refuses them even when a rule calls the cache regenerable.
pub const MODEL_WEIGHT_SUFFIXES: &[&str] = &[
    ".gguf",
    ".ggml",
    ".safetensors",
    ".ckpt",
    ".pt",
    ".pth",
    ".onnx",
    ".npz",
    ".h5",
    ".tflite",
    ".mlmodel",
    ".mlpackage",
    ".mlmodelc",
];

/// `.bin` is far too common to blanket-refuse, so it only counts as a weight
/// above this size. Typical shard sizes start in the hundreds of MB.
pub const MODEL_WEIGHT_BIN_MIN_BYTES: u64 = 64 * 1024 * 1024;

/// Patch / diff files: often the only copy of work that exists nowhere else.
pub const PATCH_SUFFIXES: &[&str] = &[".patch", ".diff"];

/// Credential material by file name or suffix. Complements the prefix-based
/// [`builtin_never_touch`], which only covers whole well-known directories.
pub const CREDENTIAL_SUFFIXES: &[&str] = &[
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".keychain",
    ".keychain-db",
    ".kdbx",
    ".asc",
    ".gpg",
];
pub const CREDENTIAL_NAMES: &[&str] = &[
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "credentials",
    "credentials.json",
    ".netrc",
    ".npmrc",
    ".pypirc",
];

/// Directory names marking version-controlled source — active work whose
/// presence means the tree is not a disposable cache.
pub const VCS_DIR_NAMES: &[&str] = &[".git", ".hg", ".svn", ".jj"];

/// Entry budget for [`sensitive_scan`]. Smaller than [`DB_SCAN_CAP`] because this
/// runs on candidates that already cleared the database floor, and a background
/// tick has a hard time budget. Exhausting it is INCONCLUSIVE → refused.
pub const AUTONOMOUS_SCAN_CAP: usize = 50_000;

/// What a bounded sensitive-content scan found.
#[derive(Debug, PartialEq, Eq)]
pub enum SensitiveScan {
    Clean,
    /// `(offending path, reason token)`.
    Found(PathBuf, &'static str),
    /// Budget exhausted before the tree could be cleared — fail closed.
    Inconclusive,
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Classify one FILE (never a directory) against the content exclusions.
/// `size` is the file's length; only `.bin` consults it.
pub fn sensitive_file_reason(path: &Path, size: u64) -> Option<&'static str> {
    let lower = name_of(path);
    if MODEL_WEIGHT_SUFFIXES.iter().any(|s| lower.ends_with(s)) {
        return Some("model-weights");
    }
    if lower.ends_with(".bin") && size >= MODEL_WEIGHT_BIN_MIN_BYTES {
        return Some("model-weights");
    }
    if PATCH_SUFFIXES.iter().any(|s| lower.ends_with(s)) {
        return Some("unique-patch");
    }
    if CREDENTIAL_SUFFIXES.iter().any(|s| lower.ends_with(s))
        || CREDENTIAL_NAMES.iter().any(|n| lower == *n)
    {
        return Some("credentials");
    }
    None
}

/// Walk `path` within `cap` entries looking for content the unattended path must
/// never delete. Symlinks are never followed (and a symlink encountered inside is
/// itself a refusal — the autonomous path does not reason about link targets).
pub fn sensitive_scan(path: &Path, cap: usize) -> SensitiveScan {
    let mut budget = cap;
    sensitive_scan_inner(path, &mut budget)
}

fn sensitive_scan_inner(path: &Path, budget: &mut usize) -> SensitiveScan {
    if *budget == 0 {
        return SensitiveScan::Inconclusive;
    }
    *budget -= 1;

    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        // Unreadable is not provably safe.
        Err(_) => return SensitiveScan::Found(path.to_path_buf(), "unreadable"),
    };
    if md.file_type().is_symlink() {
        return SensitiveScan::Found(path.to_path_buf(), "symlink");
    }
    let name = name_of(path);
    // `.git` is a FILE in worktrees and submodules (`gitdir: ...`); either shape
    // marks the tree as active source.
    if VCS_DIR_NAMES.contains(&name.as_str()) {
        return SensitiveScan::Found(path.to_path_buf(), "version-controlled-source");
    }
    if md.is_file() {
        return match sensitive_file_reason(path, md.len()) {
            Some(reason) => SensitiveScan::Found(path.to_path_buf(), reason),
            None => SensitiveScan::Clean,
        };
    }
    if !md.is_dir() {
        // Sockets, fifos, devices: not something a cleanup path should remove.
        return SensitiveScan::Found(path.to_path_buf(), "not-a-regular-file");
    }
    // Core ML models (`.mlpackage`, `.mlmodelc`) are bundle directories.
    if MODEL_WEIGHT_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        return SensitiveScan::Found(path.to_path_buf(), "model-weights");
    }

    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return SensitiveScan::Found(path.to_path_buf(), "unreadable"),
    };
    for entry in entries {
        // An entry that cannot even be listed is not provably safe.
        let Ok(entry) = entry else {
            return SensitiveScan::Found(path.to_path_buf(), "unreadable");
        };
        match sensitive_scan_inner(&entry.path(), budget) {
            SensitiveScan::Clean => {}
            other => return other,
        }
    }
    SensitiveScan::Clean
}

/// Is `path`, or any ancestor of it strictly below `home`, a symlink? Returns
/// the first offending component. Checked per-component with `symlink_metadata`
/// so nothing is ever resolved through a link. `home` itself and everything
/// above it (/, /Users) are the OS's and are not attacker-controlled, so they
/// are not policed; callers pass a canonical `home` and a path rebased onto it.
pub fn symlinked_component(path: &Path, home: &Path) -> Option<PathBuf> {
    let mut prefix = PathBuf::new();
    let mut offender = None;
    for component in path.components() {
        prefix.push(component);
        if !prefix.starts_with(home) || prefix == home {
            continue;
        }
        if let Ok(md) = std::fs::symlink_metadata(&prefix) {
            if md.file_type().is_symlink() {
                offender = Some(prefix.clone());
                break;
            }
        }
    }
    offender
}

/// The unattended-delete gate. Returns the ordered checks; the caller requires
/// every one to pass. Mirrors `check::CheckStep` so both gates render and
/// serialize identically.
pub fn autonomous_gate(path: &Path, home: &Path) -> Vec<CheckStep> {
    let step = |name: &str, passed: bool, note: String| CheckStep {
        name: name.into(),
        passed,
        note,
    };
    let mut steps = Vec::new();

    // (0) A relative path has no $HOME prefix to check and would resolve against
    // the process cwd. Nothing below can reason about it.
    if !path.is_absolute() {
        steps.push(step(
            "absolute",
            false,
            format!("relative path: {}", path.display()),
        ));
        return steps;
    }

    // $HOME may itself sit behind a symlink (macOS /var -> /private/var, relocated
    // home folders). That link is the OS's, so compare everything against the
    // canonical home and rebase the candidate onto it; links BELOW home remain
    // the candidate's problem.
    let resolved_home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let rebased = match path.strip_prefix(home) {
        Ok(rest) => resolved_home.join(rest),
        Err(_) => path.to_path_buf(),
    };

    // (1) Symlink — the target itself and every ancestor under $HOME.
    match symlinked_component(&rebased, &resolved_home) {
        Some(bad) => steps.push(step(
            "symlink",
            false,
            format!("symlinked path component: {}", bad.display()),
        )),
        None => steps.push(step(
            "symlink",
            true,
            "no symlinked component below $HOME".into(),
        )),
    }

    // (2) Containment — resolve WITHOUT following the final component (it may not
    // survive to deletion) and require it strictly beneath the resolved $HOME.
    // A `.` or `..` component is refused outright: `$HOME/a/..` names `$HOME`,
    // and resolving only the parent would misread it as `$HOME/a`.
    let has_dot_component = rebased.components().any(|c| {
        matches!(
            c,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    });
    let resolved = if has_dot_component {
        None
    } else {
        rebased
            .parent()
            .and_then(|p| std::fs::canonicalize(p).ok())
            .zip(rebased.file_name())
            .map(|(p, name)| p.join(name))
    };
    match resolved {
        Some(r) if r.starts_with(&resolved_home) && r != resolved_home => steps.push(step(
            "containment",
            true,
            format!("resolves beneath {}", resolved_home.display()),
        )),
        Some(r) => steps.push(step(
            "containment",
            false,
            format!(
                "{} is not strictly beneath {}",
                r.display(),
                resolved_home.display()
            ),
        )),
        None => steps.push(step(
            "containment",
            false,
            "path has a `.`/`..` component or its parent could not be resolved".into(),
        )),
    }

    // (3) Cloud-synced — a local delete propagates to every other device.
    let provider = crate::core::cloud::detect_provider(path);
    if provider == crate::core::cloud::CloudProvider::None {
        steps.push(step(
            "cloud-sync",
            true,
            "not under a cloud sync root".into(),
        ));
    } else {
        steps.push(step(
            "cloud-sync",
            false,
            format!("under a {} sync root — deleting propagates", provider),
        ));
    }

    // (4) Content — weights, patches, source, credentials.
    match sensitive_scan(path, AUTONOMOUS_SCAN_CAP) {
        SensitiveScan::Clean => steps.push(step(
            "protected-content",
            true,
            "no weights, patches, source or credentials found".into(),
        )),
        SensitiveScan::Found(p, reason) => steps.push(step(
            "protected-content",
            false,
            format!("{} at {}", reason, p.display()),
        )),
        SensitiveScan::Inconclusive => steps.push(step(
            "protected-content",
            false,
            format!(
                "too large to verify within {} entries — refused (fail-closed)",
                AUTONOMOUS_SCAN_CAP
            ),
        )),
    }

    steps
}

/// Did every check in [`autonomous_gate`] pass?
pub fn autonomous_gate_passed(steps: &[CheckStep]) -> bool {
    steps.iter().all(|s| s.passed)
}

#[cfg(test)]
mod autonomous_tests {
    use super::*;

    /// A relative candidate path has no `$HOME` prefix to check and would be
    /// resolved against the process cwd. Refused before any other step.
    #[test]
    fn relative_path_is_refused() {
        let home = std::env::temp_dir();
        let steps = autonomous_gate(Path::new("Library/Caches/x"), &home);
        assert!(!autonomous_gate_passed(&steps));
        assert_eq!(steps[0].name, "absolute");
        assert!(!steps[0].passed);
    }

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "diskspace-autogate-{}-{}-{}",
                tag,
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            std::fs::create_dir_all(&p).unwrap();
            // Resolve so comparisons are not defeated by /var -> /private/var.
            Self(std::fs::canonicalize(&p).unwrap())
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn plain_cache(home: &Path) -> PathBuf {
        let p = home.join("Library/Caches/example");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("blob.tmp"), b"x").unwrap();
        p
    }

    #[test]
    fn plain_cache_passes_every_check() {
        let home = Tmp::new("ok");
        let p = plain_cache(&home.0);
        let steps = autonomous_gate(&p, &home.0);
        assert!(
            autonomous_gate_passed(&steps),
            "expected pass, got {:?}",
            steps
        );
    }

    #[test]
    fn symlinked_candidate_is_refused() {
        let home = Tmp::new("symlink");
        let real = home.0.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = home.0.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let steps = autonomous_gate(&link, &home.0);
        assert!(!autonomous_gate_passed(&steps));
        assert!(steps.iter().any(|s| s.name == "symlink" && !s.passed));
    }

    /// The TOCTOU shape: the candidate's own name is fine, but a PARENT was
    /// swapped for a symlink after the scan.
    #[test]
    fn symlinked_ancestor_is_refused() {
        let home = Tmp::new("ancestor");
        let real = home.0.join("elsewhere/cache");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(home.0.join("elsewhere"), home.0.join("Library")).unwrap();
        let steps = autonomous_gate(&home.0.join("Library/cache"), &home.0);
        assert!(!autonomous_gate_passed(&steps));
        assert!(steps.iter().any(|s| s.name == "symlink" && !s.passed));
    }

    #[test]
    fn path_outside_home_is_refused() {
        let home = Tmp::new("outside");
        let other = Tmp::new("other");
        let p = plain_cache(&other.0);
        let steps = autonomous_gate(&p, &home.0);
        assert!(!autonomous_gate_passed(&steps));
        assert!(steps.iter().any(|s| s.name == "containment" && !s.passed));
    }

    #[test]
    fn home_itself_is_refused() {
        let home = Tmp::new("selfhome");
        let steps = autonomous_gate(&home.0, &home.0);
        assert!(steps.iter().any(|s| s.name == "containment" && !s.passed));
    }

    /// Generic cloud detection, not a hardcoded personal path: a `.dropbox`
    /// marker at an ancestor is the structural signal.
    #[test]
    fn cloud_synced_candidate_is_refused() {
        let home = Tmp::new("cloud");
        let root = home.0.join("SomeSyncRoot");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".dropbox"), b"").unwrap();
        let p = root.join("project/cache");
        std::fs::create_dir_all(&p).unwrap();
        let steps = autonomous_gate(&p, &home.0);
        assert!(!autonomous_gate_passed(&steps));
        assert!(steps.iter().any(|s| s.name == "cloud-sync" && !s.passed));
    }

    #[test]
    fn model_weights_patches_source_and_credentials_are_refused() {
        for (tag, build, reason) in [
            (
                "weights",
                &(|p: &Path| std::fs::write(p.join("model.safetensors"), b"w").unwrap())
                    as &dyn Fn(&Path),
                "model-weights",
            ),
            (
                "patch",
                &(|p: &Path| std::fs::write(p.join("fix.patch"), b"d").unwrap()) as &dyn Fn(&Path),
                "unique-patch",
            ),
            (
                "source",
                &(|p: &Path| std::fs::create_dir_all(p.join("repo/.git")).unwrap())
                    as &dyn Fn(&Path),
                "version-controlled-source",
            ),
            (
                "creds",
                &(|p: &Path| std::fs::write(p.join(".env"), b"K=V").unwrap()) as &dyn Fn(&Path),
                "credentials",
            ),
        ] {
            let home = Tmp::new(tag);
            let p = plain_cache(&home.0);
            build(&p);
            let steps = autonomous_gate(&p, &home.0);
            assert!(
                !autonomous_gate_passed(&steps),
                "{} must be refused",
                reason
            );
            let note = steps
                .iter()
                .find(|s| s.name == "protected-content")
                .map(|s| s.note.clone())
                .unwrap_or_default();
            assert!(note.contains(reason), "{} not in note: {}", reason, note);
        }
    }

    /// A small `.bin` is ordinary cache content; a large one is treated as a
    /// weight shard.
    #[test]
    fn bin_files_are_size_discriminated() {
        let small = Path::new("/tmp/thing.bin");
        assert_eq!(sensitive_file_reason(small, 1024), None);
        assert_eq!(
            sensitive_file_reason(small, MODEL_WEIGHT_BIN_MIN_BYTES),
            Some("model-weights")
        );
    }

    #[test]
    fn exhausted_budget_fails_closed() {
        let home = Tmp::new("budget");
        let p = plain_cache(&home.0);
        assert_eq!(sensitive_scan(&p, 0), SensitiveScan::Inconclusive);
    }

    /// `$HOME/a/..` names `$HOME` itself. Resolving only the parent and then
    /// re-appending a (missing) file name must not turn that into `$HOME/a`.
    #[test]
    fn trailing_dotdot_is_refused() {
        let home = Tmp::new("dotdot");
        let p = plain_cache(&home.0);
        let steps = autonomous_gate(&p.join(".."), &home.0);
        assert!(
            steps.iter().any(|s| s.name == "containment" && !s.passed),
            "expected containment refusal, got {:?}",
            steps
        );
    }

    /// Git worktrees and submodules carry `.git` as a FILE (`gitdir: ...`), and
    /// are just as much active source as a `.git` directory.
    #[test]
    fn git_file_marks_worktree_as_source() {
        let home = Tmp::new("gitfile");
        let p = plain_cache(&home.0);
        std::fs::create_dir_all(p.join("wt")).unwrap();
        std::fs::write(p.join("wt/.git"), b"gitdir: /somewhere/.git/worktrees/wt\n").unwrap();
        let steps = autonomous_gate(&p, &home.0);
        let note = steps
            .iter()
            .find(|s| s.name == "protected-content")
            .map(|s| s.note.clone())
            .unwrap_or_default();
        assert!(
            note.contains("version-controlled-source"),
            "expected source refusal, got {:?}",
            steps
        );
    }

    /// Core ML models are bundle DIRECTORIES, so the weight suffix has to be
    /// honored on directory names too.
    #[test]
    fn mlpackage_bundle_is_model_weights() {
        let home = Tmp::new("mlpackage");
        let p = plain_cache(&home.0);
        std::fs::create_dir_all(p.join("Model.mlpackage/Data")).unwrap();
        std::fs::write(p.join("Model.mlpackage/Data/weights"), b"w").unwrap();
        let steps = autonomous_gate(&p, &home.0);
        let note = steps
            .iter()
            .find(|s| s.name == "protected-content")
            .map(|s| s.note.clone())
            .unwrap_or_default();
        assert!(
            note.contains("model-weights"),
            "expected weights refusal, got {:?}",
            steps
        );
    }

    /// A `$HOME` that is itself reached through a symlink (macOS `/var` ->
    /// `/private/var`, relocated home folders) is the OS's business, not an
    /// attacker's. The gate must police components BELOW home, not home itself.
    #[test]
    fn symlinked_home_root_is_not_an_offender() {
        let real = Tmp::new("realhome");
        let parent = Tmp::new("linkparent");
        let link_home = parent.0.join("home");
        std::os::unix::fs::symlink(&real.0, &link_home).unwrap();
        let p = plain_cache(&real.0);
        let via_link = link_home.join(p.strip_prefix(&real.0).unwrap());
        let steps = autonomous_gate(&via_link, &link_home);
        assert!(
            autonomous_gate_passed(&steps),
            "expected pass through symlinked home, got {:?}",
            steps
        );
    }
}

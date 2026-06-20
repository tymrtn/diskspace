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

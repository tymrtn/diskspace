//! `diskspace selfcheck --measurement` — the P1 measurement-layer runtime gate.
//!
//! The exhaustive correctness proofs for the measurement layer live in the unit
//! tests (`series.rs`, `metrics.rs`, `scanner.rs`). This command is the
//! *runtime* counterpart: it re-verifies the load-bearing invariants (G1–G7)
//! against a **throwaway TEMP scratch dir**, never the real `~/.diskspace`, and
//! never mutates any user data. It is read-only with respect to the user's
//! store: every series/df/tick file it writes lands under a unique tempdir that
//! is removed on the way out.
//!
//! Output: JSON by default (an array of `{criterion, pass, detail}` plus an
//! `overall_pass`), or a compact human summary when `--json` is not set.
//!
//! LOCKED INVARIANTS this gate guards (it asserts them, it does not relax them):
//!   * never sudo; `$HOME`-scoped; all state under `~/.diskspace` via
//!     `profile::data_dir()`; no network/privilege APIs (G6).
//!   * metrics are ADVISORY ONLY — a df divergence is a note, never a trigger to
//!     widen a scan (`widened_to_full` stays false) (G3).

use anyhow::Result;
use chrono::Utc;
use console::Style;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::core::metrics;
use crate::core::scanner::{self, RegistryEntry, TickState, TICK_STATE_SCHEMA};
use crate::core::series::{self, ObsKey, Observation, Source};
use crate::output::Context;

/// One G-criterion result.
#[derive(Debug, Serialize)]
pub(crate) struct Criterion {
    criterion: String,
    pass: bool,
    detail: String,
}

impl Criterion {
    fn pass(id: &str, detail: impl Into<String>) -> Self {
        Self {
            criterion: id.to_string(),
            pass: true,
            detail: detail.into(),
        }
    }
    fn fail(id: &str, detail: impl Into<String>) -> Self {
        Self {
            criterion: id.to_string(),
            pass: false,
            detail: detail.into(),
        }
    }
}

/// A unique throwaway scratch dir under the OS temp dir, removed on drop. The
/// gate writes ALL of its series/df/tick scratch here so the real `~/.diskspace`
/// is never touched.
struct Scratch {
    path: PathBuf,
}
impl Scratch {
    fn new() -> Result<Self> {
        // Unique even when two gate runs share a pid and land on the same nanos
        // tick (parallel test threads): a process-global atomic counter
        // disambiguates. Prevents one run's Drop from deleting another's files.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "diskspace-selfcheck-{}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0),
            seq
        ));
        std::fs::create_dir_all(&p)?;
        Ok(Self { path: p })
    }
    /// A unique subdir under the scratch root (so e.g. a series base and a
    /// scanned tree never overlap).
    fn sub(&self, name: &str) -> Result<PathBuf> {
        let d = self.path.join(name);
        std::fs::create_dir_all(&d)?;
        Ok(d)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub fn run(measurement: bool, ctx: &Context) -> Result<()> {
    if !measurement {
        if ctx.json {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "error": "selfcheck requires --measurement",
                    "hint": "run `diskspace selfcheck --measurement`",
                }))?
            );
        } else {
            println!();
            println!("  selfcheck: pass --measurement to run the P1 measurement gate.");
            println!("  e.g.  diskspace selfcheck --measurement");
            println!();
        }
        return Ok(());
    }

    let results = run_measurement_gate();
    let overall = results.iter().all(|c| c.pass);
    emit(&results, overall, ctx)?;

    if !overall {
        // Non-zero exit so CI / agents can gate on it.
        std::process::exit(1);
    }
    Ok(())
}

/// Run G1–G7 against a throwaway scratch dir and collect their results. Each
/// criterion is independent: a panic-free failure is recorded as a failing
/// `Criterion` rather than aborting the whole gate, so one red line still shows
/// the others' status.
pub(crate) fn run_measurement_gate() -> Vec<Criterion> {
    let scratch = match Scratch::new() {
        Ok(s) => s,
        Err(e) => {
            return vec![Criterion::fail(
                "G0",
                format!("could not create temp scratch dir: {e}"),
            )]
        }
    };

    vec![
        g1_provenance_confidence(&scratch),
        g2_rollups_recomputable(&scratch),
        g3_in_place_growth(&scratch),
        g4_tombstone_rename_continuity(&scratch),
        g5_lock_no_torn(&scratch),
        g6_home_scope_no_sudo(),
        g7_cost_budget(&scratch),
    ]
}

// ---------------------------------------------------------------------------
// G1 — provenance / confidence weighting (Full > Restat > Incremental), monotonic.
// ---------------------------------------------------------------------------

fn g1_provenance_confidence(scratch: &Scratch) -> Criterion {
    let id = "G1";
    let base = match scratch.sub("g1") {
        Ok(b) => b,
        Err(e) => return Criterion::fail(id, format!("scratch: {e}")),
    };

    // Three single-source temp series, each at its own path. metric_confidence is
    // path-scoped, so isolate each source on its own path. With exactly
    // MIN_SAMPLES samples per path the count-damp is 1.0, so confidence equals
    // the source weight.
    let n = metrics::MIN_SAMPLES;
    let mut obs = Vec::new();
    for (path, src) in [
        ("/sc/full", Source::Full),
        ("/sc/restat", Source::Restat),
        ("/sc/incr", Source::Incremental),
    ] {
        for i in 0..n {
            obs.push(Observation::new(
                ObsKey::Path(PathBuf::from(path)),
                PathBuf::from(path),
                (i as u64 + 1) * 100,
                src,
                "selfcheck-g1",
                Utc::now(),
                None,
            ));
        }
    }
    if let Err(e) = series::append_batch_in_base(&base, &obs) {
        return Criterion::fail(id, format!("seeding series failed: {e}"));
    }

    let all = match series::read_all_in_pub(&base) {
        Ok(a) => a,
        Err(e) => return Criterion::fail(id, format!("read series failed: {e}")),
    };
    let c_full = metrics::metric_confidence(&PathBuf::from("/sc/full"), &all);
    let c_restat = metrics::metric_confidence(&PathBuf::from("/sc/restat"), &all);
    let c_incr = metrics::metric_confidence(&PathBuf::from("/sc/incr"), &all);

    // Documented weighting: damp == 1.0 at MIN_SAMPLES, so each equals its weight.
    let eq = |a: f32, b: f32| (a - b).abs() < 1e-6;
    let weights_ok = eq(c_full, metrics::WEIGHT_FULL)
        && eq(c_restat, metrics::WEIGHT_RESTAT)
        && eq(c_incr, metrics::WEIGHT_INCREMENTAL);
    // Strict provenance monotonicity: Full > Restat > Incremental.
    let monotonic = c_full > c_restat && c_restat > c_incr;

    if weights_ok && monotonic {
        Criterion::pass(
            id,
            format!(
                "confidence matches documented weighting and is monotonic \
                 (Full={c_full:.2} > Restat={c_restat:.2} > Incremental={c_incr:.2})"
            ),
        )
    } else {
        Criterion::fail(
            id,
            format!(
                "weighting/monotonicity mismatch: Full={c_full:.4} (want {:.4}), \
                 Restat={c_restat:.4} (want {:.4}), Incremental={c_incr:.4} (want {:.4})",
                metrics::WEIGHT_FULL,
                metrics::WEIGHT_RESTAT,
                metrics::WEIGHT_INCREMENTAL
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// G2 — rollups recomputable + idempotent; high-water respected.
// ---------------------------------------------------------------------------

fn g2_rollups_recomputable(scratch: &Scratch) -> Criterion {
    let id = "G2";
    let base = match scratch.sub("g2") {
        Ok(b) => b,
        Err(e) => return Criterion::fail(id, format!("scratch: {e}")),
    };

    // Two finalizable days for two keys + an open current day.
    fn day(y: i32, mo: u32, d: u32, h: u32) -> chrono::DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(y, mo, d, h, 0, 0).unwrap()
    }
    fn obs(path: &str, bytes: u64, when: chrono::DateTime<Utc>) -> Observation {
        Observation::new(
            ObsKey::Path(PathBuf::from(path)),
            PathBuf::from(path),
            bytes,
            Source::Full,
            "selfcheck-g2",
            when,
            None,
        )
    }
    let batch = vec![
        obs("/a", 100, day(2026, 6, 1, 8)),
        obs("/b", 250, day(2026, 6, 1, 9)),
        obs("/a", 300, day(2026, 6, 1, 20)),
        obs("/a", 500, day(2026, 6, 2, 9)),
        obs("/b", 700, day(2026, 6, 2, 10)),
        obs("/a", 999, day(2026, 6, 3, 1)), // open day → not finalized
    ];
    if let Err(e) = series::append_batch_in_base(&base, &batch) {
        return Criterion::fail(id, format!("seeding series failed: {e}"));
    }

    let daily = series::daily_path_in_base(&base);
    let hw = series::rollup_hw_path_in_base(&base);

    // First rollup.
    if let Err(e) = series::rollup_daily_in_base(&base) {
        return Criterion::fail(id, format!("rollup #1 failed: {e}"));
    }
    let daily1 = std::fs::read(&daily).unwrap_or_default();
    let hw1 = std::fs::read(&hw).unwrap_or_default();

    // Idempotent: a second rollup with no new data must be byte-identical and
    // leave the high-water mark untouched.
    if let Err(e) = series::rollup_daily_in_base(&base) {
        return Criterion::fail(id, format!("rollup #2 failed: {e}"));
    }
    let daily2 = std::fs::read(&daily).unwrap_or_default();
    let hw2 = std::fs::read(&hw).unwrap_or_default();
    if daily1 != daily2 || hw1 != hw2 {
        return Criterion::fail(id, "re-running the rollup was NOT idempotent");
    }

    // Recomputable: delete derived state, recompute purely from raw → identical.
    let _ = std::fs::remove_file(&daily);
    let _ = std::fs::remove_file(&hw);
    if let Err(e) = series::rollup_daily_in_base(&base) {
        return Criterion::fail(id, format!("recompute rollup failed: {e}"));
    }
    let daily3 = std::fs::read(&daily).unwrap_or_default();
    if daily1 != daily3 {
        return Criterion::fail(id, "rollup is NOT fully recomputable from raw series");
    }

    Criterion::pass(
        id,
        "rollup_daily is idempotent and byte-identical when recomputed from raw \
         (high-water mark respected)",
    )
}

// ---------------------------------------------------------------------------
// G3 — in-place growth caught by Tier B; df divergence stays ADVISORY.
// ---------------------------------------------------------------------------

fn g3_in_place_growth(scratch: &Scratch) -> Criterion {
    let id = "G3";
    #[cfg(not(unix))]
    {
        let _ = scratch;
        return Criterion::pass(id, "skipped on non-unix (Tier B re-stat is unix-keyed)");
    }
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::MetadataExt;

        let base = match scratch.sub("g3-base") {
            Ok(b) => b,
            Err(e) => return Criterion::fail(id, format!("scratch: {e}")),
        };
        let tree = match scratch.sub("g3-tree") {
            Ok(t) => t,
            Err(e) => return Criterion::fail(id, format!("scratch: {e}")),
        };

        // A registered file ~8 KiB so it occupies real blocks.
        let f = tree.join("big.bin");
        if let Err(e) = std::fs::write(&f, vec![b'x'; 8 * 1024]) {
            return Criterion::fail(id, format!("write file: {e}"));
        }
        let md = match std::fs::symlink_metadata(&f) {
            Ok(m) => m,
            Err(e) => return Criterion::fail(id, format!("stat file: {e}")),
        };
        let (dev, ino, ctime, ctime_nsec) = (md.dev(), md.ino(), md.ctime(), md.ctime_nsec());
        let bytes0 = md.blocks() * 512;

        let now = Utc::now();
        // Seed the dir-mtime cache with the tree's CURRENT mtime so Tier A's fast
        // path fires (sees "no churn") and SKIPS the subtree — the growth is then
        // invisible to A and must be caught by B's direct re-stat. last_full_walk
        // = now so NO daily true-up fires (we want the incremental path).
        let tree_mtime = std::fs::symlink_metadata(&tree)
            .map(|m| m.mtime())
            .unwrap_or(0);
        let mut dir_mtimes = HashMap::new();
        dir_mtimes.insert(tree.clone(), (tree_mtime, bytes0));
        let prior = TickState {
            schema: TICK_STATE_SCHEMA,
            last_full_walk: now,
            dir_mtimes,
            registry: vec![RegistryEntry {
                dev,
                ino,
                ctime,
                ctime_nsec,
                path: f.clone(),
                bytes: bytes0,
                last_stat: now,
            }],
            last_df_free: 0,
        };

        // Grow the file IN PLACE (append). This does not bump the parent dir's
        // mtime, so Tier A is blind to it.
        {
            let mut g = match std::fs::OpenOptions::new().append(true).open(&f) {
                Ok(g) => g,
                Err(e) => return Criterion::fail(id, format!("open for append: {e}")),
            };
            if let Err(e) = g.write_all(&vec![b'y'; 120 * 1024]).and_then(|_| g.flush()) {
                return Criterion::fail(id, format!("grow file: {e}"));
            }
        }
        let bytes1 = std::fs::symlink_metadata(&f)
            .map(|m| m.blocks() * 512)
            .unwrap_or(bytes0);
        if bytes1 <= bytes0 {
            return Criterion::fail(id, "file did not grow on disk — test setup invalid");
        }

        let out = match scanner::tick_in_base(&base, &tree, &[], &prior, now) {
            Ok(o) => o,
            Err(e) => return Criterion::fail(id, format!("tick failed: {e}")),
        };

        // Tier B must emit a Restat for the grown file at its new size.
        let restat_ok = out
            .observations
            .iter()
            .any(|o| o.source == Source::Restat && o.path == f && o.bytes == bytes1);
        // LOCKED INVARIANT: df divergence is advisory only — it must NEVER widen
        // the scan to a full walk on the incremental path.
        let advisory_only = !out.widened_to_full;

        if restat_ok && advisory_only {
            Criterion::pass(
                id,
                format!(
                    "Tier B Restat caught in-place growth ({}→{} bytes); \
                     df divergence stayed ADVISORY (widened_to_full=false)",
                    bytes0, bytes1
                ),
            )
        } else if !restat_ok {
            Criterion::fail(id, "Tier B did NOT emit a Restat for the grown file")
        } else {
            Criterion::fail(
                id,
                "INVARIANT VIOLATION: df divergence widened the scan to a full walk",
            )
        }
    }
}

// ---------------------------------------------------------------------------
// G4 — tombstone / rename continuity: rename = one Tombstone + re-observation
// under the SAME (dev, ino) key; metrics treat it as continuity.
// ---------------------------------------------------------------------------

fn g4_tombstone_rename_continuity(scratch: &Scratch) -> Criterion {
    let id = "G4";
    let base = match scratch.sub("g4") {
        Ok(b) => b,
        Err(e) => return Criterion::fail(id, format!("scratch: {e}")),
    };

    // Model a rename: same (dev, ino) observed at /old then /new. The continuity
    // key is (dev, ino) ONLY, so the renamed file is ONE series (the ctime bump a
    // rename causes must NOT fork it). We also write a Tombstone for a *separate*
    // vanished identity to prove tombstones round-trip.
    let dev = 16777220u64;
    let ino = 99u64;
    let key_old = ObsKey::for_entry(Some(dev), Some(ino), &PathBuf::from("/old"));
    let key_new = ObsKey::for_entry(Some(dev), Some(ino), &PathBuf::from("/new"));

    // Crux: rename keeps the SAME continuity key.
    if key_old != key_new {
        return Criterion::fail(id, "rename did not preserve the (dev, ino) continuity key");
    }
    // A forward ctime bump (what a rename causes) must NOT be read as inode reuse.
    let ctime_before = 1_700_000_000_000_000_000i64;
    let ctime_after = 1_700_000_005_000_000_000i64;
    if series::inode_reused(Some(ctime_before), Some(ctime_after)) {
        return Criterion::fail(id, "rename's forward ctime bump was misread as inode reuse");
    }

    let o_old = Observation::new(
        key_old.clone(),
        PathBuf::from("/old"),
        1000,
        Source::Full,
        "selfcheck-g4-1",
        Utc::now(),
        Some(ctime_before),
    );
    let o_new = Observation::new(
        key_new.clone(),
        PathBuf::from("/new"),
        1000,
        Source::Restat,
        "selfcheck-g4-2",
        Utc::now(),
        Some(ctime_after),
    );
    // A tombstone for a DIFFERENT (vanished) inode.
    let tomb = Observation {
        v: series::SERIES_SCHEMA,
        ts: Utc::now(),
        key: ObsKey::Inode { dev, ino: 7777 },
        path: PathBuf::from("/gone"),
        bytes: 0,
        source: Source::Tombstone,
        scan_id: "selfcheck-g4-tomb".into(),
        ctime: None,
    };
    if let Err(e) = series::append_batch_in_base(&base, &[o_old, o_new, tomb]) {
        return Criterion::fail(id, format!("seeding series failed: {e}"));
    }

    let all = match series::read_all_in_pub(&base) {
        Ok(a) => a,
        Err(e) => return Criterion::fail(id, format!("read series failed: {e}")),
    };

    // The renamed identity collapses to ONE continuity key with NO tombstone.
    let rename_obs: Vec<&Observation> = all.iter().filter(|o| o.key == key_old).collect();
    let one_series =
        rename_obs.len() == 2 && rename_obs.iter().all(|o| o.source != Source::Tombstone);
    let tombstone_present = all
        .iter()
        .any(|o| o.source == Source::Tombstone && o.key == ObsKey::Inode { dev, ino: 7777 });

    if one_series && tombstone_present {
        Criterion::pass(
            id,
            "rename stayed ONE continuous (dev, ino) series (no spurious tombstone); \
             a separate vanished identity round-tripped as a Tombstone",
        )
    } else if !one_series {
        Criterion::fail(id, "rename did NOT read as one continuous series")
    } else {
        Criterion::fail(id, "tombstone marker did not round-trip")
    }
}

// ---------------------------------------------------------------------------
// G5 — lock / no torn: concurrent appends from 2 threads, all lines parse.
// ---------------------------------------------------------------------------

fn g5_lock_no_torn(scratch: &Scratch) -> Criterion {
    let id = "G5";
    let base = match scratch.sub("g5") {
        Ok(b) => b,
        Err(e) => return Criterion::fail(id, format!("scratch: {e}")),
    };

    let threads = 2;
    let per_thread = 60; // 2 * 60 = 120 lines (>= 100)
    let base = std::sync::Arc::new(base);
    let mut handles = Vec::new();
    for t in 0..threads {
        let base = std::sync::Arc::clone(&base);
        handles.push(std::thread::spawn(move || -> Result<()> {
            let batch: Vec<Observation> = (0..per_thread)
                .map(|i| {
                    Observation::new(
                        ObsKey::Path(PathBuf::from(format!("/t{t}/i{i}"))),
                        PathBuf::from(format!("/t{t}/i{i}")),
                        (t * 1000 + i) as u64,
                        Source::Full,
                        "selfcheck-g5",
                        Utc::now(),
                        None,
                    )
                })
                .collect();
            series::append_batch_in_base(&base, &batch)
        }));
    }
    for h in handles {
        match h.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Criterion::fail(id, format!("append thread errored: {e}")),
            Err(_) => return Criterion::fail(id, "append thread panicked"),
        }
    }

    let expected = threads * per_thread;
    // Raw line count: no lines lost / torn under the lock.
    let raw = std::fs::read_to_string(series::series_path_in_base(&base)).unwrap_or_default();
    let raw_lines = raw.lines().filter(|l| !l.trim().is_empty()).count();
    // Parsed count: every line is well-formed (no interleaving).
    let parsed = match series::read_all_in_pub(&base) {
        Ok(p) => p.len(),
        Err(e) => return Criterion::fail(id, format!("read series failed: {e}")),
    };

    if raw_lines == expected && parsed == expected {
        Criterion::pass(
            id,
            format!("{expected} concurrent appends all parsed — exclusive lock prevented torn/interleaved lines"),
        )
    } else {
        Criterion::fail(
            id,
            format!("expected {expected} lines, got raw={raw_lines} parsed={parsed}"),
        )
    }
}

// ---------------------------------------------------------------------------
// G6 — $HOME-scope / no-sudo. Path helpers resolve under data_dir(); the
// measurement layer references no sudo / privilege-escalation call.
// ---------------------------------------------------------------------------

fn g6_home_scope_no_sudo() -> Criterion {
    let id = "G6";
    let data = crate::profile::data_dir();

    // Every measurement-layer persisted path must live under data_dir() (→ $HOME).
    let paths = [
        ("series", series::series_path()),
        ("series.daily", series::daily_path()),
        ("series.rollup.hw", series::rollup_hw_path()),
        ("df_series", metrics::df_series_path()),
        ("tick_state", scanner::tick_state_path()),
        ("history", crate::core::history::history_path()),
    ];
    for (name, p) in &paths {
        if !p.starts_with(&data) {
            return Criterion::fail(
                id,
                format!(
                    "{name} path {} does not resolve under data_dir() {}",
                    p.display(),
                    data.display()
                ),
            );
        }
    }

    // Static guard: the measurement-layer sources must reference no
    // privilege-escalation call. We scan the COMMITTED source text (include_str!)
    // for invocation patterns — not the word "sudo" in a doc comment. A future
    // edit that shells out to sudo / flips the uid turns this red.
    let series_src = include_str!("../core/series.rs");
    let metrics_src = include_str!("../core/metrics.rs");
    let escalation = [
        "Command::new(\"sudo\")",
        "\"/usr/bin/sudo\"",
        "setuid",
        "seteuid",
        "geteuid",
        "CommandExt",
    ];
    for src_name in [("series.rs", series_src), ("metrics.rs", metrics_src)] {
        for pat in &escalation {
            if src_name.1.contains(pat) {
                return Criterion::fail(
                    id,
                    format!(
                        "PRIVILEGE/ SUDO REFERENCE in {}: `{}` — the measurement layer must use \
                         no privilege-escalation APIs",
                        src_name.0, pat
                    ),
                );
            }
        }
    }

    Criterion::pass(
        id,
        format!(
            "all 6 measurement paths resolve under data_dir() ({}); sources reference \
             no sudo/privilege call",
            data.display()
        ),
    )
}

// ---------------------------------------------------------------------------
// G7 — cost budget: a pruned incremental tick over a seeded tree completes
// under a small time budget. (The ~40s full-walk is NOTED, not run.)
// ---------------------------------------------------------------------------

fn g7_cost_budget(scratch: &Scratch) -> Criterion {
    let id = "G7";
    let base = match scratch.sub("g7-base") {
        Ok(b) => b,
        Err(e) => return Criterion::fail(id, format!("scratch: {e}")),
    };
    let tree = match scratch.sub("g7-tree") {
        Ok(t) => t,
        Err(e) => return Criterion::fail(id, format!("scratch: {e}")),
    };

    // Seed a small tree: a handful of dirs each with a few files.
    for d in 0..5 {
        let sub = tree.join(format!("d{d}"));
        if std::fs::create_dir_all(&sub).is_err() {
            return Criterion::fail(id, "could not seed tree");
        }
        for fi in 0..5 {
            let _ = std::fs::write(sub.join(format!("f{fi}.bin")), vec![b'x'; 4096]);
        }
    }

    // Incremental path: last_full_walk = now (within 24h, so NO full true-up).
    // Empty dir-mtime cache forces Tier A to walk the (small) tree once — exactly
    // the pruned-tick cost we are budgeting.
    let now = Utc::now();
    let prior = TickState {
        schema: TICK_STATE_SCHEMA,
        last_full_walk: now,
        dir_mtimes: HashMap::new(),
        registry: Vec::new(),
        last_df_free: 0,
    };

    let start = std::time::Instant::now();
    let out = scanner::tick_in_base(&base, &tree, &[], &prior, now);
    let elapsed = start.elapsed();

    if let Err(e) = out {
        return Criterion::fail(id, format!("tick failed: {e}"));
    }
    let out = out.unwrap();
    if out.widened_to_full {
        return Criterion::fail(
            id,
            "expected an incremental tick, but it widened to a full walk",
        );
    }

    // Budget: a pruned tick over a tiny temp tree must finish well under 2s. The
    // production ~40s full walk of ~589k entries is the DAILY true-up — noted
    // here, never run by this gate.
    let budget = std::time::Duration::from_secs(2);
    if elapsed < budget {
        Criterion::pass(
            id,
            format!(
                "pruned incremental tick over the seeded tree completed in {:?} (< {:?} budget); \
                 the ~40s full-walk true-up is noted, not run",
                elapsed, budget
            ),
        )
    } else {
        Criterion::fail(
            id,
            format!(
                "pruned tick took {:?}, over the {:?} budget",
                elapsed, budget
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn emit(results: &[Criterion], overall: bool, ctx: &Context) -> Result<()> {
    if ctx.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "gate": "measurement",
                "overall_pass": overall,
                "criteria": results,
            }))?
        );
        return Ok(());
    }

    let green = Style::new().green().bold();
    let red = Style::new().red().bold();
    let bold = Style::new().bold();
    let dim = Style::new().dim();

    println!();
    println!("  {}  measurement gate (G1–G7)", ctx.style("·", &dim));
    println!();
    for c in results {
        let mark = if c.pass {
            ctx.style("PASS", &green)
        } else {
            ctx.style("FAIL", &red)
        };
        println!("    {}  {}", mark, ctx.style(&c.criterion, &bold));
        println!("          {}", ctx.style(&c.detail, &dim));
    }
    println!();
    if overall {
        println!("  {}  all criteria pass", ctx.style("✓", &green));
    } else {
        let n_fail = results.iter().filter(|c| !c.pass).count();
        println!(
            "  {}  {} of {} criteria FAILED",
            ctx.style("✗", &red),
            n_fail,
            results.len()
        );
    }
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On a healthy temp setup, the full G1–G7 gate returns overall pass and
    /// every criterion passes. This exercises the real seams (series append /
    /// rollup, metric_confidence, scanner::tick) against throwaway scratch dirs —
    /// the real `~/.diskspace` is never touched.
    #[test]
    fn measurement_gate_passes_on_healthy_setup() {
        let results = run_measurement_gate();
        assert_eq!(results.len(), 7, "G1–G7 = seven criteria");
        for c in &results {
            assert!(
                c.pass,
                "criterion {} failed in selfcheck: {}",
                c.criterion, c.detail
            );
        }
        assert!(results.iter().all(|c| c.pass), "overall pass");
    }

    /// Each criterion id appears exactly once, in order G1..G7.
    #[test]
    fn gate_emits_g1_through_g7_in_order() {
        let results = run_measurement_gate();
        let ids: Vec<&str> = results.iter().map(|c| c.criterion.as_str()).collect();
        assert_eq!(ids, ["G1", "G2", "G3", "G4", "G5", "G6", "G7"]);
    }

    /// Regression for finding-6: the measurement gate is READ-ONLY against the
    /// user's real `~/.diskspace`. It must write its series/df/tick scratch ONLY
    /// under its private temp dir — NEVER into `profile::data_dir()`.
    ///
    /// This guard is robust against the bug it targets: the old
    /// `series_append_batch` discarded its `base` in `#[cfg(not(test))]` and wrote
    /// to the real data dir, while the `#[cfg(test)]` branch correctly used `base`
    /// — so a test that merely seeded a tempdir could not observe the prod break.
    /// Here we point `$HOME` at a fresh tempdir so `data_dir()` resolves under it,
    /// run the FULL gate (which drives `tick_in_base` → `series_append_batch`), and
    /// assert NO measurement file ever appeared under that `$HOME`'s `.diskspace`.
    /// Because `series_append_batch` now honors `base` in EVERY build, the gate's
    /// scratch-base writes land in `/tmp/diskspace-selfcheck-*`, not here.
    #[test]
    fn gate_does_not_write_to_real_data_dir() {
        // `$HOME` is process-global; serialize the few tests that mutate it so
        // they don't race each other (or other tests reading `data_dir()`). This
        // is the SHARED crate-wide lock (also held by `doctor` and `watch`), so
        // overrides across modules are mutually exclusive.
        let _guard = crate::core::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // A fresh, empty fake-$HOME tempdir.
        let mut fake_home = std::env::temp_dir();
        fake_home.push(format!(
            "diskspace-selfcheck-home-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&fake_home).unwrap();

        let prev_home = std::env::var_os("HOME");
        // SAFETY: serialized by HOME_TEST_LOCK; restored before the guard drops.
        unsafe {
            std::env::set_var("HOME", &fake_home);
        }

        // Sanity: data_dir() now resolves under our fake $HOME.
        let data = crate::profile::data_dir();
        assert!(
            data.starts_with(&fake_home),
            "test precondition: data_dir() {} should be under fake $HOME {}",
            data.display(),
            fake_home.display()
        );

        let results = run_measurement_gate();

        // Restore $HOME before any assertion can unwind and leak the override.
        unsafe {
            match &prev_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }

        // The gate must have passed (otherwise the assertion below is moot).
        assert!(
            results.iter().all(|c| c.pass),
            "gate should pass on a healthy setup"
        );

        // The load-bearing assertion: the real data dir must be UNTOUCHED — none
        // of the measurement stores were created under the fake $HOME.
        for f in [
            "series.jsonl",
            "df_series.jsonl",
            "tick_state.json",
            "series.daily.jsonl",
        ] {
            let p = data.join(f);
            assert!(
                !p.exists(),
                "finding-6 regression: selfcheck wrote {} into the real data dir — \
                 it must write ONLY to its temp scratch base",
                p.display()
            );
        }

        let _ = std::fs::remove_dir_all(&fake_home);
    }
}

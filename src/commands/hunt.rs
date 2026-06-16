//! `diskspace hunt` — surfaces the largest directories that no rule covers.
//! The long-tail finder. Use this when `detect` looks empty but the disk is full.
//!
//! The fast path reads the existing `scan.json` cache (sub-second) instead of
//! re-walking $HOME on every invocation (the old behavior — minutes on a large
//! disk, and a silent hang in `--json`/non-TTY). For each of the largest
//! directories the scan already persisted, we subtract the bytes of the
//! rule-MATCHED entries underneath it; the remainder is the genuinely UNRULED
//! size. Because the matched entries were classified by the real glob rule engine
//! at scan time, this is glob-aware for free — it no longer mislabels every
//! `**/target` / `**/node_modules` hit as "unrule'd". A live walk is kept ONLY as
//! the fallback for a missing/stale cache or an explicit `--fresh`.

use anyhow::Result;
use chrono::{DateTime, Utc};
use console::Style;
use indicatif::{ProgressBar, ProgressStyle};
use jwalk::WalkDir;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::commands::scan::scan_cache_path;
use crate::core::candidate::ScannedEntry;
use crate::core::rules;
use crate::core::scanner::{expand_home, ScanResult};
use crate::output::{self, Context};

/// How old `scan.json` may be before `hunt` treats it as stale and falls back to
/// a fresh live walk. A day-old picture of the long tail is plenty fresh for
/// "what big directories has no rule claimed"; anything older risks pointing at
/// directories that have since been cleaned.
const CACHE_STALE_AFTER_HOURS: i64 = 24;

#[derive(Debug, Clone, Serialize)]
struct HuntCandidate {
    path: PathBuf,
    /// Genuinely-unruled bytes: total on-disk size minus the rule-matched bytes
    /// underneath. This is what `hunt` ranks and reports.
    unruled_bytes: u64,
    /// Total on-disk size of the directory (own files plus every descendant).
    /// Carried for context so a row can show "X unruled of Y total".
    total_bytes: u64,
    depth: usize,
}

pub fn run(top: usize, min_size_mb: u64, fresh: bool, ctx: &Context) -> Result<()> {
    let home = dirs_home();
    let rule_list = rules::load_builtin()?;
    let min_size = min_size_mb * 1024 * 1024;

    // Fast path: read the scan cache and subtract rule-matched bytes. Falls back
    // to a live walk when the cache is missing, stale, or `--fresh` is requested.
    let (chosen, from_cache) = if fresh {
        (
            hunt_fresh_walk(&home, &rule_list, min_size, top, ctx)?,
            false,
        )
    } else {
        match load_fresh_cache(Utc::now()) {
            Some(scan) => {
                let chosen = hunt_from_cache(&scan, &home, min_size, top);
                (chosen, true)
            }
            None => (
                hunt_fresh_walk(&home, &rule_list, min_size, top, ctx)?,
                false,
            ),
        }
    };

    render(&chosen, top, min_size_mb, from_cache, ctx)
}

/// Load `scan.json` only if it exists, parses, and is fresh enough. Returns `None`
/// (triggering the live-walk fallback) on any of: missing file, parse error, an
/// empty `largest_dirs` (a legacy cache from before Step A — it carries no
/// directory totals to subtract against), or a `scanned_at` older than
/// [`CACHE_STALE_AFTER_HOURS`].
fn load_fresh_cache(now: DateTime<Utc>) -> Option<ScanResult> {
    let cache = scan_cache_path();
    let content = std::fs::read_to_string(&cache).ok()?;
    let scan: ScanResult = serde_json::from_str(&content).ok()?;
    if scan.largest_dirs.is_empty() {
        // Legacy cache (pre-`largest_dirs`): nothing to subtract against, so fall
        // back to the live walk rather than report an empty hunt.
        return None;
    }
    let age_hours = now.signed_duration_since(scan.scanned_at).num_hours();
    if age_hours > CACHE_STALE_AFTER_HOURS {
        return None;
    }
    Some(scan)
}

/// A directory known to the hunt: its TOTAL on-disk bytes and its genuinely
/// UNRULED bytes (total minus the rule-matched bytes underneath). Both the cache
/// path and the live-walk fallback build a map of these and feed them through the
/// SAME [`drill_dir`] routine, so `hunt` and `hunt --fresh` give identical
/// landings (finding 3).
#[derive(Debug, Clone, Copy)]
struct DirStat {
    total_bytes: u64,
    unruled_bytes: u64,
}

/// The universe of directories the hunt can reason about: `path -> DirStat`,
/// pre-indexed so immediate-child lookups during the drill are cheap. Keyed by an
/// owned `PathBuf` so both the cache (`largest_dirs`) and the live walk (`HashMap`)
/// can populate it without lifetime gymnastics.
struct DirUniverse {
    stats: HashMap<PathBuf, DirStat>,
}

impl DirUniverse {
    /// Immediate child directories of `dir` that are present in the universe,
    /// returned with their stats. Order is unspecified; callers sort.
    fn immediate_children(&self, dir: &Path) -> Vec<(PathBuf, DirStat)> {
        self.stats
            .iter()
            .filter(|(p, _)| p.parent() == Some(dir))
            .map(|(p, s)| (p.clone(), *s))
            .collect()
    }
}

/// The cache-driven hunt core (pure; unit-tested directly).
///
/// For every persisted largest directory we compute its genuinely-UNRULED bytes
/// = `total_bytes − covered_bytes`, where `covered_bytes` is the sum of the
/// rule-matched entries contained under it (top-level matched entries only, to
/// mirror the scanner's own non-double-counting). Then we ADAPTIVELY DRILL via
/// [`drill_dir`]: when a directory's unruled bytes are concentrated in a FEW large
/// children, we descend and surface each big child as its own row instead of
/// reporting the coarse parent blob — turning a "397 GB Dropbox" parent into its
/// real "138 GB Clef + 60 GB BMI" unruled children.
fn hunt_from_cache(
    scan: &ScanResult,
    home: &Path,
    min_size: u64,
    top: usize,
) -> Vec<HuntCandidate> {
    // Top-level matched entries (a matched path not contained under ANOTHER
    // matched path); their `size_bytes` already aggregate descendants, so summing
    // only these under a dir never double-counts. Computed in O(n log n).
    let top_matched = top_level_matched(&scan.entries);

    // Covered bytes per persisted directory, accumulated in ONE pass over the
    // matched entries: add each top-level matched entry's bytes to every ancestor
    // directory present in the persisted set. O(matched × depth) — NOT the old
    // O(dirs × matched) per-dir scan that, combined with the O(n²) top-level pass,
    // hung for minutes on a real ~62k-entry scan.
    let dir_set: std::collections::HashSet<PathBuf> =
        scan.largest_dirs.iter().map(|d| d.path.clone()).collect();
    let mut covered: HashMap<PathBuf, u64> = HashMap::new();
    for e in &top_matched {
        for ancestor in e.path.ancestors() {
            if dir_set.contains(ancestor) {
                *covered.entry(ancestor.to_path_buf()).or_insert(0) += e.size_bytes;
            }
        }
    }

    // Build the shared directory universe from the persisted totals.
    let stats: HashMap<PathBuf, DirStat> = scan
        .largest_dirs
        .iter()
        .map(|d| {
            let cov = covered.get(&d.path).copied().unwrap_or(0);
            (
                d.path.clone(),
                DirStat {
                    total_bytes: d.total_bytes,
                    unruled_bytes: d.total_bytes.saturating_sub(cov),
                },
            )
        })
        .collect();
    let universe = DirUniverse { stats };

    collect_landings(&universe, home, min_size, top)
}

/// Shared landing selection (used by BOTH the cache path and the live-walk
/// fallback, finding 3). Seeds at the depth-1 directories under $HOME, drills each
/// into its concentrated unruled children, dedupes nested results, and returns the
/// top-N rows ranked by unruled bytes.
fn collect_landings(
    universe: &DirUniverse,
    home: &Path,
    min_size: u64,
    top: usize,
) -> Vec<HuntCandidate> {
    // Candidate seeds: depth-1 directories under $HOME present in the universe.
    // (Depth 0 is $HOME itself; we never report the whole home as one row.)
    let mut seeds: Vec<(PathBuf, DirStat)> = universe
        .stats
        .iter()
        .filter(|(p, _)| depth_from(p, home) == Some(1))
        .map(|(p, s)| (p.clone(), *s))
        .collect();
    seeds.sort_by(|a, b| b.1.unruled_bytes.cmp(&a.1.unruled_bytes));

    let mut chosen: Vec<HuntCandidate> = Vec::new();
    for (seed_path, seed_stat) in seeds {
        drill_dir(universe, &seed_path, seed_stat, home, min_size, &mut chosen);
    }

    chosen.sort_by(|a, b| b.unruled_bytes.cmp(&a.unruled_bytes));
    chosen.truncate(top);
    chosen
}

/// ADAPTIVE DRILL (findings 1 & 2). Descend from `dir`, surfacing the genuinely
/// unruled directories as rows pushed into `out`.
///
/// At each level we collect EVERY immediate child whose UNRULED bytes clear
/// `min_size` in ABSOLUTE terms — NOT as a fraction of the parent. That relative
/// gate was the bug (finding 1): `~/Dropbox/Clef` is only ~35% of a 397 GB Dropbox
/// yet is plainly the row worth showing. When a directory has such big children we
/// recurse into EACH of them, dropping the coarse parent row, so a single
/// `~/Dropbox` parent surfaces BOTH `Clef` (138 GB) AND `BMI` (60 GB) as their own
/// rows (finding 2) — and the descent is unbounded in depth, so it reaches
/// `Dropbox/Code/repo` when concentration holds all the way down. A directory is
/// kept as its OWN row only when it has NO child clearing the floor: its unruled
/// bytes are spread across many small dirs, so it is the finest actionable
/// granularity (no arbitrary child to drill into).
fn drill_dir(
    universe: &DirUniverse,
    dir: &Path,
    stat: DirStat,
    home: &Path,
    min_size: u64,
    out: &mut Vec<HuntCandidate>,
) {
    if stat.unruled_bytes < min_size {
        return;
    }

    // Big immediate children: those whose UNRULED bytes clear the floor, sorted
    // largest-unruled first so emitted rows come out biggest-first under a parent.
    let mut big_children: Vec<(PathBuf, DirStat)> = universe
        .immediate_children(dir)
        .into_iter()
        .filter(|(_, s)| s.unruled_bytes >= min_size)
        .collect();
    big_children.sort_by(|a, b| b.1.unruled_bytes.cmp(&a.1.unruled_bytes));

    if big_children.is_empty() {
        // No child concentrates enough unruled mass: this dir is the finest
        // actionable granularity. Emit it as the row.
        let depth = depth_from(dir, home).unwrap_or(1);
        out.push(HuntCandidate {
            path: dir.to_path_buf(),
            unruled_bytes: stat.unruled_bytes,
            total_bytes: stat.total_bytes,
            depth,
        });
        return;
    }

    // Recurse into each big child; the coarse parent is dropped in favor of its
    // concentrated children (each surfaced as its own row).
    for (child_path, child_stat) in big_children {
        drill_dir(universe, &child_path, child_stat, home, min_size, out);
    }
}

/// The top-level matched entries: a matched entry whose path is NOT contained
/// under any OTHER matched entry. Their `size_bytes` already aggregate their
/// descendants (the scanner patches directory entries with subtree totals), so
/// summing only these under a directory counts each matched byte exactly once.
fn top_level_matched(entries: &[ScannedEntry]) -> Vec<&ScannedEntry> {
    // After sorting by path, any ancestor precedes its descendants, so an entry is
    // a descendant of an already-kept top-level entry iff it `starts_with` the most
    // recently kept one. O(n log n) — the previous pairwise version was O(n²) and
    // hung for minutes on a real ~62k-entry scan.
    let mut es: Vec<&ScannedEntry> = entries.iter().filter(|e| e.size_bytes > 0).collect();
    es.sort_by(|a, b| a.path.cmp(&b.path));
    let mut out: Vec<&ScannedEntry> = Vec::new();
    let mut last_top: Option<&Path> = None;
    for e in es {
        match last_top {
            Some(lt) if e.path.starts_with(lt) => {} // descendant of a kept top-level
            _ => {
                out.push(e);
                last_top = Some(e.path.as_path());
            }
        }
    }
    out
}

// ===========================================================================
// Fallback: the live walk (slow). Used only for a missing/stale cache or
// `--fresh`. Preserves the pre-overhaul behavior, but now ALSO subtracts
// rule-matched bytes so the fallback is honest too.
// ===========================================================================

fn hunt_fresh_walk(
    home: &Path,
    rule_list: &[crate::core::rules::Rule],
    min_size: u64,
    top: usize,
    ctx: &Context,
) -> Result<Vec<HuntCandidate>> {
    // Build glob patterns for EVERY rule (concrete and globby alike), so the live
    // fallback is glob-aware just like the cache path — no more leaking `**/target`
    // back into "unrule'd".
    let patterns: Vec<glob::Pattern> = rule_list
        .iter()
        .filter_map(|r| glob::Pattern::new(&expand_home(&r.path_pattern, home)).ok())
        .collect();

    let spinner = if !ctx.json && !ctx.quiet {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb.set_message(format!(
            "Hunting in {} (no fresh scan cache)…",
            home.display()
        ));
        pb.enable_steady_tick(Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    // Walk once, accumulating per-directory TOTAL bytes and per-directory
    // rule-MATCHED bytes. The unruled remainder is total − matched.
    let mut dir_total: HashMap<PathBuf, u64> = HashMap::new();
    let mut dir_matched: HashMap<PathBuf, u64> = HashMap::new();

    for entry in WalkDir::new(home)
        .skip_hidden(false)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !metadata.is_file() {
            continue;
        }

        // On-disk allocation, not logical size — sparse/cloud-placeholder safe
        // (mirrors the scanner).
        let size: u64;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.len() > 4096 && metadata.blocks() == 0 {
                continue; // cloud-only placeholder
            }
            size = metadata.blocks() * 512;
        }
        #[cfg(not(unix))]
        {
            size = metadata.len();
        }
        if size == 0 {
            continue;
        }

        let matched = patterns.iter().any(|p| p.matches_path(&path));

        let mut p = path.parent();
        while let Some(parent) = p {
            *dir_total.entry(parent.to_path_buf()).or_insert(0) += size;
            if matched {
                *dir_matched.entry(parent.to_path_buf()).or_insert(0) += size;
            }
            if parent == home {
                break;
            }
            p = parent.parent();
        }
    }

    if let Some(pb) = &spinner {
        pb.finish_and_clear();
    }

    // Feed the walked per-dir totals/matched maps through the SAME drill routine
    // the cache path uses, so `hunt --fresh` and the cache hunt produce identical
    // landings — including the adaptive descent into concentrated unruled children
    // (finding 3). No more hard depth-2 cap or ancestor-first dedupe that buried
    // the concentrated child under its coarse parent.
    let stats: HashMap<PathBuf, DirStat> = dir_total
        .iter()
        .map(|(path, &total)| {
            let matched = dir_matched.get(path).copied().unwrap_or(0);
            (
                path.clone(),
                DirStat {
                    total_bytes: total,
                    unruled_bytes: total.saturating_sub(matched),
                },
            )
        })
        .collect();
    let universe = DirUniverse { stats };

    Ok(collect_landings(&universe, home, min_size, top))
}

// ===========================================================================
// Rendering (shared by both paths).
// ===========================================================================

fn render(
    chosen: &[HuntCandidate],
    _top: usize,
    min_size_mb: u64,
    from_cache: bool,
    ctx: &Context,
) -> Result<()> {
    if ctx.json {
        let out: Vec<_> = chosen
            .iter()
            .map(|c| {
                serde_json::json!({
                    "path": c.path,
                    // Back-compat: `size_bytes` is the field the old schema
                    // exposed; it now carries the UNRULED size (what hunt ranks
                    // on). `unruled_bytes` is an explicit alias, and
                    // `total_bytes` is added for context.
                    "size_bytes": c.unruled_bytes,
                    "unruled_bytes": c.unruled_bytes,
                    "total_bytes": c.total_bytes,
                    "depth": c.depth,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let yellow = Style::new().yellow();
    let cyan = Style::new().cyan().bold();
    let magenta = Style::new().magenta();

    println!();
    println!(
        "  {}",
        ctx.style(&output::rule("hunt  ·  unrule'd large dirs", 60), &dim)
    );
    println!();

    if chosen.is_empty() {
        println!(
            "  {}",
            ctx.style(
                &format!(
                    "Nothing found above {} MB outside of existing rules. Long tail is clean.",
                    min_size_mb
                ),
                &dim,
            )
        );
        println!();
        return Ok(());
    }

    let total: u64 = chosen.iter().map(|c| c.unruled_bytes).sum();
    println!(
        "  {} {}  unrule'd across {} dir{}{}",
        ctx.style("→", &yellow),
        ctx.style(&output::format_bytes(total), &bold),
        chosen.len(),
        if chosen.len() == 1 { "" } else { "s" },
        if from_cache {
            ctx.style("  (from scan cache)", &dim)
        } else {
            ctx.style("  (live walk)", &dim)
        },
    );
    println!();

    let max = chosen.first().map(|c| c.unruled_bytes).unwrap_or(1);
    for c in chosen {
        let bar = output::size_bar(c.unruled_bytes, max, 18);
        let size_str = output::format_bytes(c.unruled_bytes);
        // Show "X of Y total" when the directory is partly rule-covered, so it's
        // clear hunt already subtracted the matched bytes.
        let context = if c.total_bytes > c.unruled_bytes {
            ctx.style(
                &format!(
                    "  ({} of {} total)",
                    size_str,
                    output::format_bytes(c.total_bytes)
                ),
                &dim,
            )
        } else {
            String::new()
        };
        println!(
            "  {} {:>9}  {}  {}{}",
            ctx.style("◇", &magenta),
            ctx.style(&size_str, &bold),
            ctx.style(&bar, &magenta),
            ctx.style(&c.path.display().to_string(), &dim),
            context,
        );
    }

    println!();
    println!(
        "  {}",
        ctx.style(
            "These directories aren't covered by any rule. Inspect, then either:",
            &dim
        )
    );
    println!(
        "  {} {}",
        ctx.style("·", &dim),
        ctx.style(
            "add a rule (10-line YAML PR) so the next user benefits",
            &dim
        ),
    );
    println!(
        "  {} {}",
        ctx.style("·", &dim),
        ctx.style(
            "`du -sh <path>/*` to drill in, then delete what's safe",
            &dim
        ),
    );
    println!();
    println!(
        "  {} {}",
        ctx.style("→", &cyan),
        ctx.style(
            "After cleanup, please consider contributing rules: https://github.com/tymrtn/diskspace",
            &dim
        ),
    );
    println!();

    Ok(())
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/"))
}

/// Returns Some(depth) if `path` is `home/<a>/<b>/...`, where depth is the number
/// of path components past `home`. Returns None if `path` isn't under `home`.
fn depth_from(path: &Path, home: &Path) -> Option<usize> {
    let rel = path.strip_prefix(home).ok()?;
    Some(rel.components().count())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::candidate::Category;
    use crate::core::scanner::DirTotal;
    use chrono::Utc;

    fn dir(path: &str, total: u64) -> DirTotal {
        DirTotal {
            path: PathBuf::from(path),
            total_bytes: total,
        }
    }

    fn matched(path: &str, size: u64) -> ScannedEntry {
        ScannedEntry {
            path: PathBuf::from(path),
            size_bytes: size,
            category: Category::DevArtifact,
            modified: None,
            accessed: None,
            dev: None,
            ino: None,
            ctime: None,
        }
    }

    fn scan_with(largest: Vec<DirTotal>, entries: Vec<ScannedEntry>) -> ScanResult {
        ScanResult {
            scanned_at: Utc::now(),
            root: PathBuf::from("/home/u"),
            entries,
            total_bytes: 0,
            cloud_placeholder_bytes: 0,
            category_totals: Default::default(),
            schema: 0,
            scan_id: String::new(),
            metrics: None,
            largest_dirs: largest,
        }
    }

    /// A directory that is 100% rule-matched reports ~0 unruled and so never
    /// becomes a top row — the core correctness fix (the old `hunt` mislabeled
    /// all of it as "unrule'd").
    #[test]
    fn fully_covered_dir_reports_zero_unruled() {
        let home = PathBuf::from("/home/u");
        // ~/proj is 10 GB total, and a rule matched a 10 GB node_modules under it.
        let gb = 1024 * 1024 * 1024;
        let scan = scan_with(
            vec![
                dir("/home/u/proj", 10 * gb),
                dir("/home/u/proj/node_modules", 10 * gb),
            ],
            vec![matched("/home/u/proj/node_modules", 10 * gb)],
        );
        let got = hunt_from_cache(&scan, &home, 500 * 1024 * 1024, 15);
        assert!(
            got.is_empty(),
            "a fully rule-covered directory must not surface as unruled, got {:?}",
            got
        );
    }

    /// Covered bytes are subtracted: a dir that is half rule-matched reports the
    /// other half as unruled.
    #[test]
    fn partial_cover_subtracts_matched_bytes() {
        let home = PathBuf::from("/home/u");
        let gb = 1024 * 1024 * 1024;
        // ~/work is 10 GB; 6 GB of it is a matched target/, leaving 4 GB unruled.
        let scan = scan_with(
            vec![
                dir("/home/u/work", 10 * gb),
                dir("/home/u/work/target", 6 * gb),
            ],
            vec![matched("/home/u/work/target", 6 * gb)],
        );
        let got = hunt_from_cache(&scan, &home, 500 * 1024 * 1024, 15);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, PathBuf::from("/home/u/work"));
        assert_eq!(got[0].unruled_bytes, 4 * gb);
        assert_eq!(got[0].total_bytes, 10 * gb);
    }

    /// ADAPTIVE DRILL: a big parent whose unruled bytes are concentrated in one
    /// child surfaces the CHILD, not the coarse parent blob. The other child here
    /// (misc, 10 GB) also clears the floor, so it surfaces too — both real unruled
    /// dirs are more actionable than one coarse parent.
    #[test]
    fn drills_to_concentrated_unruled_child() {
        let home = PathBuf::from("/home/u");
        let gb = 1024 * 1024 * 1024;
        // ~/Dropbox = 200 GB total, all unruled: 138 GB in Clef, 10 GB in misc.
        let scan = scan_with(
            vec![
                dir("/home/u/Dropbox", 200 * gb),
                dir("/home/u/Dropbox/Clef", 138 * gb),
                dir("/home/u/Dropbox/misc", 10 * gb),
            ],
            vec![], // nothing rule-matched
        );
        let got = hunt_from_cache(&scan, &home, 500 * 1024 * 1024, 15);
        // The coarse parent must NOT appear; its big children do.
        assert!(
            !got.iter().any(|c| c.path == Path::new("/home/u/Dropbox")),
            "the coarse parent blob must not be reported, got {:?}",
            got.iter().map(|c| &c.path).collect::<Vec<_>>()
        );
        let clef = got
            .iter()
            .find(|c| c.path == Path::new("/home/u/Dropbox/Clef"))
            .expect("Clef surfaced as its own row");
        assert_eq!(clef.unruled_bytes, 138 * gb);
        assert!(
            got.iter()
                .any(|c| c.path == Path::new("/home/u/Dropbox/misc")),
            "misc (also above the floor) surfaced too"
        );
    }

    /// THE REAL HEADLINE CASE (finding 1 + 2 regression): ~/Dropbox = 397 GB
    /// unruled, with Clef = 138 GB and BMI = 60 GB as two distinct big children and
    /// ~199 GB more spread thin. Clef is only 138/397 ≈ 35% of the parent — the old
    /// 60%-of-parent gate broke immediately and reported the coarse 397 GB blob.
    /// The new absolute-floor drill must surface BOTH Clef AND BMI as their own
    /// rows and NEVER the 397 GB parent.
    #[test]
    fn drills_real_dropbox_surfaces_clef_and_bmi() {
        let home = PathBuf::from("/home/u");
        let gb = 1024 * 1024 * 1024;
        let scan = scan_with(
            vec![
                dir("/home/u/Dropbox", 397 * gb),
                dir("/home/u/Dropbox/Clef", 138 * gb),
                dir("/home/u/Dropbox/BMI", 60 * gb),
            ],
            vec![], // all unruled
        );
        let got = hunt_from_cache(&scan, &home, 1024 * 1024 * 1024, 15);
        assert!(
            !got.iter().any(|c| c.path == Path::new("/home/u/Dropbox")),
            "the 397 GB Dropbox blob must NOT be reported, got {:?}",
            got.iter().map(|c| &c.path).collect::<Vec<_>>()
        );
        let clef = got
            .iter()
            .find(|c| c.path == Path::new("/home/u/Dropbox/Clef"))
            .expect("Clef (138 GB) surfaced as its own row");
        assert_eq!(clef.unruled_bytes, 138 * gb);
        let bmi = got
            .iter()
            .find(|c| c.path == Path::new("/home/u/Dropbox/BMI"))
            .expect("BMI (60 GB) surfaced as its own row — finding 2");
        assert_eq!(bmi.unruled_bytes, 60 * gb);
    }

    /// When several children are each individually large, EACH is surfaced as its
    /// own row (more actionable than one coarse parent). The parent is dropped.
    #[test]
    fn surfaces_each_large_child_separately() {
        let home = PathBuf::from("/home/u");
        let gb = 1024 * 1024 * 1024;
        // ~/media = 100 GB, split 40/35/25 across three children — each clears the
        // floor, so each is surfaced; the parent blob is not.
        let scan = scan_with(
            vec![
                dir("/home/u/media", 100 * gb),
                dir("/home/u/media/a", 40 * gb),
                dir("/home/u/media/b", 35 * gb),
                dir("/home/u/media/c", 25 * gb),
            ],
            vec![],
        );
        let got = hunt_from_cache(&scan, &home, 500 * 1024 * 1024, 15);
        assert_eq!(got.len(), 3, "each large child surfaced separately");
        assert!(
            !got.iter().any(|c| c.path == Path::new("/home/u/media")),
            "the coarse parent is dropped once its big children surface"
        );
        for child in ["a", "b", "c"] {
            assert!(
                got.iter()
                    .any(|c| c.path == Path::new(&format!("/home/u/media/{child}"))),
                "media/{child} surfaced"
            );
        }
    }

    /// When unruled bytes are spread across MANY SMALL children (none clears the
    /// floor), the drill keeps the PARENT — it's the finest actionable granularity,
    /// with no single child worth its own row.
    #[test]
    fn keeps_parent_when_children_are_all_small() {
        let home = PathBuf::from("/home/u");
        let gb = 1024 * 1024 * 1024;
        // ~/scatter = 6 GB, spread across many sub-GB children, none of which
        // clears a 2 GB floor.
        let scan = scan_with(
            vec![
                dir("/home/u/scatter", 6 * gb),
                dir("/home/u/scatter/a", gb / 2),
                dir("/home/u/scatter/b", gb / 2),
                dir("/home/u/scatter/c", gb / 2),
            ],
            vec![],
        );
        let got = hunt_from_cache(&scan, &home, 2 * gb, 15);
        assert_eq!(got.len(), 1, "no child clears the floor → keep the parent");
        assert_eq!(
            got[0].path,
            PathBuf::from("/home/u/scatter"),
            "spread-thin bytes keep the parent as the reported granularity"
        );
        assert_eq!(got[0].unruled_bytes, 6 * gb);
    }

    /// The drill descends MORE THAN ONE level when concentration holds all the way
    /// down (Dropbox → Code → repo).
    #[test]
    fn drills_multiple_levels() {
        let home = PathBuf::from("/home/u");
        let gb = 1024 * 1024 * 1024;
        let scan = scan_with(
            vec![
                dir("/home/u/Dropbox", 100 * gb),
                dir("/home/u/Dropbox/Code", 95 * gb),
                dir("/home/u/Dropbox/Code/repo", 90 * gb),
            ],
            vec![],
        );
        let got = hunt_from_cache(&scan, &home, 500 * 1024 * 1024, 15);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, PathBuf::from("/home/u/Dropbox/Code/repo"));
        assert_eq!(got[0].unruled_bytes, 90 * gb);
    }

    /// `--min-size` / `--top` apply to the UNRULED size: a directory whose unruled
    /// remainder is below the floor is dropped even if its TOTAL is large.
    #[test]
    fn min_size_filters_on_unruled_not_total() {
        let home = PathBuf::from("/home/u");
        let gb = 1024 * 1024 * 1024;
        // ~/cache is 50 GB total but 49.9 GB is rule-matched, leaving ~100 MB
        // unruled — below a 500 MB floor, so it's dropped.
        let scan = scan_with(
            vec![
                dir("/home/u/cache", 50 * gb),
                dir("/home/u/cache/matched", 50 * gb - 100 * 1024 * 1024),
            ],
            vec![matched(
                "/home/u/cache/matched",
                50 * gb - 100 * 1024 * 1024,
            )],
        );
        let got = hunt_from_cache(&scan, &home, 500 * 1024 * 1024, 15);
        assert!(
            got.is_empty(),
            "a mostly-covered dir below the unruled floor is dropped, got {:?}",
            got
        );
    }

    /// `--top` truncates the ranked-by-unruled result set.
    #[test]
    fn top_truncates_ranked_by_unruled() {
        let home = PathBuf::from("/home/u");
        let gb = 1024 * 1024 * 1024;
        let scan = scan_with(
            vec![
                dir("/home/u/a", 30 * gb),
                dir("/home/u/b", 20 * gb),
                dir("/home/u/c", 10 * gb),
            ],
            vec![],
        );
        let got = hunt_from_cache(&scan, &home, 1024 * 1024 * 1024, 2);
        assert_eq!(got.len(), 2, "top=2 keeps only the two biggest");
        assert_eq!(got[0].path, PathBuf::from("/home/u/a"));
        assert_eq!(got[1].path, PathBuf::from("/home/u/b"));
    }

    /// Nested matched entries must not double-count: a top-level matched dir and a
    /// matched child inside it both appear in `entries`, but only the top-level
    /// one's (already-aggregated) bytes count toward covered.
    #[test]
    fn nested_matched_entries_do_not_double_count() {
        let home = PathBuf::from("/home/u");
        let gb = 1024 * 1024 * 1024;
        // ~/proj = 10 GB; a matched target/ (8 GB, already aggregating its
        // descendants) and a matched target/debug (5 GB) inside it. Covered must
        // be 8 GB (top-level only), not 13 GB — so unruled is 2 GB, not negative.
        let scan = scan_with(
            vec![dir("/home/u/proj", 10 * gb)],
            vec![
                matched("/home/u/proj/target", 8 * gb),
                matched("/home/u/proj/target/debug", 5 * gb),
            ],
        );
        let got = hunt_from_cache(&scan, &home, 500 * 1024 * 1024, 15);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].unruled_bytes,
            2 * gb,
            "only the top-level matched dir's bytes are subtracted"
        );
    }

    /// `load_fresh_cache` staleness: a `scanned_at` older than the threshold makes
    /// the cache stale (returns None → live-walk fallback). We can't write the
    /// real cache here without a HOME override, so this asserts the pure age
    /// math via a constructed result.
    #[test]
    fn stale_cache_age_is_detected() {
        let now = Utc::now();
        let fresh_at = now - chrono::Duration::hours(CACHE_STALE_AFTER_HOURS - 1);
        let stale_at = now - chrono::Duration::hours(CACHE_STALE_AFTER_HOURS + 1);
        assert!(
            now.signed_duration_since(fresh_at).num_hours() <= CACHE_STALE_AFTER_HOURS,
            "a recent scan is fresh"
        );
        assert!(
            now.signed_duration_since(stale_at).num_hours() > CACHE_STALE_AFTER_HOURS,
            "an old scan is stale"
        );
    }

    // -- end-to-end cache-load tests (real scan.json under a temp $HOME) -------

    /// An RAII `$HOME` override so `load_fresh_cache` reads a tempdir's
    /// `~/.diskspace/scan.json`, NEVER the real one. Holds the crate-wide
    /// `HOME_TEST_LOCK` for its whole lifetime and restores `$HOME` on drop.
    struct TempHome {
        dir: PathBuf,
        prev: Option<std::ffi::OsString>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl TempHome {
        fn new() -> Self {
            let guard = crate::core::HOME_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "diskspace-hunt-home-{}-{}",
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            std::fs::create_dir_all(&dir).expect("create fake $HOME");
            let prev = std::env::var_os("HOME");
            // SAFETY: serialized by HOME_TEST_LOCK; restored on drop.
            unsafe {
                std::env::set_var("HOME", &dir);
            }
            TempHome {
                dir,
                prev,
                _guard: guard,
            }
        }

        /// Write a `~/.diskspace/scan.json` with the given `scanned_at` and dirs.
        fn write_cache(&self, scanned_at: DateTime<Utc>, largest: Vec<DirTotal>) {
            let mut scan = scan_with(largest, Vec::new());
            scan.scanned_at = scanned_at;
            let data_dir = self.dir.join(".diskspace");
            std::fs::create_dir_all(&data_dir).unwrap();
            std::fs::write(
                data_dir.join("scan.json"),
                serde_json::to_string_pretty(&scan).unwrap(),
            )
            .unwrap();
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            // SAFETY: serialized by HOME_TEST_LOCK (held until after this).
            unsafe {
                match &self.prev {
                    Some(h) => std::env::set_var("HOME", h),
                    None => std::env::remove_var("HOME"),
                }
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A missing scan.json yields None → the caller falls back to the live walk.
    #[test]
    fn missing_cache_returns_none() {
        let _h = TempHome::new(); // fresh temp $HOME, no scan.json written
        assert!(
            load_fresh_cache(Utc::now()).is_none(),
            "no scan.json must yield None (live-walk fallback)"
        );
    }

    /// A fresh scan.json loads; a stale one (older than the threshold) yields None.
    #[test]
    fn fresh_cache_loads_stale_cache_falls_back() {
        let h = TempHome::new();
        let now = Utc::now();
        let dirs = vec![dir("/home/u/x", 1024 * 1024 * 1024)];

        // Fresh: written 1h ago → loads.
        h.write_cache(now - chrono::Duration::hours(1), dirs.clone());
        assert!(
            load_fresh_cache(now).is_some(),
            "a fresh scan.json must load"
        );

        // Stale: written past the threshold → None (fall back to live walk).
        h.write_cache(
            now - chrono::Duration::hours(CACHE_STALE_AFTER_HOURS + 2),
            dirs,
        );
        assert!(
            load_fresh_cache(now).is_none(),
            "a stale scan.json must yield None"
        );
    }

    /// A legacy cache (empty `largest_dirs`, e.g. written before Step A) yields
    /// None so hunt falls back to the live walk rather than reporting nothing.
    #[test]
    fn legacy_cache_without_largest_dirs_falls_back() {
        let h = TempHome::new();
        h.write_cache(Utc::now(), Vec::new()); // empty largest_dirs
        assert!(
            load_fresh_cache(Utc::now()).is_none(),
            "an empty largest_dirs (legacy cache) must yield None"
        );
    }

    /// The live-walk fallback (the `--fresh` path, and what runs when the cache is
    /// missing/stale) is itself honest: it walks a real tree, subtracts the
    /// rule-MATCHED bytes via the rules' globs, and surfaces only the unruled
    /// remainder. Here a matched `**/node_modules` is subtracted, leaving the
    /// sibling unruled `data/` as the surfaced row.
    #[cfg(unix)]
    #[test]
    fn fresh_walk_is_glob_aware_and_subtracts_matched() {
        use crate::core::rules::Rule;
        use std::io::Write;

        let _guard = crate::core::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // tree (acts as $HOME):
        //   proj/node_modules/lib.bin   (matched by a **/node_modules rule)
        //   proj/data/blob.bin          (unruled)
        let mut home = std::env::temp_dir();
        home.push(format!(
            "diskspace-hunt-walk-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let nm = home.join("proj/node_modules");
        let data = home.join("proj/data");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let write = |p: &Path, n: usize| {
            let mut f = std::fs::File::create(p).unwrap();
            f.write_all(&vec![0u8; n]).unwrap();
            f.flush().unwrap();
        };
        // 2 MB matched, 3 MB unruled — both clear a 1 MB floor.
        write(&nm.join("lib.bin"), 2 * 1024 * 1024);
        write(&data.join("blob.bin"), 3 * 1024 * 1024);

        let rules = vec![Rule {
            id: "node_modules".into(),
            category: "dev-artifact".into(),
            path_pattern: format!("{}/**/node_modules/**", home.display()),
            domain: None,
            base_confidence: 0.9,
            reason: "deps".into(),
            exclude_if_recent_access_days: None,
            exclude_if_recent_modified_days: None,
            consequences: None,
            reference_url: None,
        }];

        let ctx = Context {
            json: true, // suppress the spinner in the test
            yes: true,
            no_color: true,
            verbose: false,
            quiet: true,
        };
        let got = hunt_fresh_walk(&home, &rules, 1024 * 1024, 15, &ctx).unwrap();

        // The matched node_modules bytes are subtracted, so node_modules itself is
        // NOT surfaced. The fresh walk now runs the SAME adaptive drill as the
        // cache path (finding 3): proj/ is a shell whose only big unruled child is
        // data/, so the drill descends and surfaces proj/data — the finest
        // actionable unruled dir — not the coarse proj/ parent.
        assert!(
            got.iter().all(|c| !c.path.ends_with("node_modules")),
            "a fully-matched node_modules must not surface as unruled: {:?}",
            got.iter().map(|c| &c.path).collect::<Vec<_>>()
        );
        let data = got
            .iter()
            .find(|c| c.path == home.join("proj/data"))
            .expect("proj/data surfaced as the concentrated unruled child");
        // data/ holds the 3 MB unruled blob; nothing matched under it.
        assert_eq!(
            data.unruled_bytes,
            3 * 1024 * 1024,
            "matched bytes subtracted; the unruled remainder is data/'s 3 MB"
        );

        let _ = std::fs::remove_dir_all(&home);
    }

    /// FINDING 3 PARITY: the fresh walk feeds its per-dir totals through the SAME
    /// drill as the cache path, so `hunt --fresh` surfaces the concentrated unruled
    /// child (Clef + BMI), NOT the coarse parent — and is not hard-capped at depth
    /// 2. This mirrors `drills_real_dropbox_surfaces_clef_and_bmi` on a real tree.
    #[cfg(unix)]
    #[test]
    fn fresh_walk_drills_like_cache() {
        use crate::core::rules::Rule;
        use std::io::Write;

        let _guard = crate::core::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // tree (acts as $HOME):
        //   Dropbox/Clef/clef.bin   (4 MB, unruled)
        //   Dropbox/BMI/bmi.bin     (2 MB, unruled)
        //   Dropbox/scatter/x.bin   (256 KB, below floor — stays in the residual)
        let mut home = std::env::temp_dir();
        home.push(format!(
            "diskspace-hunt-drill-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let clef = home.join("Dropbox/Clef");
        let bmi = home.join("Dropbox/BMI");
        let scatter = home.join("Dropbox/scatter");
        std::fs::create_dir_all(&clef).unwrap();
        std::fs::create_dir_all(&bmi).unwrap();
        std::fs::create_dir_all(&scatter).unwrap();

        let write = |p: &Path, n: usize| {
            let mut f = std::fs::File::create(p).unwrap();
            f.write_all(&vec![0u8; n]).unwrap();
            f.flush().unwrap();
        };
        write(&clef.join("clef.bin"), 4 * 1024 * 1024);
        write(&bmi.join("bmi.bin"), 2 * 1024 * 1024);
        write(&scatter.join("x.bin"), 256 * 1024);

        let rules: Vec<Rule> = Vec::new(); // nothing rule-matched

        let ctx = Context {
            json: true,
            yes: true,
            no_color: true,
            verbose: false,
            quiet: true,
        };
        // 1 MB floor: Clef (4 MB) and BMI (2 MB) clear it; scatter (256 KB) does not.
        let got = hunt_fresh_walk(&home, &rules, 1024 * 1024, 15, &ctx).unwrap();

        // The coarse Dropbox parent must NOT be reported; both big children are.
        assert!(
            !got.iter().any(|c| c.path == home.join("Dropbox")),
            "the coarse Dropbox parent must not be reported, got {:?}",
            got.iter().map(|c| &c.path).collect::<Vec<_>>()
        );
        assert!(
            got.iter().any(|c| c.path == clef),
            "Clef surfaced by the fresh-walk drill"
        );
        assert!(
            got.iter().any(|c| c.path == bmi),
            "BMI surfaced by the fresh-walk drill (finding 2 + 3)"
        );

        let _ = std::fs::remove_dir_all(&home);
    }
}

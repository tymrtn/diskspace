use anyhow::{Context as _, Result};
use console::Style;
use std::path::Path;

use crate::commands::scan::scan_cache_path;
use crate::core::candidate::{Candidate, Category};
use crate::core::rules::{self, Rule};
use crate::core::scanner::ScanResult;
use crate::output::{self, Context};
use crate::profile::{self, Profile};

/// Confidence multiplier applied to a REGENERABLE candidate that was touched
/// inside its rule's recency window (#6). It still appears — just ranked lower —
/// instead of being silently dropped.
const RECENCY_DECAY: f32 = 0.6;

pub fn run(show_all: bool, top: usize, ctx: &Context) -> Result<()> {
    let cache = scan_cache_path();
    if !cache.exists() {
        if ctx.json {
            eprintln!(r#"{{"error":"no scan found","hint":"run diskspace survey first"}}"#);
        } else {
            eprintln!("  No survey found. Run `diskspace survey` first.");
        }
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(&cache).context("reading scan cache")?;
    let scan: ScanResult = serde_json::from_str(&content).context("parsing scan cache")?;
    let rules = rules::load_builtin()?;
    let prof = profile::load()?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());

    let mut candidates = build_candidates(&scan, &rules, &prof, &home);

    // Sort by yield × confidence descending, with a recovery-class tiebreaker
    // (#8): when two candidates score equally (or near-equally), the SAFER
    // recovery class ranks first, so a low-confidence irreversible/manual item
    // can never out-rank a safe regenerable win. `score()` itself stays
    // size×confidence and metrics-blind — this is purely a sort comparator.
    candidates.sort_by(|a, b| {
        b.score()
            .partial_cmp(&a.score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                recovery_risk_rank(candidate_recovery_class(a))
                    .cmp(&recovery_risk_rank(candidate_recovery_class(b)))
            })
    });

    // FULL candidate-set reclaimable total (#3) — independent of the shown slice.
    let total_reclaimable_all: u64 = candidates.iter().map(|c| c.size_bytes).sum();
    // Per-category rollup over the FULL set.
    let mut category_rollup: std::collections::BTreeMap<String, (usize, u64)> =
        std::collections::BTreeMap::new();
    for c in &candidates {
        let e = category_rollup
            .entry(c.category.to_string())
            .or_insert((0, 0));
        e.0 += 1;
        e.1 += c.size_bytes;
    }

    let shown: Vec<&Candidate> = if show_all {
        candidates.iter().collect()
    } else {
        candidates.iter().take(top).collect()
    };

    if ctx.json {
        let payload = detect_json_payload(&shown, candidates.len(), total_reclaimable_all);
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    if shown.is_empty() {
        println!("\n  No candidates found. Your disk looks clean!\n");
        return Ok(());
    }

    let bold = Style::new().bold();
    let dim = Style::new().dim();
    let green_bold = Style::new().green().bold();
    let red_bold = Style::new().red().bold();

    println!();
    // Header reports the FULL candidate-set reclaimable total (#3), not just the
    // shown slice — so a `--top 10` view still advertises the whole opportunity.
    let header = format!(
        "  {} candidate{}  ·  {} reclaimable{}",
        candidates.len(),
        if candidates.len() == 1 { "" } else { "s" },
        output::format_bytes(total_reclaimable_all),
        if !show_all && candidates.len() > shown.len() {
            format!("  ·  showing top {}", shown.len())
        } else {
            String::new()
        }
    );
    println!("{}", ctx.style(&header, &bold));
    println!("  {}", ctx.style(&output::rule("", 56), &dim));
    // Per-category rollup over the FULL set (#3).
    for (cat, (count, bytes)) in &category_rollup {
        let cat_style = output::category_style(cat);
        println!(
            "  {}  {:<16}  {:>4} · {:>9}",
            ctx.style(output::category_icon(cat), &cat_style),
            ctx.style(cat, &cat_style),
            ctx.style(&count.to_string(), &dim),
            ctx.style(&output::format_bytes(*bytes), &bold),
        );
    }
    println!();

    for (i, c) in shown.iter().enumerate() {
        let cat_style = output::category_style(&c.category.to_string());
        let icon = output::category_icon(&c.category.to_string());
        let rank = format!("{:>2}.", i + 1);

        // Recovery class shown inline, with a warning marker for the risky
        // (irreversible/manual) classes so a low-confidence permanent-delete is
        // never mistaken for a safe regenerable win (#8).
        let recovery_class = candidate_recovery_class(c);
        let recovery_label = if recovery_class.is_empty() {
            String::new()
        } else if is_risky_recovery(c) {
            ctx.style(&format!("⚠ {}", recovery_class), &red_bold)
        } else {
            ctx.style(recovery_class, &dim)
        };

        // Top line: rank · icon · category · size · recovery-class
        println!(
            "  {} {}  {}  {:>9}  {}",
            ctx.style(&rank, &dim),
            ctx.style(icon, &cat_style),
            ctx.style(&c.category.to_string(), &cat_style),
            ctx.style(&output::format_bytes(c.size_bytes), &bold),
            recovery_label,
        );

        // Path
        println!("       {}", ctx.style(&c.path.display().to_string(), &bold));

        // Confidence bar + id
        if !ctx.quiet {
            let bar = output::confidence_bar(c.confidence, 10);
            println!(
                "       {}  {}",
                ctx.style(&bar, &cat_style),
                ctx.style(&c.id, &dim),
            );
        }

        // Reason (verbose only)
        if ctx.verbose {
            println!("       {}", ctx.style(&format!("↳  {}", c.reason), &dim));
        }

        if i < shown.len() - 1 {
            println!("  {}", ctx.style("  ·", &dim));
        }
    }

    println!();
    println!("  {}", ctx.style(&output::rule("", 56), &dim));
    println!(
        "  {}  diskspace check <id>",
        ctx.style("→ next:", &green_bold),
    );
    println!();

    Ok(())
}

pub fn build_candidates_pub(
    scan: &ScanResult,
    rules: &[Rule],
    prof: &Profile,
    home: &str,
) -> Vec<Candidate> {
    build_candidates(scan, rules, prof, home)
}

fn build_candidates(
    scan: &ScanResult,
    rules: &[Rule],
    prof: &Profile,
    home: &str,
) -> Vec<Candidate> {
    let mut candidates: Vec<Candidate> = Vec::new();
    let home_path = Path::new(home);

    for rule in rules {
        let pattern_str = crate::core::scanner::expand_home(&rule.path_pattern, home_path);
        let glob_pat = match glob::Pattern::new(&pattern_str) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Find entries matching this rule
        for entry in &scan.entries {
            if !glob_pat.matches_path(&entry.path) {
                continue;
            }
            if entry.size_bytes == 0 {
                continue;
            }

            // Check minimum size
            let min_bytes = (prof.preferences.min_candidate_size_gb * 1_073_741_824.0) as u64;
            if entry.size_bytes < min_bytes {
                continue;
            }

            // Check never_touch policy
            if is_never_touch(&entry.path, &prof.paths.never_touch, home_path) {
                continue;
            }

            // Check never_suggest
            if prof
                .paths
                .never_suggest
                .iter()
                .any(|p| entry.path.starts_with(p))
            {
                continue;
            }

            // Compute confidence adjustments
            let mut confidence = rule.base_confidence;

            // Boost if domain is explicitly inactive in profile
            if let Some(domain) = &rule.domain {
                if let Some(d) = prof.domains.get(domain) {
                    if !d.active {
                        confidence = (confidence + 0.10).min(0.99);
                    }
                }
            }

            // Recency handling (#6). The OLD behavior hard-`continue`d on any
            // recent access/modification, which silently dropped active
            // dev-artifact (the 158 GB the audit found missing). The pressure
            // test in `check` is the real liveness gate — detect must SURFACE
            // these, just ranked lower.
            //
            // For REGENERABLE classes (auto | redownload | rebuild | recreate)
            // a recent touch is normal churn, not a reason to hide the win: we
            // KEEP the candidate but DECAY its confidence (×0.6) so it ranks
            // below cold targets. For {manual, irreversible} a recent touch is a
            // strong "leave it alone" signal, so we preserve the HARD exclusion.
            let recovery_class = rule
                .consequences
                .as_ref()
                .map(|c| c.recovery.as_str())
                .unwrap_or("");
            let regenerable = is_regenerable(recovery_class);
            let mut recent = false;

            if let Some(days) = rule.exclude_if_recent_access_days {
                if let Some(accessed) = entry.accessed {
                    let age_days = chrono::Utc::now()
                        .signed_duration_since(accessed)
                        .num_days();
                    if age_days < days as i64 {
                        if regenerable {
                            recent = true;
                        } else {
                            continue;
                        }
                    }
                }
            }

            if let Some(days) = rule.exclude_if_recent_modified_days {
                if let Some(modified) = entry.modified {
                    let age_days = chrono::Utc::now()
                        .signed_duration_since(modified)
                        .num_days();
                    if age_days < days as i64 {
                        if regenerable {
                            recent = true;
                        } else {
                            continue;
                        }
                    }
                }
            }

            if recent {
                confidence *= RECENCY_DECAY;
            }

            let id = format!(
                "{}-{}",
                rule.id,
                &format!("{:x}", md5_short(&entry.path.to_string_lossy()))
            );

            let mut candidate = Candidate {
                id,
                rule_id: rule.id.clone(),
                path: entry.path.clone(),
                size_bytes: entry.size_bytes,
                category: category_from_str(&rule.category),
                confidence,
                reason: rule.reason.clone(),
                domain: rule.domain.clone(),
                modified: entry.modified,
                accessed: entry.accessed,
                consequences: rule.consequences.clone(),
                consequence_contract: None,
                metrics: None,
                reference_url: None,
            };

            // Agent-surface enrichment: attach reference_url, consequence
            // contract, and advisory metrics. Purely additive / advisory — it
            // never touches the score() inputs, so ranking stays unaffected.
            crate::commands::agent_surface::enrich_candidate(&mut candidate, rule, prof);

            candidates.push(candidate);
        }
    }

    // ── exact-duplicate-path dedup (#1) ──────────────────────────────────
    // Two DIFFERENT rules — or two overlapping globs — can match the SAME path
    // (e.g. a generic `cache` rule and a vendor-specific rule both hitting
    // `~/Library/Caches/foo`). That yields two candidates with an identical
    // `path`, which would list the path twice AND double-count its bytes in
    // `total_reclaimable_all`. Collapse exact duplicates first, keeping the
    // highest-confidence candidate for each path (ties resolved by the safer
    // recovery class, then stably by first occurrence). This must run BEFORE the
    // ancestor pass below, whose `starts_with` test treats an identical path as a
    // (self-)ancestor and so cannot, on its own, drop an exact duplicate.
    candidates.sort_by(|a, b| {
        a.path.cmp(&b.path).then_with(|| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    recovery_risk_rank(candidate_recovery_class(a))
                        .cmp(&recovery_risk_rank(candidate_recovery_class(b)))
                })
        })
    });
    candidates.dedup_by(|a, b| a.path == b.path);

    // ── ancestor-containment dedup (#1) ──────────────────────────────────
    // Removing the per-rule `break` means we now emit a candidate for EVERY
    // surviving matched entry (ids are per-path, so no collisions). But two
    // rules — or one glob — can match both a parent target/ and a nested entry
    // inside it; listing both double-counts bytes (the nested path's bytes are
    // already inside the ancestor's aggregated size). Mirror the scanner's
    // nested-entry logic (scanner.rs:176-186): when a candidate's path is
    // contained within ANOTHER kept candidate's path, keep the ANCESTOR only.
    // Exact duplicates are already gone (above), so the `*other != c.path` guard
    // here only ever skips the self-comparison.
    let paths: Vec<std::path::PathBuf> = candidates.iter().map(|c| c.path.clone()).collect();
    candidates.retain(|c| {
        !paths
            .iter()
            .any(|other| *other != c.path && c.path.starts_with(other))
    });

    candidates
}

/// `true` when a recovery class regenerates on its own / on next run
/// (auto | redownload | rebuild | recreate). For these, a recent touch is
/// normal churn, so detect decays confidence instead of hard-excluding (#6).
/// `manual` and `irreversible` are NOT regenerable.
fn is_regenerable(recovery_class: &str) -> bool {
    matches!(
        recovery_class,
        "auto" | "redownload" | "rebuild" | "recreate"
    )
}

/// Ranking penalty for the recovery class (#8). Higher = riskier = ranks lower.
/// Used only as a SORT tiebreaker after `score()`, so a low-confidence
/// irreversible/manual item can never out-rank a safe regenerable win. This does
/// NOT change `Candidate::score` (which stays size×confidence and metrics-blind).
fn recovery_risk_rank(recovery_class: &str) -> u8 {
    match recovery_class {
        "auto" => 0,
        "redownload" => 1,
        "rebuild" => 2,
        "recreate" => 3,
        "manual" => 4,
        "irreversible" => 5,
        _ => 4, // unknown/unspecified: treat as cautious as `manual`
    }
}

/// The recovery class for a candidate, read from its consequence contract (set
/// during enrichment) or its raw consequences. Empty string when unspecified.
fn candidate_recovery_class(c: &Candidate) -> &str {
    if let Some(contract) = &c.consequence_contract {
        return contract.recovery_class.as_str();
    }
    if let Some(cons) = &c.consequences {
        return cons.recovery.as_str();
    }
    ""
}

/// `true` when a candidate's recovery class warrants an inline warning marker in
/// the human list (irreversible or manual recovery — deleting it is costly or
/// permanent).
fn is_risky_recovery(c: &Candidate) -> bool {
    matches!(candidate_recovery_class(c), "manual" | "irreversible")
}

/// `detect --json` schema version. Bumped to **2** when the top-level envelope
/// changed from a bare candidate ARRAY (pre-P2) to the `{"meta":..,"candidates":..}`
/// OBJECT (#4). A consumer that pinned to the old array form (`jq '.[]'`,
/// `Vec<Candidate>` at the root) must update; `meta.schema_version` lets a
/// consumer detect the shape it received.
pub const DETECT_JSON_SCHEMA_VERSION: u32 = 2;

/// Build the `detect --json` payload: a top-level `meta` object
/// (`schema_version` + `immediate_threshold` + full-set totals) and a
/// `candidates` array where each candidate carries an added `recommended_command`
/// and an inline `recovery_class`.
///
/// SCHEMA NOTE (#4): the top-level envelope is an OBJECT, not the pre-P2 bare
/// candidate ARRAY. This is an intentional, documented break (see
/// `DETECT_JSON_SCHEMA_VERSION` and CHANGELOG). The PER-CANDIDATE keys remain
/// additive — legacy candidate keys are untouched — but the DOCUMENT root is not
/// array-compatible.
///
/// detect runs no live pressure test (that is `check`'s job and the real gate),
/// so we pass a synthetic SAFE pressure result to the helper: these candidates
/// already survived the static rule/recency/policy filters. The recommendation
/// branches on each candidate's EFFECTIVE `confidence` vs. `IMMEDIATE_THRESHOLD`
/// (#3) — so a recency-decayed candidate (#6) never gets an `--immediate`
/// recommendation that contradicts its own demoted `confidence`.
/// `total_candidates` / `total_reclaimable_bytes` describe the FULL set, not the
/// `shown` slice, so an agent reading a truncated view still sees the whole
/// opportunity.
fn detect_json_payload(
    shown: &[&Candidate],
    total_candidates: usize,
    total_reclaimable_all: u64,
) -> serde_json::Value {
    let safe_pressure =
        crate::core::candidate::CheckResult::gate("(detect)".into(), true, 1.0, Vec::new());

    let enriched: Vec<serde_json::Value> = shown
        .iter()
        .map(|c| {
            let mut v = serde_json::to_value(c).unwrap_or(serde_json::Value::Null);
            // (#3) Recommend off the candidate's EFFECTIVE confidence, not the
            // rule's static base. A recency-decayed regenerable (#6) carries a
            // demoted `c.confidence` (base × RECENCY_DECAY); passing that here
            // keeps a decayed candidate out of the `--immediate` branch so the
            // serialized `confidence` and `recommended_command` agree.
            let rec = crate::commands::explain::recommended_command_for(
                &c.path,
                Some(c.confidence),
                &safe_pressure,
            );
            if let Some(obj) = v.as_object_mut() {
                obj.insert("recommended_command".into(), serde_json::Value::String(rec));
                obj.insert(
                    "recovery_class".into(),
                    serde_json::Value::String(candidate_recovery_class(c).to_string()),
                );
            }
            v
        })
        .collect();

    serde_json::json!({
        "meta": {
            "schema_version": DETECT_JSON_SCHEMA_VERSION,
            "immediate_threshold": crate::commands::explain::IMMEDIATE_THRESHOLD,
            "total_reclaimable_bytes": total_reclaimable_all,
            "total_candidates": total_candidates,
            "shown": shown.len(),
        },
        "candidates": enriched,
    })
}

fn is_never_touch(path: &Path, patterns: &[String], home: &Path) -> bool {
    for p in patterns {
        let expanded = crate::core::scanner::expand_home(p, home);
        if let Ok(pat) = glob::Pattern::new(&expanded) {
            if pat.matches_path(path) {
                return true;
            }
        }
    }
    false
}

fn category_from_str(s: &str) -> Category {
    match s {
        "dev-artifact" => Category::DevArtifact,
        "app-cache" => Category::AppCache,
        "download-entropy" => Category::DownloadEntropy,
        "vm-disk" => Category::VmDisk,
        _ => Category::Unknown,
    }
}

fn md5_short(s: &str) -> u32 {
    // Simple non-cryptographic hash for short IDs
    let mut h: u32 = 0x811c9dc5;
    for b in s.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::candidate::{Category, ScannedEntry};
    use crate::core::rules::{Consequences, Rule};
    use crate::core::scanner::ScanResult;
    use chrono::Utc;
    use std::path::PathBuf;

    /// A profile with the size floor at zero so synthetic small test entries
    /// survive `build_candidates`. Everything else is `Profile::default`.
    fn test_profile() -> Profile {
        let mut p = Profile::default();
        p.preferences.min_candidate_size_gb = 0.0;
        p
    }

    fn cons(recovery: &str) -> Consequences {
        Consequences {
            recovery: recovery.into(),
            rebuild_seconds: Some(60),
            impact: "test".into(),
            recovery_cmd: None,
        }
    }

    fn rule(
        id: &str,
        pattern: &str,
        confidence: f32,
        recovery: &str,
        recent_modified_days: Option<u32>,
    ) -> Rule {
        Rule {
            id: id.into(),
            category: "dev-artifact".into(),
            path_pattern: pattern.into(),
            domain: None,
            base_confidence: confidence,
            reason: "test rule".into(),
            exclude_if_recent_access_days: None,
            exclude_if_recent_modified_days: recent_modified_days,
            consequences: Some(cons(recovery)),
            reference_url: None,
        }
    }

    fn entry(path: &str, size: u64, modified_days_ago: i64) -> ScannedEntry {
        ScannedEntry {
            path: PathBuf::from(path),
            size_bytes: size,
            category: Category::DevArtifact,
            modified: Some(Utc::now() - chrono::Duration::days(modified_days_ago)),
            accessed: Some(Utc::now() - chrono::Duration::days(modified_days_ago)),
            dev: None,
            ino: None,
            ctime: None,
        }
    }

    fn scan_with(entries: Vec<ScannedEntry>) -> ScanResult {
        ScanResult {
            scanned_at: Utc::now(),
            root: PathBuf::from("/scan-root"),
            entries,
            total_bytes: 0,
            cloud_placeholder_bytes: 0,
            category_totals: Default::default(),
            schema: 0,
            scan_id: String::new(),
            metrics: None,
            largest_dirs: Vec::new(),
        }
    }

    /// Run the candidates through the same score+recovery tiebreaker comparator
    /// `run()` uses, so tests assert on the ACTUAL ranking order.
    fn sorted(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
        candidates.sort_by(|a, b| {
            b.score()
                .partial_cmp(&a.score())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    recovery_risk_rank(candidate_recovery_class(a))
                        .cmp(&recovery_risk_rank(candidate_recovery_class(b)))
                })
        });
        candidates
    }

    /// #1: one rule, three matching entries at different sizes -> three
    /// candidates (NOT one), largest first after the score sort. Proves the
    /// per-rule `break` is gone.
    #[test]
    fn one_rule_emits_a_candidate_per_matched_entry() {
        let _h = TempHome::new();
        let rules = vec![rule("node_modules", "/proj/**", 0.9, "redownload", None)];
        let scan = scan_with(vec![
            entry("/proj/a/node_modules", 100, 999),
            entry("/proj/b/node_modules", 300, 999),
            entry("/proj/c/node_modules", 200, 999),
        ]);
        let got = build_candidates(&scan, &rules, &test_profile(), "/home/test");
        assert_eq!(
            got.len(),
            3,
            "every surviving matched entry must become a candidate (no `break`)"
        );

        let ranked = sorted(got);
        assert_eq!(
            ranked[0].size_bytes, 300,
            "the largest candidate must rank first after the score sort"
        );
        assert_eq!(ranked[2].size_bytes, 100);
    }

    /// #1: a nested duplicate under a kept ancestor is dropped (ancestor wins).
    #[test]
    fn nested_candidate_under_kept_ancestor_is_dropped() {
        let _h = TempHome::new();
        // One rule matches the parent target/, another matches a nested path
        // inside it. The nested entry's bytes are already inside the ancestor's
        // aggregated size, so only the ANCESTOR is kept.
        let rules = vec![
            rule("target", "/proj/**/target", 0.9, "rebuild", None),
            rule("target_inner", "/proj/**/debug", 0.9, "rebuild", None),
        ];
        let scan = scan_with(vec![
            entry("/proj/target", 1000, 999),
            entry("/proj/target/debug", 600, 999),
        ]);
        let got = build_candidates(&scan, &rules, &test_profile(), "/home/test");
        assert_eq!(
            got.len(),
            1,
            "nested candidate under ancestor must be dropped"
        );
        assert_eq!(got[0].path, PathBuf::from("/proj/target"));
    }

    /// #6: an ACTIVE (recently-modified) rebuild-class target still appears, but
    /// with its confidence decayed (so it ranks below a cold equivalent).
    #[test]
    fn recent_regenerable_target_is_kept_but_decayed() {
        let _h = TempHome::new();
        let rules = vec![rule(
            "target",
            "/proj/**/target",
            0.9,
            "rebuild",
            Some(7), // exclude-if-modified-within 7 days
        )];
        // Modified 1 day ago: well inside the recency window.
        let scan = scan_with(vec![entry("/proj/x/target", 500, 1)]);
        let got = build_candidates(&scan, &rules, &test_profile(), "/home/test");
        assert_eq!(
            got.len(),
            1,
            "recent rebuild-class target must still appear"
        );
        let c = &got[0];
        assert!(
            (c.confidence - 0.9 * RECENCY_DECAY).abs() < 1e-5,
            "confidence must be decayed by RECENCY_DECAY, got {}",
            c.confidence
        );
    }

    /// #6: a recent MANUAL/IRREVERSIBLE item keeps the HARD exclusion.
    #[test]
    fn recent_irreversible_item_stays_excluded() {
        let _h = TempHome::new();
        let rules = vec![rule("vm_disk", "/vms/**", 0.9, "irreversible", Some(30))];
        let scan = scan_with(vec![entry("/vms/win.qcow2", 9000, 2)]);
        let got = build_candidates(&scan, &rules, &test_profile(), "/home/test");
        assert!(
            got.is_empty(),
            "recent irreversible item must remain hard-excluded"
        );
    }

    /// #8: a low-confidence IRREVERSIBLE item must rank BELOW a safe high-conf
    /// regenerable win, even when its raw size×confidence would tie/exceed.
    #[test]
    fn irreversible_low_conf_ranks_below_safe_regenerable() {
        let _h = TempHome::new();
        // Tune sizes so score() is a TIE (0.45*2000 == 0.9*1000 == 900). The
        // recovery-class tiebreaker must then put the safe regenerable first.
        let rules = vec![
            rule("vm_disk", "/vms/**", 0.45, "irreversible", None),
            rule("node_modules", "/proj/**", 0.9, "redownload", None),
        ];
        let scan = scan_with(vec![
            entry("/vms/disk.img", 2000, 999),
            entry("/proj/node_modules", 1000, 999),
        ]);
        let got = build_candidates(&scan, &rules, &test_profile(), "/home/test");
        let ranked = sorted(got);
        assert_eq!(
            candidate_recovery_class(&ranked[0]),
            "redownload",
            "the safe regenerable win must rank first"
        );
        assert_eq!(
            candidate_recovery_class(&ranked[1]),
            "irreversible",
            "the low-confidence irreversible item must rank last"
        );
    }

    /// #3: `detect --json` payload carries the new keys — a top-level `meta`
    /// with `immediate_threshold` (0.85) and the FULL-set reclaimable total, plus
    /// a per-candidate `recommended_command` and inline `recovery_class`.
    #[test]
    fn detect_json_payload_carries_new_keys() {
        let _h = TempHome::new();
        let rules = vec![rule("node_modules", "/proj/**", 0.9, "redownload", None)];
        let scan = scan_with(vec![
            entry("/proj/a/node_modules", 100, 999),
            entry("/proj/b/node_modules", 300, 999),
        ]);
        let mut candidates = build_candidates(&scan, &rules, &test_profile(), "/home/test");
        candidates = sorted(candidates);
        let total: u64 = candidates.iter().map(|c| c.size_bytes).sum();
        let shown: Vec<&Candidate> = candidates.iter().collect();

        let payload = detect_json_payload(&shown, candidates.len(), total);
        let obj = payload.as_object().unwrap();

        // Top-level meta object.
        assert!(obj.contains_key("meta"), "payload must carry a meta object");
        let meta = obj["meta"].as_object().unwrap();
        // (#4) schema_version pins the OBJECT envelope shape (vs. the pre-P2 array).
        assert_eq!(
            meta["schema_version"].as_u64().unwrap(),
            DETECT_JSON_SCHEMA_VERSION as u64,
            "meta must carry the detect --json schema_version"
        );
        assert_eq!(
            meta["immediate_threshold"],
            serde_json::json!(crate::commands::explain::IMMEDIATE_THRESHOLD)
        );
        assert!(
            (meta["immediate_threshold"].as_f64().unwrap() - 0.85_f64).abs() < 1e-6,
            "immediate_threshold must be 0.85, got {}",
            meta["immediate_threshold"]
        );
        assert_eq!(
            meta["total_reclaimable_bytes"].as_u64().unwrap(),
            total,
            "meta must report the FULL-set reclaimable total"
        );
        assert_eq!(meta["total_candidates"].as_u64().unwrap(), 2);

        // Per-candidate recommended_command + recovery_class.
        let cands = obj["candidates"].as_array().unwrap();
        assert_eq!(cands.len(), 2);
        for c in cands {
            let co = c.as_object().unwrap();
            assert!(
                co.contains_key("recommended_command"),
                "each candidate must carry recommended_command"
            );
            assert!(
                co.contains_key("recovery_class"),
                "each candidate must carry recovery_class"
            );
            assert_eq!(co["recovery_class"], serde_json::json!("redownload"));
            // The legacy per-candidate keys are still present (additive change).
            assert!(co.contains_key("id") && co.contains_key("size_bytes"));
            // recommended_command must be the explain helper's output (non-empty,
            // and for a safe high-confidence redownload it recommends a reclaim).
            assert!(!co["recommended_command"].as_str().unwrap().is_empty());
        }
    }

    /// #1: TWO different rules matching the SAME path must collapse to exactly
    /// ONE candidate, so the path is listed once and its bytes are counted once
    /// in `total_reclaimable_all`. The higher-confidence rule wins. Without the
    /// exact-duplicate dedup, the ancestor `retain` (guarded by `*other != c.path`)
    /// would let both survive and re-introduce the double-count.
    #[test]
    fn exact_duplicate_path_from_two_rules_collapses_to_one() {
        let _h = TempHome::new();
        // Same path matched by a generic cache rule (0.7) and a vendor rule (0.9).
        let rules = vec![
            rule(
                "cache_generic",
                "/u/Library/Caches/**",
                0.7,
                "redownload",
                None,
            ),
            rule(
                "vendor_foo",
                "/u/Library/Caches/foo",
                0.9,
                "redownload",
                None,
            ),
        ];
        let scan = scan_with(vec![entry("/u/Library/Caches/foo", 4096, 999)]);
        let got = build_candidates(&scan, &rules, &test_profile(), "/home/test");
        assert_eq!(
            got.len(),
            1,
            "an identical path matched by two rules must yield exactly one candidate"
        );
        assert_eq!(got[0].path, PathBuf::from("/u/Library/Caches/foo"));
        // The kept candidate is the higher-confidence one.
        assert!(
            (got[0].confidence - 0.9).abs() < 1e-5,
            "the highest-confidence duplicate must be the one kept, got {}",
            got[0].confidence
        );
        // Bytes are counted ONCE (the regression this guards against).
        let total: u64 = got.iter().map(|c| c.size_bytes).sum();
        assert_eq!(total, 4096, "bytes must be counted once, not doubled");
    }

    /// #3: a recency-DECAYED regenerable candidate (effective confidence below
    /// IMMEDIATE_THRESHOLD even though its rule's base is high) must NOT be told
    /// to `--immediate` permanently delete. The serialized `confidence` and the
    /// `recommended_command` must agree.
    #[test]
    fn recency_decayed_candidate_is_not_recommended_immediate() {
        let _h = TempHome::new();
        // base 0.9 redownload, recency-windowed; touched 1 day ago -> decayed to
        // 0.9 * 0.6 = 0.54, which is below IMMEDIATE_THRESHOLD (0.85).
        let rules = vec![rule(
            "node_modules",
            "/proj/**/node_modules",
            0.9,
            "redownload",
            Some(14),
        )];
        let scan = scan_with(vec![entry("/proj/x/node_modules", 5000, 1)]);
        let got = build_candidates(&scan, &rules, &test_profile(), "/home/test");
        assert_eq!(
            got.len(),
            1,
            "recent regenerable candidate must still appear"
        );
        let c = &got[0];
        assert!(
            c.confidence < crate::commands::explain::IMMEDIATE_THRESHOLD,
            "precondition: confidence must be decayed below threshold, got {}",
            c.confidence
        );

        let shown: Vec<&Candidate> = got.iter().collect();
        let payload = detect_json_payload(&shown, got.len(), 5000);
        let cand = &payload.as_object().unwrap()["candidates"]
            .as_array()
            .unwrap()[0];
        let rec = cand["recommended_command"].as_str().unwrap();
        assert!(
            !rec.contains("--immediate"),
            "a decayed candidate must NOT get an --immediate recommendation, got: {rec}"
        );
        assert!(
            rec.contains("Airlock (reversible)"),
            "a decayed candidate must get the reversible airlock recommendation, got: {rec}"
        );
        // And the serialized confidence agrees with the demoted ranking.
        assert!(
            (cand["confidence"].as_f64().unwrap() - (0.9 * RECENCY_DECAY) as f64).abs() < 1e-5,
            "serialized confidence must reflect the decay"
        );
    }

    #[test]
    fn is_regenerable_classifies_correctly() {
        for c in ["auto", "redownload", "rebuild", "recreate"] {
            assert!(is_regenerable(c), "{c} must be regenerable");
        }
        for c in ["manual", "irreversible", ""] {
            assert!(!is_regenerable(c), "{c} must NOT be regenerable");
        }
    }

    #[test]
    fn recovery_risk_rank_orders_safe_before_risky() {
        assert!(recovery_risk_rank("auto") < recovery_risk_rank("irreversible"));
        assert!(recovery_risk_rank("redownload") < recovery_risk_rank("manual"));
        assert!(recovery_risk_rank("rebuild") < recovery_risk_rank("irreversible"));
    }

    /// An RAII `$HOME` override so enrichment's `compute_metrics` reads a fresh
    /// tempdir, NEVER the real `~/.diskspace`. Holds the crate-wide
    /// `HOME_TEST_LOCK` for its whole lifetime (matching `doctor`/`watch`/
    /// `selfcheck`), and restores the prior `$HOME` on drop.
    struct TempHome {
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
                "diskspace-detect-home-{}-{}",
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
                prev,
                _guard: guard,
            }
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
        }
    }
}

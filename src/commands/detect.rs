use anyhow::{Context as _, Result};
use console::Style;
use std::path::Path;

use crate::commands::scan::scan_cache_path;
use crate::core::candidate::{Candidate, Category};
use crate::core::rules::{self, Rule};
use crate::core::scanner::ScanResult;
use crate::output::{self, Context};
use crate::profile::{self, Profile};

pub fn run(show_all: bool, top: usize, ctx: &Context) -> Result<()> {
    let cache = scan_cache_path();
    if !cache.exists() {
        if ctx.json {
            eprintln!(r#"{{"error":"no scan found","hint":"run disk-advisor scan first"}}"#);
        } else {
            eprintln!("  No scan found. Run `disk-advisor scan` first.");
        }
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(&cache).context("reading scan cache")?;
    let scan: ScanResult = serde_json::from_str(&content).context("parsing scan cache")?;
    let rules = rules::load_builtin()?;
    let prof = profile::load()?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());

    let mut candidates = build_candidates(&scan, &rules, &prof, &home);

    // Sort by yield × confidence descending
    candidates.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap());

    let shown: Vec<&Candidate> = if show_all {
        candidates.iter().collect()
    } else {
        candidates.iter().take(top).collect()
    };

    if ctx.json {
        println!("{}", serde_json::to_string_pretty(&shown)?);
        return Ok(());
    }

    if shown.is_empty() {
        println!("\n  No candidates found. Your disk looks clean!\n");
        return Ok(());
    }

    let bold = Style::new().bold();
    let dim = Style::new().dim();
    let green_bold = Style::new().green().bold();

    let total_reclaimable: u64 = shown.iter().map(|c| c.size_bytes).sum();

    println!();
    let header = format!(
        "  {} candidate{}  ·  {} reclaimable{}",
        shown.len(),
        if shown.len() == 1 { "" } else { "s" },
        output::format_bytes(total_reclaimable),
        if !show_all && candidates.len() > top {
            format!("  ·  {} total", candidates.len())
        } else {
            String::new()
        }
    );
    println!("{}", ctx.style(&header, &bold));
    println!("  {}", ctx.style(&output::rule("", 56), &dim));
    println!();

    for (i, c) in shown.iter().enumerate() {
        let cat_style = output::category_style(&c.category.to_string());
        let icon = output::category_icon(&c.category.to_string());
        let rank = format!("{:>2}.", i + 1);

        // Top line: rank · icon · category · size
        println!(
            "  {} {}  {}  {:>9}",
            ctx.style(&rank, &dim),
            ctx.style(icon, &cat_style),
            ctx.style(&c.category.to_string(), &cat_style),
            ctx.style(&output::format_bytes(c.size_bytes), &bold),
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
        "  {}  disk-advisor check <id>",
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

            // Decay if recently accessed
            if let Some(days) = rule.exclude_if_recent_access_days {
                if let Some(accessed) = entry.accessed {
                    let age_days = chrono::Utc::now()
                        .signed_duration_since(accessed)
                        .num_days();
                    if age_days < days as i64 {
                        continue;
                    }
                }
            }

            // Decay if recently modified
            if let Some(days) = rule.exclude_if_recent_modified_days {
                if let Some(modified) = entry.modified {
                    let age_days = chrono::Utc::now()
                        .signed_duration_since(modified)
                        .num_days();
                    if age_days < days as i64 {
                        continue;
                    }
                }
            }

            let id = format!(
                "{}-{}",
                rule.id,
                &format!("{:x}", md5_short(&entry.path.to_string_lossy()))
            );

            candidates.push(Candidate {
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
            });

            // Only match first entry per rule to avoid duplicates from glob walking
            break;
        }
    }

    candidates
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

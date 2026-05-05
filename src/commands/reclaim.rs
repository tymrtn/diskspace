use anyhow::{Context as _, Result};
use console::Style;
use std::path::Path;

use crate::commands::check;
use crate::commands::detect::build_candidates_pub;
use crate::commands::scan::scan_cache_path;
use crate::core::candidate::Candidate;
use crate::core::scanner::ScanResult;
use crate::output::{self, Context};
use crate::profile;

const MIN_CONFIDENCE: f32 = 0.85;

pub fn run(top: usize, ctx: &Context) -> Result<()> {
    let cache = scan_cache_path();
    if !cache.exists() {
        if ctx.json {
            eprintln!(r#"{{"error":"no scan found","hint":"run disk-space scan first"}}"#);
        } else {
            eprintln!("\n  No scan found. Run `disk-space scan` first.\n");
        }
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(&cache).context("reading scan cache")?;
    let scan: ScanResult = serde_json::from_str(&content).context("parsing scan cache")?;
    let rules = crate::core::rules::load_builtin()?;
    let prof = profile::load()?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());

    let candidates = build_candidates_pub(&scan, &rules, &prof, &home);

    let mut high_conf: Vec<Candidate> = candidates
        .into_iter()
        .filter(|c| c.confidence >= MIN_CONFIDENCE)
        .take(top)
        .collect();

    if high_conf.is_empty() {
        if ctx.json {
            println!(r#"{{"reclaimed":[],"message":"no high-confidence candidates"}}"#);
        } else {
            println!(
                "\n  No candidates at confidence ≥ {:.0}%. Run `disk-space detect` and use `airlock` for lower-confidence items.\n",
                MIN_CONFIDENCE * 100.0
            );
        }
        return Ok(());
    }

    // Pressure-test each
    let mut survivors: Vec<Candidate> = Vec::new();
    let mut blocked: Vec<(Candidate, String)> = Vec::new();
    for c in high_conf.drain(..) {
        let result = check::pressure_test(&c.id, &c.path, &prof)?;
        if result.safe {
            survivors.push(c);
        } else {
            let note = result
                .steps
                .iter()
                .find(|s| !s.passed)
                .map(|s| s.note.clone())
                .unwrap_or_else(|| "blocked".into());
            blocked.push((c, note));
        }
    }

    let total_bytes: u64 = survivors.iter().map(|c| c.size_bytes).sum();
    let free_before = free_bytes(Path::new(&home));

    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let red = Style::new().red().bold();
    let yellow = Style::new().yellow();
    let green = Style::new().green().bold();

    if !ctx.json {
        println!();
        println!(
            "  {}",
            ctx.style(&output::rule("reclaim  ·  jettisoning cargo", 56), &dim)
        );
        println!();
        if let Some(fb) = free_before {
            println!(
                "  {}  {}  free now",
                ctx.style("disk", &dim),
                ctx.style(&output::format_bytes(fb), &bold),
            );
            println!();
        }

        for c in &survivors {
            println!(
                "  {}  {:>9}  {}  {}",
                ctx.style("✓", &green),
                ctx.style(&output::format_bytes(c.size_bytes), &bold),
                ctx.style(&format!("{:>4.0}%", c.confidence * 100.0), &yellow),
                ctx.style(&c.path.display().to_string(), &dim),
            );
        }
        for (c, note) in &blocked {
            println!(
                "  {}  {:>9}  {}  {}  {}",
                ctx.style("✗", &red),
                ctx.style(&output::format_bytes(c.size_bytes), &dim),
                ctx.style(&format!("{:>4.0}%", c.confidence * 100.0), &dim),
                ctx.style(&c.path.display().to_string(), &dim),
                ctx.style(&format!("(skipped: {})", note), &dim),
            );
        }

        println!();
        println!(
            "  {}  {}  ready to permanently delete  ·  {} blocked",
            ctx.style("→", &yellow),
            ctx.style(&output::format_bytes(total_bytes), &bold),
            blocked.len(),
        );
        println!();
    }

    if survivors.is_empty() {
        if ctx.json {
            println!(r#"{{"reclaimed":[],"message":"all candidates blocked by pressure test"}}"#);
        } else {
            println!("  Nothing to reclaim — all candidates blocked.\n");
        }
        return Ok(());
    }

    if !ctx.json && !ctx.yes {
        let prompt = format!(
            "  Permanently delete {} item(s) totaling {}? This cannot be undone.",
            survivors.len(),
            output::format_bytes(total_bytes)
        );
        if !ctx.confirm(&prompt) {
            println!("  Aborted.");
            return Ok(());
        }
    }

    let mut deleted: Vec<serde_json::Value> = Vec::new();
    let mut deleted_bytes: u64 = 0;
    for c in &survivors {
        let result = if c.path.is_dir() {
            std::fs::remove_dir_all(&c.path)
        } else {
            std::fs::remove_file(&c.path)
        };
        match result {
            Ok(_) => {
                deleted_bytes += c.size_bytes;
                deleted.push(serde_json::json!({
                    "id": c.id,
                    "path": c.path,
                    "size_bytes": c.size_bytes,
                }));
                if !ctx.json {
                    println!(
                        "  {}  {} freed  {}",
                        ctx.style("✓", &red),
                        ctx.style(&output::format_bytes(c.size_bytes), &bold),
                        ctx.style(&c.path.display().to_string(), &dim),
                    );
                }
            }
            Err(e) => {
                if !ctx.json {
                    eprintln!(
                        "  {}  failed: {}  ({})",
                        ctx.style("✗", &red),
                        c.path.display(),
                        e
                    );
                }
            }
        }
    }

    let free_after = free_bytes(Path::new(&home));

    if ctx.json {
        let out = serde_json::json!({
            "reclaimed": deleted,
            "bytes_deleted": deleted_bytes,
            "free_before": free_before,
            "free_after": free_after,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!();
        if let (Some(before), Some(after)) = (free_before, free_after) {
            let delta = after.saturating_sub(before);
            println!(
                "  {}  {} → {}  ({} freed)",
                ctx.style("disk", &bold),
                ctx.style(&output::format_bytes(before), &dim),
                ctx.style(&output::format_bytes(after), &green),
                ctx.style(&output::format_bytes(delta), &bold),
            );
        } else {
            println!(
                "  {}  {} freed",
                ctx.style("✓", &green),
                ctx.style(&output::format_bytes(deleted_bytes), &bold),
            );
        }
        println!();
    }

    Ok(())
}

/// Free bytes available on the filesystem containing `path`. Uses `df -k`.
fn free_bytes(path: &Path) -> Option<u64> {
    let output = std::process::Command::new("df")
        .arg("-k")
        .arg(path)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().nth(1)?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    let kb_avail: u64 = fields.get(3)?.parse().ok()?;
    Some(kb_avail * 1024)
}

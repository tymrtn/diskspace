use anyhow::Result;
use console::Style;
use indicatif::{ProgressBar, ProgressStyle};
use jwalk::WalkDir;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::core::rules;
use crate::core::scanner::expand_home;
use crate::output::{self, Context};

/// `diskspace hunt` — surfaces the largest directories that no rule covers.
/// The long-tail finder. Use this when `detect` looks empty but the disk is full.
#[derive(Debug, Serialize)]
struct HuntCandidate {
    path: PathBuf,
    size_bytes: u64,
    depth: usize,
}

pub fn run(top: usize, min_size_mb: u64, ctx: &Context) -> Result<()> {
    let home = dirs_home();
    let rule_list = rules::load_builtin()?;

    // Build a set of "covered" path prefixes from rules whose patterns are concrete
    // (i.e. don't contain glob metacharacters). Globby rules like `**/node_modules`
    // can't be turned into a prefix, so we conservatively skip — `hunt` may surface
    // paths those globs would later catch. That's fine: `detect` is the right tool
    // for those, and `hunt` is for what falls through.
    let covered: Vec<PathBuf> = rule_list
        .iter()
        .filter_map(|r| {
            let resolved = expand_home(&r.path_pattern, &home);
            if resolved.contains('*') || resolved.contains('?') || resolved.contains('[') {
                None
            } else {
                Some(PathBuf::from(resolved))
            }
        })
        .collect();

    let spinner = if !ctx.json && !ctx.quiet {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("Hunting in {}…", home.display()));
        pb.enable_steady_tick(Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    // Walk and aggregate directory sizes
    let mut dir_sizes: HashMap<PathBuf, u64> = HashMap::new();

    for entry in WalkDir::new(&home)
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

        // Use on-disk allocation, not logical size — sparse files (like virtual disk
        // images) report huge logical sizes but only allocate what they're actually using.
        let size: u64;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // Cloud-only placeholder: logical size > 0 but no blocks allocated → skip
            if metadata.len() > 4096 && metadata.blocks() == 0 {
                continue;
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

        // Walk up parents and accumulate, but stop at $HOME
        let mut p = path.parent();
        while let Some(parent) = p {
            *dir_sizes.entry(parent.to_path_buf()).or_insert(0) += size;
            if parent == home {
                break;
            }
            p = parent.parent();
        }
    }

    if let Some(pb) = &spinner {
        pb.finish_and_clear();
    }

    let min_size = min_size_mb * 1024 * 1024;
    let max_depth = 2usize; // depth 1 = ~/foo, depth 2 = ~/foo/bar

    // Pick directories at depth 1-2 from home, bigger than threshold, NOT covered by a rule.
    // We also skip a directory if a parent of it is already going to be reported (avoid showing
    // both ~/foo and ~/foo/bar — the parent's size already includes the child).
    let mut candidates: Vec<HuntCandidate> = dir_sizes
        .iter()
        .filter_map(|(path, &size)| {
            if size < min_size {
                return None;
            }
            let depth = depth_from(path, &home)?;
            if depth == 0 || depth > max_depth {
                return None;
            }
            if is_covered(path, &covered) {
                return None;
            }
            Some(HuntCandidate {
                path: path.clone(),
                size_bytes: size,
                depth,
            })
        })
        .collect();

    candidates.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

    // Dedupe nested: if a parent is in the result set, drop the child
    let mut chosen: Vec<HuntCandidate> = Vec::with_capacity(candidates.len());
    for c in candidates {
        let parent_in_set = chosen.iter().any(|p| c.path.starts_with(&p.path));
        if !parent_in_set {
            chosen.push(c);
        }
    }
    chosen.truncate(top);

    if ctx.json {
        let out: Vec<_> = chosen
            .iter()
            .map(|c| {
                serde_json::json!({
                    "path": c.path,
                    "size_bytes": c.size_bytes,
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

    let total: u64 = chosen.iter().map(|c| c.size_bytes).sum();
    println!(
        "  {} {}  total in {} unrule'd dirs",
        ctx.style("→", &yellow),
        ctx.style(&output::format_bytes(total), &bold),
        chosen.len(),
    );
    println!();

    let max = chosen.first().map(|c| c.size_bytes).unwrap_or(1);
    for c in &chosen {
        let bar = output::size_bar(c.size_bytes, max, 18);
        let size_str = output::format_bytes(c.size_bytes);
        println!(
            "  {} {:>9}  {}  {}",
            ctx.style("◇", &magenta),
            ctx.style(&size_str, &bold),
            ctx.style(&bar, &magenta),
            ctx.style(&c.path.display().to_string(), &dim),
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

/// Returns Some(depth) if `path` is `home/<a>/<b>/...`, where depth is the number of
/// path components past `home`. Returns None if `path` isn't under `home`.
fn depth_from(path: &Path, home: &Path) -> Option<usize> {
    let rel = path.strip_prefix(home).ok()?;
    Some(rel.components().count())
}

fn is_covered(path: &Path, covered: &[PathBuf]) -> bool {
    covered
        .iter()
        .any(|c| path.starts_with(c) || c.starts_with(path))
}

use console::{Style, Term};

pub struct Context {
    pub json: bool,
    #[allow(dead_code)]
    pub yes: bool,
    pub no_color: bool,
    pub verbose: bool,
    pub quiet: bool,
}

impl Context {
    pub fn style(&self, s: &str, style: &Style) -> String {
        if self.no_color {
            s.to_string()
        } else {
            style.apply_to(s).to_string()
        }
    }

    #[allow(dead_code)]
    pub fn confirm(&self, prompt: &str) -> bool {
        if self.yes || self.json {
            return true;
        }
        let term = Term::stderr();
        eprint!("{} [y/N] ", prompt);
        if let Ok(line) = term.read_line() {
            matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
        } else {
            false
        }
    }

    /// Require the user to retype an exact id verbatim. Used for high-stakes
    /// bypasses of safety gates (per-target typed consent). `--yes` does NOT
    /// auto-pass this — that's the whole point.
    pub fn confirm_typed_id(&self, id: &str) -> bool {
        if self.json {
            // Agents that opt out of consent flow get a non-pass here unless
            // they've also pre-supplied the id elsewhere (we don't here).
            return false;
        }
        let term = Term::stderr();
        eprintln!();
        eprintln!(
            "  Type the candidate id verbatim to confirm: {}",
            self.style(id, &Style::new().yellow().bold())
        );
        eprint!("  > ");
        match term.read_line() {
            Ok(line) => line.trim() == id,
            Err(_) => false,
        }
    }
}

/// Render a confidence bar like [████████░░] 80%
pub fn confidence_bar(score: f32, width: usize) -> String {
    let filled = (score * width as f32).round() as usize;
    let empty = width.saturating_sub(filled);
    format!(
        "[{}{}] {:.0}%",
        "█".repeat(filled),
        "░".repeat(empty),
        score * 100.0
    )
}

/// Format bytes as human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const GB: u64 = 1_073_741_824;
    const MB: u64 = 1_048_576;
    const KB: u64 = 1_024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.0} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.0} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Inline horizontal bar using block gradient chars for visual weight
pub fn size_bar(bytes: u64, max_bytes: u64, width: usize) -> String {
    if max_bytes == 0 {
        return "░".repeat(width);
    }
    let ratio = bytes as f64 / max_bytes as f64;
    let filled = (ratio * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width.saturating_sub(filled);
    // Use gradient blocks for the filled portion: taper off at the end
    let bar: String = (0..filled)
        .map(|i| {
            if filled < 3 || i < filled.saturating_sub(2) {
                '█'
            } else if i == filled.saturating_sub(2) {
                '▓'
            } else {
                '▒'
            }
        })
        .collect();
    format!("{}{}", bar, "░".repeat(empty))
}

/// Unicode sparkline: bucket `values` into `width` buckets (mean per bucket)
/// and render each with the ▁▂▃▄▅▆▇█ gradient, scaled to the series' own
/// min..max. Fewer values than buckets renders one char per value. An empty
/// series yields an empty string; a flat series renders mid-height so it reads
/// as "signal present, no movement" rather than a floor.
pub fn sparkline(values: &[f64], width: usize) -> String {
    const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if values.is_empty() || width == 0 {
        return String::new();
    }
    // Mean-per-bucket downsample so a 2000-sample week fits any width.
    let buckets: Vec<f64> = if values.len() <= width {
        values.to_vec()
    } else {
        (0..width)
            .map(|i| {
                let lo = i * values.len() / width;
                let hi = (((i + 1) * values.len()) / width).max(lo + 1);
                values[lo..hi].iter().sum::<f64>() / (hi - lo) as f64
            })
            .collect()
    };
    let min = buckets.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = buckets.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let span = max - min;
    buckets
        .iter()
        .map(|v| {
            if span <= f64::EPSILON {
                LEVELS[3] // flat series → mid-height
            } else {
                let idx = ((v - min) / span * (LEVELS.len() - 1) as f64).round() as usize;
                LEVELS[idx.min(LEVELS.len() - 1)]
            }
        })
        .collect()
}

/// Icon for a category (plain ASCII-art style, no emoji)
pub fn category_icon(category: &str) -> &'static str {
    match category {
        "dev-artifact" => "◈",
        "app-cache" => "◉",
        "download-entropy" => "◎",
        "vm-disk" => "▣",
        _ => "·",
    }
}

/// Style for a category
pub fn category_style(category: &str) -> Style {
    match category {
        "dev-artifact" => Style::new().yellow(),
        "app-cache" => Style::new().cyan(),
        "download-entropy" => Style::new().magenta(),
        "vm-disk" => Style::new().red(),
        _ => Style::new().dim(),
    }
}

/// Draw a horizontal rule with an optional centered label
///   ── label ────────────────────
pub fn rule(label: &str, width: usize) -> String {
    if label.is_empty() {
        "─".repeat(width)
    } else {
        let inner = format!(" {} ", label);
        let dashes = width.saturating_sub(inner.len() + 2);
        let left = dashes / 2;
        let right = dashes - left;
        format!("{}{}{}", "─".repeat(left), inner, "─".repeat(right))
    }
}

/// Draw a padded box header
///   ╭─ title ──────────────────╮
///   ╰──────────────────────────╯
pub fn box_line(label: &str, width: usize) -> (String, String) {
    let inner = format!("─ {} ", label);
    let dashes = width.saturating_sub(inner.len() + 2);
    let top = format!("╭{}{}╮", inner, "─".repeat(dashes));
    let bottom = format!("╰{}╯", "─".repeat(width.saturating_sub(2)));
    (top, bottom)
}

//! Cross-platform filesystem utilities — the ONE place diskspace shells out to
//! `df`.
//!
//! Historically `watch.rs`, `history.rs`, and `reclaim.rs` each re-implemented a
//! `df -k` parse keyed off macOS column positions. That breaks on Linux: GNU
//! `coreutils` `df` wraps a long device name onto its own line, shifting every
//! field by one and silently mis-reading the "available" column. The portable
//! fix is `df -kP` — POSIX mode (`-P`) guarantees exactly six columns on ONE
//! physical line on BOTH macOS (BSD `df`) and Linux (GNU `df`):
//!
//! ```text
//! Filesystem 1024-blocks Used Available Capacity Mounted on
//! ```
//!
//! We parse the SECOND line (the data row), splitting on whitespace, and read
//! field index 1 (total KiB) and index 3 (available KiB). Because `-P` collapses
//! the wrapped device name back onto one line, the column indices are stable
//! across platforms.
//!
//! Everything is in KiB (`-k`), which we multiply to bytes. This is the single
//! consolidated parser; all callers funnel through [`df_free_and_total`] (or the
//! [`free_bytes`] convenience wrapper).

use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::process::Command;

/// Free + total bytes for the filesystem containing `path`.
///
/// Shells out to `df -kP <path>` (POSIX portable format) and returns
/// `(free_bytes, total_bytes)`. The POSIX `-P` flag is what makes this work on
/// Linux as well as macOS: it forces one data row with stable columns even when
/// the device name is long enough that GNU `df` would otherwise line-wrap it.
pub fn df_free_and_total(path: &Path) -> Result<(u64, u64)> {
    let output = Command::new("df")
        .arg("-kP")
        .arg(path)
        .output()
        .context("spawning `df -kP`")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_df_kp(&stdout)
}

/// Convenience wrapper: just the free bytes for the filesystem at `path`, or
/// `None` if `df` fails or its output can't be parsed. Mirrors the old
/// `history::free_bytes` signature so the many `.unwrap_or(...)` callers don't
/// change shape.
pub fn free_bytes(path: &Path) -> Option<u64> {
    df_free_and_total(path).ok().map(|(free, _total)| free)
}

/// Parse the text output of `df -kP`. Split out from the spawn so it is unit
/// testable against captured macOS- and Linux-style samples.
///
/// Returns `(free_bytes, total_bytes)`. POSIX `-P` guarantees the data row is a
/// single physical line with columns:
///   `Filesystem 1024-blocks Used Available Capacity Mounted-on`
/// so index 1 is the total and index 3 is the available, in KiB.
fn parse_df_kp(stdout: &str) -> Result<(u64, u64)> {
    let line = stdout
        .lines()
        .nth(1)
        .ok_or_else(|| anyhow!("df returned no data row"))?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    let total_kb: u64 = fields
        .get(1)
        .ok_or_else(|| anyhow!("df: missing total (1024-blocks) column"))?
        .parse()
        .context("df: total column not an integer")?;
    let avail_kb: u64 = fields
        .get(3)
        .ok_or_else(|| anyhow!("df: missing available column"))?
        .parse()
        .context("df: available column not an integer")?;
    Ok((avail_kb * 1024, total_kb * 1024))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// macOS (BSD) `df -kP /` — short device name, one data row. Columns:
    /// Filesystem 1024-blocks Used Available Capacity Mounted on
    const MACOS_SAMPLE: &str = "\
Filesystem 1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1s1 971350180 21500000 800000000    13%    /
";

    /// Linux (GNU) `df -kP /` — note the LONG device name. Under plain `df -k`
    /// GNU wraps this onto its own line, shifting the data columns; `-P` (POSIX)
    /// collapses it back onto ONE line, which is exactly why we use `-kP`. This
    /// sample is the single-line POSIX form we actually parse.
    const LINUX_SAMPLE: &str = "\
Filesystem                          1024-blocks     Used Available Capacity Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv      102626232 41234560  56123456      43% /
";

    #[test]
    fn parses_macos_df_kp() {
        let (free, total) = parse_df_kp(MACOS_SAMPLE).unwrap();
        assert_eq!(total, 971_350_180 * 1024, "total = 1024-blocks * 1024");
        assert_eq!(free, 800_000_000 * 1024, "free = available * 1024");
    }

    #[test]
    fn parses_linux_df_kp_with_long_device_name() {
        // The long LVM device name is the failure mode that broke the old
        // macOS-column parser on Linux. With `-P` it is a single line and the
        // available column is still index 3.
        let (free, total) = parse_df_kp(LINUX_SAMPLE).unwrap();
        assert_eq!(total, 102_626_232 * 1024);
        assert_eq!(free, 56_123_456 * 1024);
    }

    #[test]
    fn missing_data_row_errors() {
        let header_only = "Filesystem 1024-blocks Used Available Capacity Mounted on\n";
        assert!(parse_df_kp(header_only).is_err());
    }

    #[test]
    fn non_numeric_columns_error() {
        let garbage = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                       /dev/x notanumber 0 alsonot 0% /\n";
        assert!(parse_df_kp(garbage).is_err());
    }
}

//! Integration guard for finding-6: `diskspace selfcheck --measurement` must be
//! READ-ONLY against the user's real `~/.diskspace` measurement store.
//!
//! This guard runs the ACTUAL BUILT BINARY as a subprocess with `$HOME` pointed
//! at a throwaway tempdir. That is the one thing a `#[cfg(test)]` unit test cannot
//! do: in the test build, the scanner's `series_append_batch` seam used to route
//! to the temp `base` correctly while the SHIPPED (`#[cfg(not(test))]`) build
//! discarded `base` and appended to the real `series.jsonl`. Because we exercise
//! the non-test binary here, a regression that re-introduces that cfg split (or
//! any production write that ignores the scratch base) turns this red — the test
//! build can no longer mask it.
//!
//! Mechanism: a fresh `$HOME` starts with NO `.diskspace`. The gate writes all of
//! its series/df/tick scratch under its own `/tmp/diskspace-selfcheck-*` dir, so
//! after a successful `selfcheck --measurement` the fake `$HOME/.diskspace` must
//! still contain none of the measurement stores (`series.jsonl`, `df_series.jsonl`,
//! `tick_state.json`, `series.daily.jsonl`).

use std::path::PathBuf;
use std::process::Command;

/// Unique throwaway dir under the OS temp dir, removed on drop.
struct TmpHome {
    path: PathBuf,
}
impl TmpHome {
    fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "diskspace-it-home-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self { path: p }
    }
}
impl Drop for TmpHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn selfcheck_measurement_does_not_write_real_data_dir() {
    let bin = env!("CARGO_BIN_EXE_diskspace");
    let home = TmpHome::new();

    // Run the real gate against the fake $HOME. `--json` keeps output stable and
    // non-interactive; the first-run wizard auto-skips in non-TTY contexts.
    let output = Command::new(bin)
        .args(["selfcheck", "--measurement", "--json"])
        .env("HOME", &home.path)
        .output()
        .expect("failed to spawn diskspace selfcheck");

    assert!(
        output.status.success(),
        "selfcheck --measurement should exit 0 on a healthy setup; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // The load-bearing assertion: the gate must NOT have created the user's real
    // measurement store under the fake $HOME. `.diskspace` may exist (profile
    // bootstrap), but none of the measurement files may.
    let data = home.path.join(".diskspace");
    for f in [
        "series.jsonl",
        "df_series.jsonl",
        "tick_state.json",
        "series.daily.jsonl",
    ] {
        let p = data.join(f);
        assert!(
            !p.exists(),
            "finding-6 regression: selfcheck --measurement wrote {} into the real \
             data dir — the gate must write ONLY to its temp scratch base",
            p.display()
        );
    }
}

//! Integration guard for P4: the AGENT-PATH GRANT GATE.
//!
//! Under the `actuation` feature, an autonomous/non-interactive mutating entry
//! point REQUIRES a valid grant. Without one it must refuse with a
//! machine-parseable `no_grant` marker and a non-zero exit, BEFORE doing any work
//! (and WITHOUT deleting or airlocking anything). This is the documented behavior
//! change. We lock it at EVERY mutating non-interactive entry point:
//!   * `doctor --json`            (gates on `--json`/`--yes`)
//!   * `apply --json <hash>`      (gates on `--json`/`--yes`)
//!   * `guard --json --exec …`    (ALWAYS non-interactive — gates unconditionally)
//!
//! We exercise the ACTUAL BUILT BINARY as a subprocess (so the `#[cfg(test)]`
//! seams can't mask the shipped behavior) with `$HOME` pointed at a throwaway
//! tempdir. The whole file is gated on `actuation`: without the feature the gate
//! does not exist and these commands behave as before, so there is nothing to
//! assert here.
#![cfg(feature = "actuation")]

use std::path::PathBuf;
use std::process::Command;

/// Unique throwaway `$HOME` under the OS temp dir, removed on drop.
struct TmpHome {
    path: PathBuf,
}
impl TmpHome {
    fn new(tag: &str) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "diskspace-grant-it-{}-{}-{}",
            tag,
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

/// `doctor --json` with NO grant present must refuse with `no_grant` and a
/// non-zero exit, mutating nothing.
#[test]
fn doctor_json_without_grant_refuses_with_no_grant() {
    let bin = env!("CARGO_BIN_EXE_diskspace");
    let home = TmpHome::new("nogrant");

    let output = Command::new(bin)
        .args(["doctor", "--json"])
        .env("HOME", &home.path)
        .output()
        .expect("failed to spawn diskspace doctor");

    assert!(
        !output.status.success(),
        "doctor --json with no grant must exit non-zero; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The machine-parseable refusal must appear on stdout (agents parse stdout).
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim().lines().last().unwrap_or(""))
            .or_else(|_| serde_json::from_str(stdout.trim()))
            .unwrap_or_else(|_| {
                panic!("expected a JSON object on stdout, got: {stdout}");
            });
    assert_eq!(
        parsed["error"], "no_grant",
        "doctor --json with no grant must emit error=no_grant; got: {stdout}"
    );
}

/// `doctor` WITHOUT `--json`/`--yes` (interactive) is NOT subject to the agent
/// gate — it falls through to the human path. With no candidates to free and a
/// fresh tempdir it bails early (already-sufficient or no-candidates), never
/// emitting `no_grant`. We assert the gate did NOT trip (no `no_grant` token).
#[test]
fn doctor_interactive_without_grant_is_not_gated() {
    let bin = env!("CARGO_BIN_EXE_diskspace");
    let home = TmpHome::new("interactive");

    // No --json and no --yes: this is the interactive (human) path. We pipe no
    // stdin; the run either bails early (already-sufficient/no-candidates) or
    // prints the intro — in NO case should it print the agent `no_grant` refusal.
    let output = Command::new(bin)
        .args(["doctor"])
        .env("HOME", &home.path)
        .output()
        .expect("failed to spawn diskspace doctor");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("no_grant"),
        "interactive doctor must NOT hit the agent grant gate; output=\n{combined}"
    );
}

/// `apply --json <hash>` with NO grant present must refuse with `no_grant` and a
/// non-zero exit, BEFORE loading the plan. (apply gates on `--json`/`--yes` like
/// doctor.) Any hash works — the gate runs ahead of plan resolution.
#[test]
fn apply_json_without_grant_refuses_with_no_grant() {
    let bin = env!("CARGO_BIN_EXE_diskspace");
    let home = TmpHome::new("apply-nogrant");

    let output = Command::new(bin)
        .args(["apply", "deadbeef", "--json"])
        .env("HOME", &home.path)
        .output()
        .expect("failed to spawn diskspace apply");

    assert!(
        !output.status.success(),
        "apply --json with no grant must exit non-zero; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim().lines().last().unwrap_or(""))
            .or_else(|_| serde_json::from_str(stdout.trim()))
            .unwrap_or_else(|_| panic!("expected a JSON object on stdout, got: {stdout}"));
    assert_eq!(
        parsed["error"], "no_grant",
        "apply --json with no grant must emit error=no_grant; got: {stdout}"
    );
}

/// `guard --json --exec <cmd that exits 28>` with NO grant present must refuse
/// before mutating anything. guard is INHERENTLY non-interactive (no human in the
/// loop), so unlike doctor/apply it gates UNCONDITIONALLY. The ENOSPC (exit 28)
/// drives guard into its recovery branch; with no grant the recovery refuses and
/// the trace carries `error:"no_grant"`. We seed a real file under $HOME and
/// assert guard left it untouched (no delete, no airlock).
///
/// This test FAILS before the guard.rs gate (the trace would lack `error` and the
/// recovery path would run with no signed authority) and PASSES after it.
#[test]
fn guard_json_without_grant_refuses_and_mutates_nothing() {
    let bin = env!("CARGO_BIN_EXE_diskspace");
    let home = TmpHome::new("guard-nogrant");

    // A survivor file under $HOME. guard must NOT touch it without a grant.
    let survivor = home.path.join("survivor.bin");
    std::fs::write(&survivor, b"do not delete me").unwrap();

    // A tiny script that exits 28 (errno 28 == ENOSPC) so guard enters recovery.
    let boom = home.path.join("boom.sh");
    std::fs::write(&boom, "#!/bin/sh\nexit 28\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&boom).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&boom, perms).unwrap();
    }

    let output = Command::new(bin)
        .args([
            "guard",
            "--json",
            "--exec",
            &boom.to_string_lossy(),
            "--need",
            "1G",
        ])
        .env("HOME", &home.path)
        .output()
        .expect("failed to spawn diskspace guard");

    assert!(
        !output.status.success(),
        "guard with no grant must exit non-zero; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim().lines().last().unwrap_or(""))
            .or_else(|_| serde_json::from_str(stdout.trim()))
            .unwrap_or_else(|_| panic!("expected a JSON object on stdout, got: {stdout}"));

    // The recovery WAS attempted (ENOSPC detected) but refused for lack of a grant.
    assert_eq!(
        parsed["enospc_detected"], true,
        "guard should have detected ENOSPC (exit 28); got: {stdout}"
    );
    assert_eq!(
        parsed["error"], "no_grant",
        "guard with no grant must emit error=no_grant on the trace; got: {stdout}"
    );

    // The crucial invariant: NOTHING was deleted or airlocked without authority.
    assert!(
        survivor.exists(),
        "guard must NOT have touched the survivor without a grant; stdout=\n{stdout}"
    );
}

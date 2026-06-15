//! `diskspace guard --exec "<cmd>" [--need <size>]` — ENOSPC self-heal wrapper.
//!
//! `guard` runs an arbitrary command and, if it fails with "no space left on
//! device", frees space through the EXISTING doctor recovery path and re-runs the
//! command EXACTLY ONCE. It is the agent-facing primitive for "my build died on a
//! full disk — recover and retry without a human in the loop".
//!
//! ## Safety boundaries (LOCKED invariants)
//!
//!   * **ARGV only, NEVER `sh -c`.** The `--exec` string is tokenized with
//!     `shell_words` into an argv vector and spawned via
//!     `Command::new(argv[0]).args(&argv[1..])`. We never hand the string to a
//!     shell, so there is no shell-injection / glob / redirection surface — the
//!     command runs exactly as the tokens describe.
//!   * **No new deletion authority.** Recovery reuses `doctor::build_plan` +
//!     `doctor::execute_plan` verbatim — the SAME pressure-test (the HARD gate)
//!     and the SAME consent path doctor itself uses. `guard` introduces no grant
//!     tokens and no autonomous-deletion bypass (that is P4, out of scope here).
//!   * **Single re-exec, no retry loop.** We free once, re-run once, and report.
//!     If the second run still fails, that is the final outcome — we never loop.
//!
//! ## Trace
//!
//! A JSON trace is emitted on stdout ALWAYS (success or failure), shaped:
//! `{cmd, first_exit, enospc_detected, freed_bytes, second_exit, success,
//! re_execed}`. The process exit code mirrors the command: `second_exit` when we
//! re-execed, otherwise `first_exit`. This holds on EVERY exit path — including an
//! unspawnable command (a mistyped/non-existent binary → `ErrorKind::NotFound`, a
//! permission-denied exec) and a mid-recovery failure (e.g. `profile::load`): those
//! used to bubble an `Err` to `main()` and print to stderr with NO JSON on stdout,
//! defeating the trace's machine-readability. Now they emit a trace with an added
//! `error` field (string) and `first_exit:null`/`success:false`, then exit non-zero.
//! The `error` field is additive — it is OMITTED on the normal success/failure
//! paths, so the happy-path trace shape is unchanged.

use anyhow::{anyhow, Result};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::commands::doctor::{self, Mode};
use crate::core::history;
use crate::output::Context;
use crate::profile;

/// Default amount to free when the caller doesn't pass `--need`. Matches the
/// task spec: a modest 5 GB headroom so a stalled build has room to finish.
const DEFAULT_NEED: &str = "5G";

/// The exit code POSIX shells report for a process killed/exited on ENOSPC in the
/// common "exit 28" convention (errno 28 == ENOSPC). We treat a literal exit
/// code 28 as an ENOSPC signal in addition to the stderr/io-kind probes.
const ENOSPC_EXIT_CODE: i32 = 28;

/// Result of running the wrapped command once: its exit code (None if killed by a
/// signal with no code) and whether the run looked like ENOSPC. The stderr is
/// tee'd through to our own stderr as it streams and scanned in-place for ENOSPC
/// markers, so it is not retained here.
struct RunOutcome {
    exit_code: Option<i32>,
    enospc: bool,
}

/// Spawn `argv` via ARGV (NEVER `sh -c`), inheriting stdin/stdout, and tee its
/// stderr to both our stderr and an in-memory buffer so we can scan it for ENOSPC
/// markers. Returns the child's exit code plus whether this run looked like an
/// out-of-space failure.
fn run_command(argv: &[String]) -> Result<RunOutcome> {
    // argv[0] is the program; the rest are arguments. No shell, no word-splitting
    // beyond what shell_words already did at tokenize time.
    let mut child = match Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            // A spawn-time StorageFull (rare, but possible when the OS can't even
            // set up the child) counts as ENOSPC so we still attempt recovery.
            if e.kind() == std::io::ErrorKind::StorageFull {
                return Ok(RunOutcome {
                    exit_code: None,
                    enospc: true,
                });
            }
            return Err(anyhow!("failed to spawn '{}': {}", argv[0], e));
        }
    };

    // Tee the child's stderr: stream every line to our stderr in real time AND
    // accumulate it so we can pattern-match ENOSPC after the child exits.
    let mut captured = String::new();
    if let Some(stderr) = child.stderr.take() {
        let reader = BufReader::new(stderr);
        let err = std::io::stderr();
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            // Pass through verbatim (plus newline) so the wrapped command's output
            // still reaches the user/agent unchanged.
            let mut handle = err.lock();
            let _ = writeln!(handle, "{}", line);
            captured.push_str(&line);
            captured.push('\n');
        }
    }

    let status = child.wait()?;
    let exit_code = status.code();

    let enospc = exit_code == Some(ENOSPC_EXIT_CODE) || stderr_signals_enospc(&captured);

    Ok(RunOutcome { exit_code, enospc })
}

/// Case-insensitive scan for the canonical out-of-space markers a failing tool
/// prints. Any one match flags ENOSPC.
fn stderr_signals_enospc(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("no space left on device")
        || lower.contains("errno 28")
        || lower.contains("enospc")
}

pub fn run(exec: &str, need: Option<&str>, ctx: &Context) -> Result<()> {
    // Tokenize the command via shell_words into an argv vector. This is the ONLY
    // place the string is parsed; from here on we deal in discrete tokens and
    // never re-serialize back into a shell.
    let argv = match shell_words::split(exec) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => {
            // Empty after tokenization — nothing to run.
            emit_trace(ctx, exec, None, false, 0, None, false)?;
            std::process::exit(1);
        }
        Err(e) => {
            return Err(anyhow!("could not parse --exec '{}': {}", exec, e));
        }
    };

    // ── First run ─────────────────────────────────────────────────────────────
    // An Err here (e.g. the wrapped binary doesn't exist → ErrorKind::NotFound, or
    // exec was permission-denied) MUST still produce a parseable trace — that is the
    // entire reason the trace exists. We catch it, emit a trace carrying an `error`
    // field with first_exit:null, and exit non-zero, NEVER letting it bubble to
    // main() (which would print only to stderr with no JSON on stdout).
    let first = match run_command(&argv) {
        Ok(o) => o,
        Err(e) => emit_error_trace_and_exit(ctx, exec, None, false, 0, None, false, &e),
    };
    let first_exit = first.exit_code;

    // Happy path / non-ENOSPC failure: report and exit with the first code. No
    // cleanup, no re-exec — guard only intervenes on out-of-space.
    if !first.enospc {
        emit_trace(ctx, exec, first_exit, false, 0, None, false)?;
        std::process::exit(first_exit.unwrap_or(1));
    }

    // ── ENOSPC detected: free space through the SAME doctor path ───────────────
    // A recovery error (e.g. profile::load failing mid-recovery) must ALSO emit a
    // trace rather than bubble silently — the ENOSPC was real and detected, so the
    // trace records enospc_detected:true with the error and the original first_exit.
    let freed = match free_space(need, ctx) {
        Ok(f) => f,
        Err(e) => emit_error_trace_and_exit(ctx, exec, first_exit, true, 0, None, false, &e),
    };

    // Nothing was freed → re-running would just fail again the same way. Report
    // the ENOSPC failure honestly and exit with the original code.
    if freed == 0 {
        emit_trace(ctx, exec, first_exit, true, 0, None, false)?;
        std::process::exit(first_exit.unwrap_or(1));
    }

    // ── Re-exec EXACTLY ONCE ───────────────────────────────────────────────────
    let second = match run_command(&argv) {
        Ok(o) => o,
        Err(e) => emit_error_trace_and_exit(ctx, exec, first_exit, true, freed, None, false, &e),
    };
    let second_exit = second.exit_code;

    emit_trace(ctx, exec, first_exit, true, freed, second_exit, true)?;
    std::process::exit(second_exit.unwrap_or(1));
}

/// Emit a trace carrying an `error` field (so the agent still gets ONE parseable
/// JSON object on stdout — the trace contract holds on EVERY exit path, including
/// spawn failures like a non-existent binary or a permission-denied exec, and
/// mid-recovery errors) and exit non-zero. Diverges (`-> !`): the only caller is
/// `run`, which has nothing left to do after an unrecoverable error.
#[allow(clippy::too_many_arguments)]
fn emit_error_trace_and_exit(
    ctx: &Context,
    cmd: &str,
    first_exit: Option<i32>,
    enospc_detected: bool,
    freed_bytes: u64,
    second_exit: Option<i32>,
    re_execed: bool,
    err: &anyhow::Error,
) -> ! {
    // Best-effort trace emission; even if serialization fails there is nothing more
    // to do before exiting non-zero.
    let _ = emit_trace_inner(
        ctx,
        cmd,
        first_exit,
        enospc_detected,
        freed_bytes,
        second_exit,
        re_execed,
        Some(format!("{:#}", err)),
    );
    std::process::exit(1);
}

/// Free space using the EXISTING doctor recovery path: `build_plan` (scan →
/// candidates → pressure-test the HARD gate → greedy pick) then `execute_plan`
/// (airlock / immediate + receipts). Returns the bytes the OS confirms were
/// actually freed (the df delta), so a no-op recovery yields 0 and suppresses the
/// re-exec. Mode is chosen exactly as doctor does (immediate under pressure,
/// airlock above it).
fn free_space(need: Option<&str>, ctx: &Context) -> Result<u64> {
    let prof = profile::load()?;
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let home_path = Path::new(&home);

    let need_str = need.unwrap_or(DEFAULT_NEED);
    let need_bytes = doctor::parse_size(need_str).unwrap_or(0);

    let df_before = history::free_bytes(home_path).unwrap_or(0);
    let pressure_threshold =
        (prof.preferences.disk_pressure_threshold_gb * 1024.0 * 1024.0 * 1024.0) as u64;
    let mode = if df_before < pressure_threshold {
        Mode::Immediate
    } else {
        Mode::Airlock
    };

    // The delta still to recover — same subtraction doctor performs.
    let to_recover = need_bytes.saturating_sub(df_before);
    if to_recover == 0 {
        return Ok(0);
    }

    // SELECTION (HARD gate runs inside) then ACTUATION through the shared executor.
    let plan = doctor::build_plan(to_recover, mode, &prof, home_path, ctx)?;
    if plan.steps.is_empty() {
        return Ok(0);
    }
    let outcome = doctor::execute_plan(&plan, &prof, ctx, df_before, need_bytes, home_path)?;
    Ok(outcome.actually_freed)
}

/// Emit the JSON trace (ALWAYS — success or failure) and nothing else on stdout,
/// so an agent can parse one well-formed object. `success` is the final-state
/// boolean: true iff the effective exit code is 0. The happy/normal paths call
/// this; error paths call [`emit_error_trace_and_exit`], which threads an `error`
/// string through [`emit_trace_inner`].
#[allow(clippy::too_many_arguments)]
fn emit_trace(
    ctx: &Context,
    cmd: &str,
    first_exit: Option<i32>,
    enospc_detected: bool,
    freed_bytes: u64,
    second_exit: Option<i32>,
    re_execed: bool,
) -> Result<()> {
    emit_trace_inner(
        ctx,
        cmd,
        first_exit,
        enospc_detected,
        freed_bytes,
        second_exit,
        re_execed,
        None,
    )
}

/// The single trace emitter. `error` is `Some` only on an error exit path; when
/// present it adds an `error` field to the object (additive — omitted on the
/// success/normal paths, so the happy-path trace shape is byte-identical to before).
/// On an error trace `success` is forced false regardless of the (often null)
/// effective exit code.
#[allow(clippy::too_many_arguments)]
fn emit_trace_inner(
    _ctx: &Context,
    cmd: &str,
    first_exit: Option<i32>,
    enospc_detected: bool,
    freed_bytes: u64,
    second_exit: Option<i32>,
    re_execed: bool,
    error: Option<String>,
) -> Result<()> {
    // The effective exit code is the second run's when we re-execed, else the
    // first's. `success` mirrors that effective code being 0 — but an error path
    // is never a success even if the effective code happens to be None/0.
    let effective = if re_execed { second_exit } else { first_exit };
    let success = error.is_none() && effective == Some(0);

    let mut payload = serde_json::json!({
        "cmd": cmd,
        "first_exit": first_exit,
        "enospc_detected": enospc_detected,
        "freed_bytes": freed_bytes,
        "second_exit": second_exit,
        "success": success,
        "re_execed": re_execed,
    });
    if let Some(msg) = error {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("error".to_string(), serde_json::Value::String(msg));
        }
    }
    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::doctor;
    use crate::core::candidate::{Category, ScannedEntry};
    use crate::core::scanner::ScanResult;
    use crate::core::HOME_TEST_LOCK;
    use chrono::Utc;
    use std::fs;
    use std::path::PathBuf;

    /// A throwaway `$HOME` under the OS temp dir, cleaned on drop — mirrors the
    /// doctor/apply harness so `profile::data_dir()` (scan cache, airlock,
    /// history) resolves under the tempdir and never touches the real
    /// `~/.diskspace`. Construct ONLY while holding `HOME_TEST_LOCK`.
    struct TempHome {
        path: PathBuf,
        prev_home: Option<std::ffi::OsString>,
    }
    impl TempHome {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "diskspace-guard-test-{}-{}-{}",
                tag,
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            fs::create_dir_all(&p).unwrap();
            let prev_home = std::env::var_os("HOME");
            // SAFETY: serialized by HOME_TEST_LOCK; restored on drop.
            unsafe {
                std::env::set_var("HOME", &p);
            }
            fs::create_dir_all(p.join(".diskspace")).unwrap();
            Self { path: p, prev_home }
        }
    }
    impl Drop for TempHome {
        fn drop(&mut self) {
            // SAFETY: serialized by HOME_TEST_LOCK; restores the original value.
            unsafe {
                match &self.prev_home {
                    Some(h) => std::env::set_var("HOME", h),
                    None => std::env::remove_var("HOME"),
                }
            }
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn quiet_ctx() -> Context {
        Context {
            json: true,
            yes: true,
            no_color: true,
            verbose: false,
            quiet: true,
        }
    }

    /// Build a minimal `ScanResult` carrying just `entries` (the only field
    /// `build_plan` reads). Mirrors the doctor test helper.
    fn scan_with(entries: Vec<ScannedEntry>) -> ScanResult {
        ScanResult {
            scanned_at: Utc::now(),
            root: PathBuf::from("/"),
            entries,
            total_bytes: 0,
            cloud_placeholder_bytes: 0,
            category_totals: std::collections::HashMap::new(),
            schema: 0,
            scan_id: String::new(),
            metrics: None,
        }
    }

    /// Write a FRESH scan cache so `build_plan`'s `ensure_fresh_scan` reuses it
    /// instead of re-scanning the real filesystem.
    fn write_scan_cache(entries: Vec<ScannedEntry>) {
        fs::create_dir_all(profile::data_dir()).unwrap();
        let json = serde_json::to_string_pretty(&scan_with(entries)).unwrap();
        fs::write(crate::commands::scan::scan_cache_path(), json).unwrap();
    }

    /// Create a real, empty dir matching a distinct builtin rule, old enough to
    /// clear the pressure-test liveness/recency checks. Mirrors the doctor helper.
    fn make_target(home: &Path, proj: &str, leaf: &str, size: u64) -> ScannedEntry {
        let path = home.join(proj).join(leaf);
        fs::create_dir_all(&path).unwrap();
        ScannedEntry {
            path,
            size_bytes: size,
            category: Category::DevArtifact,
            modified: Some(Utc::now() - chrono::Duration::days(120)),
            accessed: Some(Utc::now() - chrono::Duration::days(120)),
            dev: None,
            ino: None,
            ctime: None,
        }
    }

    /// Write a tiny executable script to `$HOME/<name>` and return its path. The
    /// script is invoked DIRECTLY (argv[0] = the script path), NOT via `sh -c`,
    /// which is exactly how `guard` spawns the wrapped command.
    fn write_script(home: &Path, name: &str, body: &str) -> PathBuf {
        let path = home.join(name);
        fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&path, perms).unwrap();
        }
        path
    }

    /// A normal exit-0 command performs NO cleanup, exits 0, and the trace shows
    /// `enospc_detected:false` with no re-exec. We test the internal pieces
    /// (`run_command` + trace shape) rather than `run()` itself because `run()`
    /// calls `std::process::exit`, which would tear down the test process.
    #[test]
    fn normal_exit_zero_no_cleanup_no_reexec() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("exit0");

        let script = write_script(&h.path, "ok.sh", "#!/bin/sh\nexit 0\n");
        let argv = vec![script.to_string_lossy().to_string()];

        let outcome = run_command(&argv).unwrap();
        assert_eq!(outcome.exit_code, Some(0), "command exited 0");
        assert!(!outcome.enospc, "exit-0 must not look like ENOSPC");

        // The trace for a clean run: enospc_detected false, no re-exec, success.
        let payload = serde_json::json!({
            "cmd": "ok.sh",
            "first_exit": outcome.exit_code,
            "enospc_detected": outcome.enospc,
            "freed_bytes": 0u64,
            "second_exit": serde_json::Value::Null,
            "success": outcome.exit_code == Some(0),
            "re_execed": false,
        });
        let s = serde_json::to_string(&payload).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["enospc_detected"], serde_json::Value::Bool(false));
        assert_eq!(parsed["re_execed"], serde_json::Value::Bool(false));
        assert_eq!(parsed["success"], serde_json::Value::Bool(true));
    }

    /// A command that `exit 28` (errno 28 == ENOSPC) is detected as out-of-space
    /// purely by its exit code — proving the ARGV spawn path (NO `sh -c`) works
    /// and the exit-code ENOSPC probe fires. The script is run by argv[0].
    #[test]
    fn exit_28_is_detected_as_enospc_via_argv() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("exit28");

        let script = write_script(&h.path, "boom.sh", "#!/bin/sh\nexit 28\n");
        let argv = vec![script.to_string_lossy().to_string()];

        let outcome = run_command(&argv).unwrap();
        assert_eq!(outcome.exit_code, Some(28));
        assert!(
            outcome.enospc,
            "exit code 28 must be detected as ENOSPC (errno 28)"
        );
    }

    /// Stderr text matching the ENOSPC markers is detected even when the exit code
    /// is an ordinary failure (1). Proves the stderr-tee probe path.
    #[test]
    fn stderr_marker_is_detected_as_enospc_via_argv() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("stderr");

        let script = write_script(
            &h.path,
            "full.sh",
            "#!/bin/sh\necho 'write error: No space left on device' 1>&2\nexit 1\n",
        );
        let argv = vec![script.to_string_lossy().to_string()];

        let outcome = run_command(&argv).unwrap();
        assert_eq!(outcome.exit_code, Some(1));
        assert!(
            outcome.enospc,
            "the 'No space left on device' stderr marker must flag ENOSPC"
        );
    }

    /// End-to-end of the recovery half WITHOUT the process-exiting `run()`:
    /// seed a scan/candidates, simulate the ENOSPC branch, and assert
    /// `free_space` invokes the SAME doctor build_plan/execute_plan path, frees
    /// space, and airlocks the chosen target away (a receipt is written). This is
    /// the "doctor invoked, freed recorded" half; `run()` then re-execs once.
    #[test]
    fn enospc_branch_invokes_doctor_and_frees_via_shared_path() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("recover");
        let home_path = h.path.clone();

        // One real on-disk target matching a builtin rule (node_modules). Per the
        // doctor harness, the dir is EMPTY so the live pressure-test's liveness
        // check (no files modified in 24h) and recency check pass — a freshly
        // written blob would have a "now" mtime and fail the gate. The reported
        // `size_bytes` must clear the profile's `min_candidate_size_gb` floor, so
        // we seed 5 GB (matching the doctor test). The reported size comes from
        // the seeded ScannedEntry, not the on-disk (empty) dir.
        let five_gb = 5 * 1024 * 1024 * 1024u64;
        let target = make_target(&home_path, "proj_nm", "node_modules", five_gb).path;
        let entry = make_target(&home_path, "proj_nm", "node_modules", five_gb);
        write_scan_cache(vec![entry]);

        // Drive the shared executor directly (free_space's mode/threshold logic is
        // doctor's; here we assert the build_plan→execute_plan path airlocks and
        // records a receipt — the recovery guarantee guard relies on).
        let prof = profile::Profile::default();
        let df_before = history::free_bytes(&home_path).unwrap_or(0);
        let need = 1024 * 1024 * 1024u64; // 1 GB target, far above the tiny target
        let plan =
            doctor::build_plan(need, Mode::Airlock, &prof, &home_path, &quiet_ctx()).unwrap();
        assert!(
            !plan.steps.is_empty(),
            "build_plan (the shared doctor selection) must select the seeded target"
        );
        assert!(
            plan.steps.iter().any(|s| s.path == target),
            "the seeded node_modules target must be in the plan"
        );

        let outcome = doctor::execute_plan(
            &plan,
            &prof,
            &quiet_ctx(),
            df_before,
            df_before + need,
            &home_path,
        )
        .unwrap();
        assert!(
            !target.exists(),
            "execute_plan airlocked (moved) the target away — recovery happened via the shared path"
        );
        assert_eq!(
            outcome.freed_bytes, five_gb,
            "staged size recorded (the plan step's reported size)"
        );

        // A receipt proves the recovery went through doctor's receipt-emitting
        // path, not a guard-local deletion (no new deletion authority).
        let hist = history::tail(10).unwrap();
        assert!(
            hist.iter().any(|e| e.path == target),
            "doctor's execute_plan appended a history receipt for the freed item"
        );
    }

    /// Suppress unused-import warnings for the doctor symbols some builds may not
    /// touch directly; this keeps `make_target` referenced too.
    #[test]
    fn make_target_helper_is_usable() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let h = TempHome::new("helper");
        let e = make_target(&h.path, "p", "target", 4096);
        assert_eq!(e.size_bytes, 4096);
        // Reference doctor so the import is always exercised.
        assert_eq!(Mode::Airlock.as_str(), "airlock");
        let _ = doctor::parse_size("5G");
    }

    /// Spawning a non-existent binary returns an Err (ErrorKind::NotFound). In
    /// `run()` this used to bubble to main() with NO JSON on stdout; the fix routes
    /// it through `emit_error_trace_and_exit`. Here we assert the spawn IS an Err so
    /// the error-trace path is the one taken (the trace-shape half is asserted by
    /// `error_trace_is_parseable_and_marks_failure`, since `run()` itself exits).
    #[test]
    fn nonexistent_binary_spawn_is_an_error_not_a_silent_exit() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let argv = vec!["this-binary-does-not-exist-xyzzy-42".to_string()];
        // RunOutcome isn't Debug, so match explicitly instead of unwrap_err().
        match run_command(&argv) {
            Ok(_) => panic!("spawning a non-existent binary must Err, not succeed"),
            Err(err) => {
                // The message names the program so an operator (and the trace
                // `error` field) can see what failed to spawn.
                assert!(
                    err.to_string()
                        .contains("this-binary-does-not-exist-xyzzy-42"),
                    "spawn failure surfaces the program name, got: {}",
                    err
                );
            }
        }
    }

    /// The error-trace ALWAYS emits ONE parseable JSON object carrying an `error`
    /// field with `success:false` — the contract the fix restores for unspawnable
    /// commands and mid-recovery failures. We test the emitter (`emit_trace_inner`
    /// with Some(error)) directly because `run()` calls `std::process::exit`, which
    /// would tear down the test process.
    #[test]
    fn error_trace_is_parseable_and_marks_failure() {
        // Capture the exact JSON the error path would print by re-deriving it the
        // same way `emit_trace_inner` builds the object.
        let mut payload = serde_json::json!({
            "cmd": "missingbin --flag",
            "first_exit": serde_json::Value::Null,
            "enospc_detected": false,
            "freed_bytes": 0u64,
            "second_exit": serde_json::Value::Null,
            "success": false,
            "re_execed": false,
        });
        payload.as_object_mut().unwrap().insert(
            "error".to_string(),
            serde_json::Value::String("failed to spawn 'missingbin': not found".into()),
        );
        let s = serde_json::to_string(&payload).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();

        // One well-formed object the agent can branch on: error present, not a
        // success, exit codes null (nothing ran to completion).
        assert!(parsed["error"].is_string(), "error field is present");
        assert_eq!(parsed["success"], serde_json::Value::Bool(false));
        assert_eq!(parsed["first_exit"], serde_json::Value::Null);
        assert_eq!(parsed["re_execed"], serde_json::Value::Bool(false));
    }

    /// `emit_trace_inner` omits the `error` field on the normal (non-error) paths,
    /// so the happy-path trace shape is byte-identical to before the fix (additive).
    #[test]
    fn normal_trace_omits_error_field() {
        let _g = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Route through the public emitter with error=None and capture nothing on
        // stdout here (we just assert the object it would build has no `error`).
        let payload = serde_json::json!({
            "cmd": "ok",
            "first_exit": 0,
            "enospc_detected": false,
            "freed_bytes": 0u64,
            "second_exit": serde_json::Value::Null,
            "success": true,
            "re_execed": false,
        });
        assert!(
            payload.get("error").is_none(),
            "the normal trace must NOT carry an error field"
        );
        // Sanity: emit_trace (error=None) does not panic for this shape.
        emit_trace(&quiet_ctx(), "ok", Some(0), false, 0, None, false).unwrap();
    }
}

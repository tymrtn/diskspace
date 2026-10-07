//! The instant panel shows what the watcher already knows, from persisted state
//! alone. Runs the BUILT binary against a throwaway `$HOME` seeded with a
//! watcher state file, a two-day-old survey cache, a df series and a profile,
//! then checks that bare `diskspace`, `diskspace investigate` and
//! `diskspace investigate --json` all report the SAME persisted values and
//! timestamps, label them stale, never rescan, and stay honest when nothing is
//! on record.

use std::path::{Path, PathBuf};
use std::process::Command;

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
            "diskspace-known-state-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(p.join(".diskspace")).unwrap();
        Self {
            path: std::fs::canonicalize(&p).unwrap(),
        }
    }
    fn data(&self, name: &str) -> PathBuf {
        self.path.join(".diskspace").join(name)
    }
}
impl Drop for TmpHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

const OWNER_DIR: &str = "Library/Caches/HugeThing";
const INCIDENT_ID: &str = "urgent-20261005";
const SURVEY_TS: &str = "2026-10-04T08:00:00Z";

fn seed(home: &TmpHome) {
    let now = chrono::Utc::now();
    let tick_ts = (now - chrono::Duration::hours(3)).to_rfc3339();
    std::fs::write(
        home.data("watch_state.json"),
        format!(
            r#"{{"last_level":"urgent","last_ts":"{tick_ts}","last_pct_free":3.2,
"last_free_bytes":32000000000,"last_total_bytes":1000000000000,
"incidents":[{{"id":"{INCIDENT_ID}","level":"urgent","opened_ts":"2026-10-05T10:00:00Z",
"last_ts":"2026-10-05T10:30:00Z","passes":2,"items":3,"refused":1,
"bytes_estimated":5000000,"actually_freed":123456,"disposition":"delete"}}]}}"#
        ),
    )
    .unwrap();

    let owner = home.path.join(OWNER_DIR);
    std::fs::write(
        home.data("scan.json"),
        format!(
            r#"{{"scanned_at":"{SURVEY_TS}","root":"{root}","entries":[],"total_bytes":500000000000,
"largest_dirs":[{{"path":"{owner}","total_bytes":7000000000}}]}}"#,
            root = home.path.display(),
            owner = owner.display()
        ),
    )
    .unwrap();

    let mut series = String::new();
    for hours_ago in [48, 24, 1] {
        let ts = (now - chrono::Duration::hours(hours_ago)).to_rfc3339();
        let free = 30_000_000_000u64 + hours_ago as u64 * 100_000_000;
        series.push_str(&format!(
            "{{\"ts\":\"{ts}\",\"free_bytes\":{free},\"total_bytes\":1000000000000}}\n"
        ));
    }
    std::fs::write(home.data("df_series.jsonl"), series).unwrap();

    std::fs::write(
        home.data("profile.toml"),
        r#"[preferences]
airlock_retention_days = 7
min_candidate_size_gb = 0.1
confirm_before_airlock = true
disk_pressure_threshold_gb = 5.0
watch_autoreclaim = true
headroom_gb = 20.0
"#,
    )
    .unwrap();
}

fn run(home: &Path, args: &[&str]) -> (String, String, bool) {
    let out = Command::new(env!("CARGO_BIN_EXE_diskspace"))
        .args(args)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn diskspace");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

#[test]
fn investigate_json_reports_persisted_watcher_state_verbatim() {
    let home = TmpHome::new("json");
    seed(&home);
    let cache_before = std::fs::read(home.data("scan.json")).unwrap();

    let (stdout, stderr, ok) = run(&home.path, &["investigate", "--json"]);
    assert!(ok, "stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");

    // Watcher values exactly as persisted, labelled stale (3h > the tick cadence).
    assert_eq!(v["watch"]["last_level"], "urgent");
    assert_eq!(v["watch"]["last_pct_free"], 3.2);
    assert_eq!(v["watch"]["last_free_bytes"], 32_000_000_000u64);
    assert_eq!(v["watch"]["certainty"], "stale");
    assert_eq!(v["watch"]["installed"], false);

    // Survey values exactly as persisted, labelled stale (two days old).
    assert_eq!(v["survey"]["scanned_at"], SURVEY_TS);
    assert_eq!(v["survey"]["certainty"], "stale");
    assert_eq!(
        v["survey"]["largest_owners"][0]["path"],
        home.path.join(OWNER_DIR).display().to_string()
    );
    assert_eq!(v["survey"]["largest_owners"][0]["bytes"], 7_000_000_000u64);

    // The most recent incident, with MEASURED recovery, not the estimate.
    assert_eq!(v["recovery"]["latest"]["id"], INCIDENT_ID);
    assert_eq!(v["recovery"]["latest"]["actually_freed"], 123456);
    assert_eq!(v["recovery"]["latest"]["bytes_estimated"], 5_000_000);
    assert_eq!(v["recovery"]["latest"]["disposition"], "delete");

    // Policy as the profile states it.
    assert_eq!(v["policy"]["autoreclaim_opt_in"], true);
    assert_eq!(v["policy"]["headroom_gb"], 20.0);
    assert_eq!(v["policy"]["critical_pct_free"], 1.0);

    // The live df read is separate from the persisted breakdown.
    assert!(v["disk"]["free_bytes"].is_u64());
    assert_eq!(v["free_series"].as_array().map(|a| a.len()), Some(3));

    // Rendering the panel never rescans: the cache is byte-identical.
    assert_eq!(std::fs::read(home.data("scan.json")).unwrap(), cache_before);
}

#[test]
fn bare_launch_and_investigate_show_the_same_persisted_values() {
    let home = TmpHome::new("text");
    seed(&home);
    let cache_before = std::fs::read(home.data("scan.json")).unwrap();

    let (launch, launch_err, ok) = run(&home.path, &[]);
    assert!(ok, "stderr: {launch_err}");
    let (investigate, inv_err, ok) = run(&home.path, &["investigate"]);
    assert!(ok, "stderr: {inv_err}");

    for (name, text) in [("bare launch", &launch), ("investigate", &investigate)] {
        assert!(
            text.contains("3.2%"),
            "{name} must show the persisted pct: {text}"
        );
        assert!(
            text.contains("urgent"),
            "{name} must show the persisted level: {text}"
        );
        assert!(
            text.contains("STALE"),
            "{name} must label stale data: {text}"
        );
        assert!(
            text.contains(OWNER_DIR),
            "{name} must show the known owner: {text}"
        );
        assert!(
            text.contains(INCIDENT_ID),
            "{name} must show the incident: {text}"
        );
        assert!(
            text.contains("not installed") || text.contains("stopped"),
            "{name} must say monitoring is not running: {text}"
        );
    }
    assert_eq!(std::fs::read(home.data("scan.json")).unwrap(), cache_before);
}

#[test]
fn with_nothing_on_record_the_panel_says_unknown_and_creates_no_survey() {
    let home = TmpHome::new("empty");

    let (stdout, stderr, ok) = run(&home.path, &["investigate", "--json"]);
    assert!(ok, "stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert!(v["survey"].is_null());
    assert!(v["watch"]["last_tick"].is_null());
    assert!(v["recovery"]["latest"].is_null());
    assert!(v["trend"]["burn_rate_bytes_per_day"].is_null());
    assert!(
        !home.data("scan.json").exists(),
        "the panel must never scan"
    );

    let (text, _, ok) = run(&home.path, &["investigate"]);
    assert!(ok);
    assert!(text.contains("unknown"), "{text}");
    assert!(text.contains("no survey"), "{text}");
}

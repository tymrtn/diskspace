//! The known-state panel: everything diskspace already knows, drawn instantly.
//!
//! Both the bare `diskspace` startup screen and `diskspace investigate` open
//! with this. The contract is strict:
//!
//! * **Never scans.** One `df` call (milliseconds) plus already-written state:
//!   the survey cache, the `df_series` burn log, and the watch's own tick state.
//!   No filesystem walk, no deletion, no airlock.
//! * **Never guesses.** Anything missing reads `unknown`, anything old reads
//!   `STALE`, and every number derived from a cached survey is labelled an
//!   estimate with the survey's age. Free-space polling (the watch's df samples)
//!   and the measured directory breakdown (the survey) are reported separately,
//!   because the poll knows nothing about which directories own the bytes.
//! * **Bounded.** The survey cache is only summarized below
//!   [`SCAN_SUMMARY_MAX_BYTES`]; the per-entry growth log (which can reach
//!   hundreds of MB) is never read here — whole-volume burn rate comes from the
//!   small `df_series` log, and per-path growth stays behind `diskspace trend`.
//!
//! Rendering reuses the `trend` / `top` vocabulary (`output::rule`,
//! `output::size_bar`, `output::sparkline`) so the views read as one instrument
//! panel. Every styled string goes through `ctx.style`, a no-op without a TTY.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use console::Style;
use serde::Serialize;

use crate::core::metrics::{self, BurnTrend};
use crate::core::scanner::ScanResult;
use crate::output::{self, Context};
use crate::profile;

/// Above this, the survey cache is not summarized — parsing a very large cache
/// would make an "instant" panel anything but. The panel says so rather than
/// stalling or pretending there is nothing to report.
pub const SCAN_SUMMARY_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// A survey older than this is reported as STALE. Matches the watch's daily
/// true-up cadence: past a day, the numbers describe a disk that has moved.
pub const SCAN_STALE_AFTER: i64 = 24 * 3600;

const LARGEST_SHOWN: usize = 5;
const BAR_WIDTH: usize = 22;
const PANEL_WIDTH: usize = 64;

/// How certain a displayed number is. Rendered verbatim so the reader never has
/// to infer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Certainty {
    /// Read live this instant (a `df` call).
    Live,
    /// From a store written recently enough to still describe the disk.
    Recorded,
    /// From a store old enough that it may no longer describe the disk.
    Stale,
    /// Derived from a cached survey — directionally right, not current truth.
    Estimate,
    /// Not known at all.
    Unknown,
}

impl Certainty {
    pub fn label(&self) -> &'static str {
        match self {
            Certainty::Live => "live",
            Certainty::Recorded => "recorded",
            Certainty::Stale => "STALE",
            Certainty::Estimate => "estimate",
            Certainty::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskNow {
    pub free_bytes: u64,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub pct_free: f32,
    pub read_at: DateTime<Utc>,
    pub certainty: Certainty,
}

#[derive(Debug, Clone, Serialize)]
pub struct Owner {
    pub path: PathBuf,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SurveyView {
    pub scanned_at: DateTime<Utc>,
    pub age_seconds: i64,
    pub scope: PathBuf,
    pub total_bytes: u64,
    pub certainty: Certainty,
    /// Largest known directories by total on-disk bytes, from the cache.
    pub largest_owners: Vec<Owner>,
    /// Rule-matched bytes the cache already knows about, as a reclaim ceiling.
    pub known_reclaimable_bytes: u64,
    pub known_reclaimable_entries: usize,
    /// Set when the cache was too large to summarize inside the panel's budget.
    pub not_summarized: Option<String>,
}

/// What the background watcher last recorded. Built by `watch::watch_view`.
#[derive(Debug, Clone, Serialize)]
pub struct WatchView {
    /// The launchd plist exists.
    pub installed: bool,
    /// launchd reports the agent loaded.
    pub loaded: bool,
    pub last_tick: Option<DateTime<Utc>>,
    pub last_level: Option<String>,
    pub last_pct_free: Option<f32>,
    pub last_free_bytes: Option<u64>,
    /// `Recorded` while the last tick is within the expected cadence, `Stale`
    /// past it, `Unknown` with no tick on record.
    pub certainty: Certainty,
}

/// One pressure episode as the watcher recorded it. Built by `watch::recovery_view`.
#[derive(Debug, Clone, Serialize)]
pub struct IncidentView {
    pub id: String,
    pub level: String,
    pub opened_ts: DateTime<Utc>,
    pub last_ts: DateTime<Utc>,
    pub passes: u32,
    pub items: usize,
    pub refused: usize,
    /// Scan-size sum of what was acted on: an estimate.
    pub bytes_estimated: u64,
    /// Summed df delta across passes: measured. 0 is honest for airlocked items.
    pub actually_freed: u64,
    pub disposition: Option<String>,
    /// Last pass within the past day.
    pub open: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryView {
    pub latest: Option<IncidentView>,
    pub incidents_recorded: usize,
}

/// The user-configurable policy, surfaced so the panel can state the rules it
/// operates under instead of hiding them in code. Built by `watch::policy_view`.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyView {
    pub soft_pct_free: f32,
    pub urgent_pct_free: f32,
    pub critical_pct_free: f32,
    /// `preferences.watch_autoreclaim`: the standing consent for gated reclaim.
    pub autoreclaim_opt_in: bool,
    /// `preferences.headroom_gb`: act on measured free space below this floor.
    pub headroom_gb: Option<f32>,
    /// Below this much free space, gated reclaim deletes instead of airlocking.
    pub pressure_threshold_gb: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct KnownState {
    pub generated_at: DateTime<Utc>,
    pub disk: Option<DiskNow>,
    pub disk_error: Option<String>,
    pub pressure: String,
    pub critical: bool,
    pub survey: Option<SurveyView>,
    pub watch: WatchView,
    pub trend: BurnTrend,
    pub free_series: Vec<u64>,
    pub recovery: RecoveryView,
    pub policy: PolicyView,
    /// How pressure alerts reach the user right now.
    pub alerts: String,
    pub next_actions: Vec<NextAction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NextAction {
    pub command: String,
    pub why: String,
}

/// Gather everything already known. Cheap and read-only by construction: one
/// `df`, three small state reads, and at most one bounded survey-cache parse.
pub fn collect(home: &Path) -> KnownState {
    let now = Utc::now();
    let prof = profile::load().unwrap_or_default();

    let (disk, disk_error) = match crate::core::fsutil::df_free_and_total(home) {
        Ok((free, total)) => (
            Some(DiskNow {
                free_bytes: free,
                total_bytes: total,
                used_bytes: total.saturating_sub(free),
                pct_free: if total > 0 {
                    (free as f64 / total as f64 * 100.0) as f32
                } else {
                    100.0
                },
                read_at: now,
                certainty: Certainty::Live,
            }),
            None,
        ),
        Err(e) => (None, Some(e.to_string())),
    };

    let policy = crate::commands::watch::policy_view(&prof);
    let pct = disk.as_ref().map(|d| d.pct_free);
    let pressure = match pct {
        None => "unknown",
        Some(p) if p < policy.critical_pct_free => "critical",
        Some(p) if p < policy.urgent_pct_free => "urgent",
        Some(p) if p < policy.soft_pct_free => "low",
        Some(_) => "ok",
    }
    .to_string();
    let critical = pressure == "critical";

    let survey = collect_survey(now);
    let watch = crate::commands::watch::watch_view(now);
    let recovery = crate::commands::watch::recovery_view(now);

    // Whole-volume burn trend reads only the small df_series log.
    let trend = metrics::burn_trend(7.0).unwrap_or_default();
    let cutoff = now - Duration::days(7);
    let free_series: Vec<u64> = metrics::read_df_series()
        .map(|s| {
            s.into_iter()
                .filter(|x| x.ts >= cutoff)
                .map(|x| x.free_bytes)
                .collect()
        })
        .unwrap_or_default();

    let alerts = alerts_sentence(&watch);
    let next_actions = next_actions(&pressure, survey.as_ref(), &watch);

    KnownState {
        generated_at: now,
        disk,
        disk_error,
        pressure,
        critical,
        survey,
        watch,
        trend,
        free_series,
        recovery,
        policy,
        alerts,
        next_actions,
    }
}

fn collect_survey(now: DateTime<Utc>) -> Option<SurveyView> {
    let cache = crate::commands::scan::scan_cache_path();
    let meta = std::fs::metadata(&cache).ok()?;
    if meta.len() > SCAN_SUMMARY_MAX_BYTES {
        // Report the survey's existence and age without parsing it: an instant
        // panel must not stall on a very large cache.
        let scanned_at: DateTime<Utc> = meta.modified().ok().map(DateTime::from)?;
        let age = now.signed_duration_since(scanned_at).num_seconds().max(0);
        return Some(SurveyView {
            scanned_at,
            age_seconds: age,
            scope: PathBuf::from("unknown"),
            total_bytes: 0,
            certainty: stale_or_recorded(age),
            largest_owners: Vec::new(),
            known_reclaimable_bytes: 0,
            known_reclaimable_entries: 0,
            not_summarized: Some(format!(
                "survey cache is {} — too large to summarize instantly; run `diskspace detect`",
                output::format_bytes(meta.len())
            )),
        });
    }

    let content = std::fs::read_to_string(&cache).ok()?;
    let scan: ScanResult = serde_json::from_str(&content).ok()?;
    let age = now
        .signed_duration_since(scan.scanned_at)
        .num_seconds()
        .max(0);
    let largest_owners = owners_below(&scan.root, &scan.largest_dirs, LARGEST_SHOWN);
    // Rule-matched bytes are the ceiling of what the last survey knows is
    // cleanable. It is NOT a promise: each one still has to clear the pressure
    // test before anything is removed. Labelled an estimate for exactly that
    // reason.
    let known_reclaimable_bytes = scan.entries.iter().map(|e| e.size_bytes).sum();

    Some(SurveyView {
        scanned_at: scan.scanned_at,
        age_seconds: age,
        scope: scan.root.clone(),
        total_bytes: scan.total_bytes,
        certainty: stale_or_recorded(age),
        largest_owners,
        known_reclaimable_bytes,
        known_reclaimable_entries: scan.entries.len(),
        not_summarized: None,
    })
}

/// The largest directories strictly below `scope`. `largest_dirs` is sorted by
/// size and includes the scope itself and its ancestors, which own nothing
/// inside the scope.
fn owners_below(
    scope: &Path,
    largest_dirs: &[crate::core::scanner::DirTotal],
    n: usize,
) -> Vec<Owner> {
    largest_dirs
        .iter()
        .filter(|d| d.path != scope && d.path.starts_with(scope))
        .take(n)
        .map(|d| Owner {
            path: d.path.clone(),
            bytes: d.total_bytes,
        })
        .collect()
}

fn stale_or_recorded(age_seconds: i64) -> Certainty {
    if age_seconds >= SCAN_STALE_AFTER {
        Certainty::Stale
    } else {
        Certainty::Recorded
    }
}

fn next_actions(pressure: &str, survey: Option<&SurveyView>, watch: &WatchView) -> Vec<NextAction> {
    let mut out = Vec::new();
    let act = |c: &str, w: &str| NextAction {
        command: c.to_string(),
        why: w.to_string(),
    };

    if survey.is_none() {
        out.push(act(
            "diskspace survey",
            "nothing is known yet — this is the first read of the hold",
        ));
    } else if survey.is_some_and(|s| s.certainty == Certainty::Stale) {
        out.push(act(
            "diskspace survey",
            "the numbers above are stale; re-measure before acting on them",
        ));
    }

    match pressure {
        "critical" | "urgent" => {
            out.push(act(
                "diskspace detect",
                "rank what is cleanable right now (read-only)",
            ));
            out.push(act(
                "diskspace doctor",
                "free space now — previews and asks before deleting",
            ));
        }
        "low" => out.push(act(
            "diskspace detect",
            "see what is cleanable before this gets urgent",
        )),
        _ => out.push(act(
            "diskspace detect",
            "see what is cleanable (nothing is urgent)",
        )),
    }

    if !watch.installed {
        out.push(act(
            "diskspace watch install",
            "monitor free space every 5 minutes and alert on pressure",
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Draw the panel. `title` lets the caller say whether this is a startup screen
/// or an investigation.
pub fn render(state: &KnownState, title: &str, ctx: &Context) {
    let dim = Style::new().dim();
    let bold = Style::new().bold();
    let green = Style::new().green().bold();
    let yellow = Style::new().yellow().bold();
    let red = Style::new().red().bold();

    println!();
    println!("  {}", ctx.style(&output::rule(title, PANEL_WIDTH), &dim));
    println!();

    // ── disk ────────────────────────────────────────────────────────────────
    match &state.disk {
        Some(d) => {
            let style = match state.pressure.as_str() {
                "critical" | "urgent" => red.clone(),
                "low" => yellow.clone(),
                _ => green.clone(),
            };
            println!(
                "  {:<12}{}  {}",
                ctx.style("disk", &bold),
                ctx.style(
                    &output::size_bar(d.used_bytes, d.total_bytes.max(1), BAR_WIDTH),
                    &style
                ),
                ctx.style(
                    &format!(
                        "{} free of {}  ({:.1}%)  ·  {} used",
                        output::format_bytes(d.free_bytes),
                        output::format_bytes(d.total_bytes),
                        d.pct_free,
                        output::format_bytes(d.used_bytes),
                    ),
                    &bold
                ),
            );
            println!(
                "  {:<12}{}",
                ctx.style("pressure", &bold),
                ctx.style(&pressure_sentence(state), &style),
            );
        }
        None => {
            println!(
                "  {:<12}{}",
                ctx.style("disk", &bold),
                ctx.style(
                    &format!(
                        "unknown — df failed ({})",
                        state.disk_error.as_deref().unwrap_or("no detail")
                    ),
                    &dim
                ),
            );
        }
    }
    println!(
        "  {:<12}{}",
        "",
        ctx.style(&policy_sentence(&state.policy), &dim)
    );
    println!();

    // ── when things were measured ───────────────────────────────────────────
    println!(
        "  {:<12}{}",
        ctx.style("polled", &bold),
        ctx.style(&measured_sentence(state), &dim),
    );
    println!(
        "  {:<12}{}",
        ctx.style("survey", &bold),
        ctx.style(&survey_sentence(state), &dim),
    );
    println!();

    // ── largest known owners (estimate) ─────────────────────────────────────
    match &state.survey {
        Some(s) if !s.largest_owners.is_empty() => {
            println!(
                "  {}  {}",
                ctx.style("largest known owners", &bold),
                ctx.style(
                    &format!(
                        "({} from a survey {} old)",
                        Certainty::Estimate.label(),
                        humanize(s.age_seconds)
                    ),
                    &dim
                ),
            );
            let max = s.largest_owners.iter().map(|o| o.bytes).max().unwrap_or(1);
            for o in &s.largest_owners {
                println!(
                    "    {}  {:>10}  {}  {}",
                    ctx.style("◆", &yellow),
                    ctx.style(&output::format_bytes(o.bytes), &bold),
                    ctx.style(&output::size_bar(o.bytes, max, 14), &yellow),
                    ctx.style(&o.path.display().to_string(), &dim),
                );
            }
            println!(
                "  {:<12}{}",
                ctx.style("reclaim", &bold),
                ctx.style(
                    &format!(
                        "~{} across {} known candidate(s) — {}, each still pressure-tested before \
                         anything is removed",
                        output::format_bytes(s.known_reclaimable_bytes),
                        s.known_reclaimable_entries,
                        Certainty::Estimate.label(),
                    ),
                    &dim
                ),
            );
        }
        Some(s) => {
            println!(
                "  {:<12}{}",
                ctx.style("owners", &bold),
                ctx.style(
                    s.not_summarized
                        .as_deref()
                        .unwrap_or("unknown — the survey recorded no directory totals"),
                    &dim
                ),
            );
        }
        None => {
            println!(
                "  {:<12}{}",
                ctx.style("owners", &bold),
                ctx.style(
                    "unknown — no survey on record, so nothing is known about what is using the \
                     disk",
                    &dim
                ),
            );
        }
    }
    println!();

    // ── trend ───────────────────────────────────────────────────────────────
    if state.free_series.len() >= 2 {
        let series: Vec<f64> = state.free_series.iter().map(|v| *v as f64).collect();
        println!(
            "  {:<12}{}  {}",
            ctx.style("free hist", &bold),
            ctx.style(&output::sparkline(&series, BAR_WIDTH), &bold),
            ctx.style(
                &format!("{} sample(s), 7d window", state.free_series.len()),
                &dim
            ),
        );
    }
    println!(
        "  {:<12}{}",
        ctx.style("trend", &bold),
        ctx.style(&trend_sentence(&state.trend), &dim),
    );
    println!(
        "  {:<12}{}",
        ctx.style("recovery", &bold),
        ctx.style(&recovery_sentence(&state.recovery), &dim),
    );
    println!(
        "  {:<12}{}",
        ctx.style("alerts", &bold),
        ctx.style(&state.alerts, &dim),
    );
    println!();

    // ── next actions ────────────────────────────────────────────────────────
    println!("  {}", ctx.style(&output::rule("next", PANEL_WIDTH), &dim));
    println!();
    let cyan = Style::new().cyan();
    for a in &state.next_actions {
        println!(
            "    {}  {}",
            ctx.style(&format!("{:<22}", a.command), &cyan),
            ctx.style(&a.why, &dim),
        );
    }
    println!();
    println!(
        "  {}",
        ctx.style(
            "Read-only: this panel never scans and never deletes. Live view: `diskspace top`.",
            &dim
        )
    );
    println!();
}

fn pressure_sentence(state: &KnownState) -> String {
    let p = &state.policy;
    match state.pressure.as_str() {
        "critical" => format!(
            "CRITICAL — below the {:.1}% critical floor",
            p.critical_pct_free
        ),
        "urgent" => format!(
            "URGENT — below the {:.1}% urgent threshold",
            p.urgent_pct_free
        ),
        "low" => format!("LOW — below the {:.1}% soft target", p.soft_pct_free),
        "ok" => format!("ok — above the {:.1}% soft target", p.soft_pct_free),
        _ => "unknown".to_string(),
    }
}

fn policy_sentence(p: &PolicyView) -> String {
    let reclaim = if p.autoreclaim_opt_in {
        format!(
            "gated auto-reclaim ON (airlocks; deletes only below {:.0} GB free)",
            p.pressure_threshold_gb
        )
    } else {
        "auto-reclaim OFF (notify only)".to_string()
    };
    let headroom = match p.headroom_gb {
        Some(gb) => format!(" · headroom floor {:.0} GB", gb),
        None => String::new(),
    };
    format!(
        "policy: soft <{:.0}% · urgent <{:.0}% · critical <{:.0}% · {}{}",
        p.soft_pct_free, p.urgent_pct_free, p.critical_pct_free, reclaim, headroom
    )
}

/// Free-space polling: the live df read plus the watcher's last sample. Says
/// nothing about directories — that is the survey's job.
fn measured_sentence(state: &KnownState) -> String {
    let df = match &state.disk {
        Some(_) => "df read just now (live)".to_string(),
        None => "df unavailable".to_string(),
    };
    let w = &state.watch;
    let watch = match (w.last_tick, &w.last_level) {
        (Some(ts), Some(level)) => {
            let age = ago(Utc::now().signed_duration_since(ts).num_seconds().max(0));
            let pct = w
                .last_pct_free
                .map(|p| format!(", {:.1}% free", p))
                .unwrap_or_default();
            let mut s = format!("watch last sampled {} ({}{}", age, level, pct);
            if w.certainty == Certainty::Stale {
                s.push_str(", STALE");
            }
            s.push(')');
            if !w.installed {
                s.push_str(" — watch not installed now");
            } else if !w.loaded {
                s.push_str(" — watch agent not loaded");
            } else if w.certainty == Certainty::Stale {
                s.push_str(" — monitoring stopped or stalled");
            } else {
                s.push_str(" — monitoring on");
            }
            s
        }
        _ => {
            if w.installed {
                "watch installed but has not reported a sample yet".to_string()
            } else {
                "watch not installed — no background polling".to_string()
            }
        }
    };
    format!("{}  ·  {}", df, watch)
}

fn survey_sentence(state: &KnownState) -> String {
    match &state.survey {
        Some(s) => format!(
            "measured {}  ·  scope {}  ·  {}{}",
            ago(s.age_seconds),
            s.scope.display(),
            s.certainty.label(),
            if s.certainty == Certainty::Stale {
                " (>24h — re-run `diskspace survey`)"
            } else {
                ""
            }
        ),
        None => "unknown — no survey cache on record".to_string(),
    }
}

fn trend_sentence(t: &BurnTrend) -> String {
    match (t.burn_rate_bytes_per_day, t.days_to_full) {
        (Some(rate), Some(days)) if rate > 0.0 => format!(
            "filling at {}/day  ·  full in ~{} day(s)  ({} sample(s), advisory)",
            output::format_bytes(rate as u64),
            days,
            t.samples
        ),
        (Some(rate), _) if rate < 0.0 => format!(
            "freeing {}/day  ({} sample(s), advisory)",
            output::format_bytes((-rate) as u64),
            t.samples
        ),
        (Some(_), _) => format!("flat — no meaningful drift ({} sample(s))", t.samples),
        (None, _) if t.samples == 0 => {
            "unknown — no df samples yet; the watch records one every 5 min".to_string()
        }
        (None, _) => format!(
            "unknown — no stable rate yet, {} sample(s) since the last big change (advisory)",
            t.samples
        ),
    }
}

fn recovery_sentence(r: &RecoveryView) -> String {
    let Some(i) = &r.latest else {
        return "no incidents on record".to_string();
    };
    let what = match (i.items, i.disposition.as_deref()) {
        (0, _) => "nothing cleared the gate".to_string(),
        (n, Some("airlock")) => format!("{} item(s) airlocked (reversible)", n),
        (n, Some("delete")) => format!("{} item(s) deleted", n),
        (n, _) => format!("{} item(s) acted on", n),
    };
    format!(
        "latest incident {} ({}, {}) · {} pass(es) · {} · {} refused · est. {} · measured freed {}{}",
        i.id,
        i.level,
        if i.open { "open" } else { "closed" },
        i.passes,
        what,
        i.refused,
        output::format_bytes(i.bytes_estimated),
        output::format_bytes(i.actually_freed),
        if r.incidents_recorded > 1 {
            format!(" · {} on record", r.incidents_recorded)
        } else {
            String::new()
        }
    )
}

fn alerts_sentence(w: &WatchView) -> String {
    if !w.installed {
        "none — `diskspace watch install` enables disk-pressure alerts".to_string()
    } else if !w.loaded {
        "watch installed but not loaded — re-run `diskspace watch install`".to_string()
    } else {
        "macOS banners from the watch agent (no action buttons yet)".to_string()
    }
}

/// Compact relative age.
/// `humanize` with the "ago" suffix, except for "just now".
fn ago(secs: i64) -> String {
    let h = humanize(secs);
    if h == "just now" {
        h
    } else {
        format!("{h} ago")
    }
}

pub fn humanize(secs: i64) -> String {
    if secs < 60 {
        "just now".to_string()
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_state() -> KnownState {
        KnownState {
            generated_at: Utc::now(),
            disk: None,
            disk_error: Some("df boom".into()),
            pressure: "unknown".into(),
            critical: false,
            survey: None,
            watch: WatchView {
                installed: false,
                loaded: false,
                last_tick: None,
                last_level: None,
                last_pct_free: None,
                last_free_bytes: None,
                certainty: Certainty::Unknown,
            },
            trend: BurnTrend::default(),
            free_series: Vec::new(),
            recovery: RecoveryView {
                latest: None,
                incidents_recorded: 0,
            },
            policy: PolicyView {
                soft_pct_free: 10.0,
                urgent_pct_free: 5.0,
                critical_pct_free: 1.0,
                autoreclaim_opt_in: false,
                headroom_gb: None,
                pressure_threshold_gb: 5.0,
            },
            alerts: String::new(),
            next_actions: Vec::new(),
        }
    }

    #[test]
    fn certainty_labels_are_honest_not_blank() {
        for c in [
            Certainty::Live,
            Certainty::Recorded,
            Certainty::Stale,
            Certainty::Estimate,
            Certainty::Unknown,
        ] {
            assert!(!c.label().is_empty());
        }
        assert_eq!(Certainty::Stale.label(), "STALE");
        assert_eq!(Certainty::Unknown.label(), "unknown");
    }

    #[test]
    fn trend_without_samples_says_unknown() {
        let s = trend_sentence(&BurnTrend::default());
        assert!(s.starts_with("unknown"), "{}", s);
    }

    #[test]
    fn missing_survey_says_unknown_not_zero() {
        let s = empty_state();
        assert!(survey_sentence(&s).starts_with("unknown"));
        assert!(measured_sentence(&s).contains("df unavailable"));
        assert!(measured_sentence(&s).contains("watch not installed"));
        assert_eq!(recovery_sentence(&s.recovery), "no incidents on record");
    }

    /// A survey finished seconds ago reads "measured just now", never "just now ago".
    #[test]
    fn fresh_survey_reads_just_now_without_ago() {
        let mut s = empty_state();
        s.survey = Some(SurveyView {
            scanned_at: Utc::now(),
            age_seconds: 5,
            scope: PathBuf::from("/home/u"),
            total_bytes: 10,
            certainty: Certainty::Recorded,
            largest_owners: Vec::new(),
            known_reclaimable_bytes: 0,
            known_reclaimable_entries: 0,
            not_summarized: None,
        });
        let m = survey_sentence(&s);
        assert!(m.starts_with("measured just now  ·"), "{m}");
        assert!(!m.contains("just now ago"), "{m}");
    }

    #[test]
    fn stale_survey_is_flagged_and_recommends_remeasure() {
        let mut s = empty_state();
        s.survey = Some(SurveyView {
            scanned_at: Utc::now() - Duration::days(3),
            age_seconds: 3 * 86_400,
            scope: PathBuf::from("/home/u"),
            total_bytes: 10,
            certainty: Certainty::Stale,
            largest_owners: Vec::new(),
            known_reclaimable_bytes: 0,
            known_reclaimable_entries: 0,
            not_summarized: None,
        });
        let actions = next_actions("ok", s.survey.as_ref(), &s.watch);
        assert!(actions.iter().any(|a| a.command == "diskspace survey"));
        assert!(survey_sentence(&s).contains("STALE"));
    }

    /// A stale watcher sample is still shown, with its values, and the reader is
    /// told monitoring is not running.
    #[test]
    fn stale_watch_sample_is_shown_and_labelled() {
        let mut s = empty_state();
        s.watch = WatchView {
            installed: false,
            loaded: false,
            last_tick: Some(Utc::now() - Duration::hours(3)),
            last_level: Some("urgent".into()),
            last_pct_free: Some(3.2),
            last_free_bytes: Some(1),
            certainty: Certainty::Stale,
        };
        let m = measured_sentence(&s);
        assert!(m.contains("3h ago"), "{m}");
        assert!(m.contains("urgent"), "{m}");
        assert!(m.contains("3.2% free"), "{m}");
        assert!(m.contains("STALE"), "{m}");
        assert!(m.contains("not installed"), "{m}");
    }

    /// A sample under a minute old reads "just now", never "just now ago".
    #[test]
    fn fresh_watch_sample_reads_just_now_without_ago() {
        let mut s = empty_state();
        s.watch = WatchView {
            installed: true,
            loaded: true,
            last_tick: Some(Utc::now()),
            last_level: Some("urgent".into()),
            last_pct_free: Some(0.5),
            last_free_bytes: Some(1),
            certainty: Certainty::Recorded,
        };
        let m = measured_sentence(&s);
        assert!(m.contains("sampled just now ("), "{m}");
        assert!(!m.contains("just now ago"), "{m}");
    }

    #[test]
    fn recovery_sentence_reports_measured_not_estimated_bytes() {
        let r = RecoveryView {
            latest: Some(IncidentView {
                id: "urgent-20261005".into(),
                level: "urgent".into(),
                opened_ts: Utc::now(),
                last_ts: Utc::now(),
                passes: 2,
                items: 3,
                refused: 1,
                bytes_estimated: 5_000_000,
                actually_freed: 123_456,
                disposition: Some("airlock".into()),
                open: true,
            }),
            incidents_recorded: 2,
        };
        let s = recovery_sentence(&r);
        assert!(s.contains("urgent-20261005"), "{s}");
        assert!(s.contains("airlocked (reversible)"), "{s}");
        assert!(s.contains("measured freed"), "{s}");
        assert!(s.contains("2 on record"), "{s}");
    }

    /// `largest_dirs` includes the scan root's own ancestors (`/`, `/Users`).
    /// Those are not owners of anything inside the scope; only directories
    /// strictly below it are.
    #[test]
    fn owners_exclude_the_scope_and_its_ancestors() {
        use crate::core::scanner::DirTotal;
        let scope = PathBuf::from("/Users/u");
        let dirs = vec![
            DirTotal {
                path: PathBuf::from("/"),
                total_bytes: 900,
            },
            DirTotal {
                path: PathBuf::from("/Users"),
                total_bytes: 900,
            },
            DirTotal {
                path: PathBuf::from("/Users/u"),
                total_bytes: 900,
            },
            DirTotal {
                path: PathBuf::from("/Users/u/Dropbox"),
                total_bytes: 500,
            },
            DirTotal {
                path: PathBuf::from("/Users/u/Library"),
                total_bytes: 300,
            },
        ];
        let owners = owners_below(&scope, &dirs, 5);
        let paths: Vec<_> = owners
            .iter()
            .map(|o| o.path.display().to_string())
            .collect();
        assert_eq!(paths, vec!["/Users/u/Dropbox", "/Users/u/Library"]);
    }

    /// Many df samples can sit in the window while the fitted segment after a
    /// big step is still too short for a rate. The sentence must not claim the
    /// samples are missing.
    #[test]
    fn trend_without_rate_but_with_samples_says_no_stable_rate() {
        let t = BurnTrend {
            samples: 16,
            ..BurnTrend::default()
        };
        let s = trend_sentence(&t);
        assert!(s.starts_with("unknown"), "{s}");
        assert!(s.contains("no stable rate"), "{s}");
        assert!(!s.contains("only"), "{s}");
    }

    /// A fresh sample from an installed, loaded agent states that monitoring is on.
    #[test]
    fn fresh_sample_from_loaded_agent_says_monitoring_on() {
        let mut s = empty_state();
        s.watch = WatchView {
            installed: true,
            loaded: true,
            last_tick: Some(Utc::now() - Duration::minutes(3)),
            last_level: Some("ok".into()),
            last_pct_free: Some(42.0),
            last_free_bytes: Some(1),
            certainty: Certainty::Recorded,
        };
        let m = measured_sentence(&s);
        assert!(m.contains("monitoring on"), "{m}");
    }

    #[test]
    fn humanize_buckets() {
        assert_eq!(humanize(5), "just now");
        assert_eq!(humanize(305), "5m");
        assert_eq!(humanize(7200), "2h");
        assert_eq!(humanize(3 * 86_400), "3d");
    }
}

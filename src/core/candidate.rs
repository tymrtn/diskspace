use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    DevArtifact,
    AppCache,
    DownloadEntropy,
    VmDisk,
    Unknown,
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::DevArtifact => write!(f, "dev-artifact"),
            Category::AppCache => write!(f, "app-cache"),
            Category::DownloadEntropy => write!(f, "download-entropy"),
            Category::VmDisk => write!(f, "vm-disk"),
            Category::Unknown => write!(f, "unknown"),
        }
    }
}

/// A scanned filesystem entry, annotated with category and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedEntry {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub category: Category,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    /// Device id (unix `stat.st_dev`) — half of the inode identity used to key
    /// the time series. `None` on non-unix or when unavailable. Additive +
    /// serde-default so legacy scan.json still deserializes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<u64>,
    /// Inode number (unix `stat.st_ino`). `None` on non-unix or when unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ino: Option<u64>,
    /// Inode change time as nanoseconds-since-epoch (`st_ctime * 1e9 +
    /// st_ctime_nsec`), NOT whole seconds. The series layer keys continuity on
    /// `(dev, ino)` alone and uses this ctime only as an inode-reuse tiebreaker;
    /// full sub-second resolution is required because a delete + create can
    /// reuse the same inode inside one wall-clock second. `None` on non-unix or
    /// when unavailable. Additive + serde-default so legacy scan.json still
    /// deserializes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctime: Option<i64>,
}

/// A flattened, agent-facing view of a rule's [`Consequences`] plus its
/// reference URL. This is the "consequence contract" attached to a candidate or
/// a check result so an agent can read recovery semantics without re-joining
/// against the rule set. Purely advisory metadata — it never influences ranking
/// (`Candidate::score`) or the safety gate (`pressure_test`).
///
/// [`Consequences`]: crate::core::rules::Consequences
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsequenceContract {
    /// Recovery class, copied VERBATIM from `Consequences.recovery`
    /// (auto | redownload | rebuild | recreate | manual | irreversible).
    pub recovery_class: String,
    /// Rough recovery time in seconds (from `Consequences.rebuild_seconds`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_cost_seconds: Option<u32>,
    /// One-line, user-visible impact description.
    pub impact: String,
    /// Optional command to recover the data, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_cmd: Option<String>,
    /// Canonical reference (rule's own URL, or a synthesized release-tagged
    /// link into `rules/builtin.yaml`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_url: Option<String>,
}

/// A candidate for cleanup: a scanned entry promoted by a matching rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    pub rule_id: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub category: Category,
    pub confidence: f32,
    pub reason: String,
    pub domain: Option<String>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    /// Consequence metadata copied from the matching rule (M6).
    #[serde(default)]
    pub consequences: Option<crate::core::rules::Consequences>,
    /// Agent-surface enrichment (P2): the flattened consequence contract. Set by
    /// `agent_surface::enrich_candidate`. Additive + serde-default skip-if-none.
    /// ADVISORY ONLY — never read by `score()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consequence_contract: Option<ConsequenceContract>,
    /// Agent-surface enrichment (P2): advisory measurements for this path. Set by
    /// `agent_surface::enrich_candidate` via `metrics::compute_metrics(...).ok()`.
    /// Additive + serde-default skip-if-none. ADVISORY ONLY — measurement signals
    /// MUST NOT influence ranking; `score()` never reads this field (enforced by
    /// the scope-fence guard in `metrics.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<crate::core::metrics::Metrics>,
    /// Agent-surface enrichment (P2): canonical reference URL for the matching
    /// rule. Additive + serde-default skip-if-none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_url: Option<String>,
}

impl Candidate {
    /// Sort key: larger yield and higher confidence rank first.
    ///
    /// SCOPE FENCE: this MUST stay measurement-blind. It reads ONLY `size_bytes`
    /// and `confidence` — never `self.metrics`, `self.consequence_contract`, or
    /// any advisory signal. The mechanical guard in `metrics.rs` scans THIS
    /// function body and fails the build if `metrics` ever appears in it.
    pub fn score(&self) -> f64 {
        self.size_bytes as f64 * self.confidence as f64
    }
}

/// The result of a pressure-test on a candidate (used in M2).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub candidate_id: String,
    pub safe: bool,
    pub confidence: f32,
    pub steps: Vec<CheckStep>,
    /// Consequence metadata: what happens if you delete this (M6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consequences: Option<crate::core::rules::Consequences>,
    /// Agent-surface enrichment (P2): flattened consequence contract. Attached
    /// AFTER `pressure_test` runs — never influences `safe`. Additive +
    /// serde-default skip-if-none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consequence_contract: Option<ConsequenceContract>,
    /// Agent-surface enrichment (P2): advisory measurements for the candidate's
    /// path. Attached AFTER `pressure_test` runs — never influences `safe`.
    /// Additive + serde-default skip-if-none. ADVISORY ONLY.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<crate::core::metrics::Metrics>,
    /// Agent-surface enrichment (P2): canonical reference URL for the matching
    /// rule. Additive + serde-default skip-if-none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_url: Option<String>,
}

impl CheckResult {
    /// Construct a gate result with the advisory agent-surface fields unset.
    ///
    /// The pressure-test gate calls this so its own function body never mentions
    /// the advisory `metrics`/`consequence_contract`/`reference_url` fields —
    /// preserving the metrics-blindness scope fence (the guard scans the
    /// `pressure_test` body for `metrics`). Enrichment happens later, in the
    /// command layer, strictly AFTER `safe` is decided.
    pub fn gate(candidate_id: String, safe: bool, confidence: f32, steps: Vec<CheckStep>) -> Self {
        CheckResult {
            candidate_id,
            safe,
            confidence,
            steps,
            consequences: None,
            consequence_contract: None,
            metrics: None,
            reference_url: None,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckStep {
    pub name: String,
    pub passed: bool,
    pub note: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::metrics::Metrics;

    fn sample_candidate() -> Candidate {
        Candidate {
            id: "rule-abc".into(),
            rule_id: "rule".into(),
            path: PathBuf::from("/p"),
            size_bytes: 2048,
            category: Category::DevArtifact,
            confidence: 0.9,
            reason: "test".into(),
            domain: None,
            modified: None,
            accessed: None,
            consequences: None,
            consequence_contract: Some(ConsequenceContract {
                recovery_class: "rebuild".into(),
                recovery_cost_seconds: Some(120),
                impact: "rebuilt next run".into(),
                recovery_cmd: Some("cargo build".into()),
                reference_url: Some("https://x/y".into()),
            }),
            metrics: Some(Metrics::default()),
            reference_url: Some("https://x/y".into()),
        }
    }

    #[test]
    fn candidate_json_includes_new_agent_surface_keys() {
        // This mirrors what `diskspace detect --json` serializes per candidate.
        let json = serde_json::to_value(sample_candidate()).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("consequence_contract"));
        assert!(obj.contains_key("metrics"));
        assert!(obj.contains_key("reference_url"));
        assert_eq!(
            obj["consequence_contract"]["recovery_class"],
            serde_json::json!("rebuild")
        );
        assert_eq!(obj["reference_url"], serde_json::json!("https://x/y"));
    }

    #[test]
    fn candidate_new_fields_skip_when_none() {
        // skip_serializing_if keeps the JSON clean (and the cache small) when the
        // agent-surface fields are unset — they must NOT appear as null keys.
        let mut c = sample_candidate();
        c.consequence_contract = None;
        c.metrics = None;
        c.reference_url = None;
        let json = serde_json::to_value(&c).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("consequence_contract"));
        assert!(!obj.contains_key("metrics"));
        assert!(!obj.contains_key("reference_url"));
    }

    #[test]
    fn legacy_candidate_json_without_new_fields_deserializes() {
        // A pre-P2 candidate JSON (no agent-surface keys) must still deserialize,
        // with the new fields defaulting to None. Back-compat.
        let legacy = r#"{
            "id": "rule-abc",
            "rule_id": "rule",
            "path": "/p",
            "size_bytes": 2048,
            "category": "dev_artifact",
            "confidence": 0.9,
            "reason": "test",
            "domain": null,
            "modified": null,
            "accessed": null
        }"#;
        let c: Candidate = serde_json::from_str(legacy).expect("legacy candidate parses");
        assert!(c.consequence_contract.is_none());
        assert!(c.metrics.is_none());
        assert!(c.reference_url.is_none());
    }

    #[test]
    fn gate_leaves_advisory_fields_unset_and_safe_intact() {
        // The pressure-test gate constructor sets `safe` from its args and leaves
        // every advisory field None — enrichment can only happen later, never
        // touching `safe`.
        let r = CheckResult::gate("c1".into(), true, 1.0, vec![]);
        assert!(r.safe);
        assert!(r.consequence_contract.is_none());
        assert!(r.metrics.is_none());
        assert!(r.reference_url.is_none());

        // Attaching advisory fields afterward must not change `safe`.
        let mut enriched = CheckResult::gate("c1".into(), true, 1.0, vec![]);
        enriched.metrics = Some(Metrics::default());
        enriched.reference_url = Some("https://x/y".into());
        assert!(enriched.safe, "enrichment must never flip `safe`");
    }

    #[test]
    fn score_ignores_metrics_field() {
        // Value-level proof of the scope fence: two candidates identical in
        // size/confidence score equally regardless of their metrics field.
        let mut a = sample_candidate();
        let mut b = sample_candidate();
        a.metrics = Some(Metrics {
            burn_rate_bytes_per_day: Some(9.9e12),
            days_to_full: Some(1),
            ..Metrics::default()
        });
        b.metrics = None;
        assert_eq!(a.score(), b.score(), "metrics must not affect score()");
    }
}

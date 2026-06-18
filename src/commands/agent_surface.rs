//! Agent-surface enrichment (P2) — the single source of truth for turning a
//! rule's [`Consequences`] into a flattened [`ConsequenceContract`], synthesizing
//! a canonical [`reference_url`], and attaching advisory [`Metrics`] to a
//! [`Candidate`].
//!
//! ## Why this lives in one place
//!
//! `detect`, `check`, and `explain` all need the same three derived fields
//! (consequence contract, reference URL, advisory metrics). Centralizing the
//! mapping here keeps the recovery-class verbatim copy, the release-tagged URL
//! template, and the metrics best-effort call consistent across every command —
//! one bug to fix, one behavior to test.
//!
//! ## Scope fence
//!
//! These helpers are PURELY ADVISORY. `enrich_candidate` writes only the new
//! additive fields on `Candidate`; it never touches `size_bytes`, `confidence`,
//! or anything `Candidate::score` reads, and it is never called from the
//! pressure-test gate. Measurement can never reorder candidates or flip `safe`.
//!
//! [`Consequences`]: crate::core::rules::Consequences
//! [`Metrics`]: crate::core::metrics::Metrics

use crate::core::candidate::{Candidate, ConsequenceContract};
use crate::core::metrics;
use crate::core::rules::{Consequences, Rule};
use crate::profile::Profile;

/// Build the agent-facing [`ConsequenceContract`] from a rule's [`Consequences`].
///
/// `recovery_class` is copied **verbatim** from `cons.recovery` (it is already a
/// closed vocabulary: auto | redownload | rebuild | recreate | manual |
/// irreversible — we do not normalize or validate it here, so the contract is a
/// faithful mirror of the rule). `reference_url` is resolved via
/// [`reference_url`] from the rule's own URL or a synthesized release-tagged
/// fallback.
pub fn contract_from_consequences(
    cons: &Consequences,
    rule_id: &str,
    rule_url: Option<&str>,
) -> ConsequenceContract {
    ConsequenceContract {
        recovery_class: cons.recovery.clone(),
        recovery_cost_seconds: cons.rebuild_seconds,
        impact: cons.impact.clone(),
        recovery_cmd: cons.recovery_cmd.clone(),
        reference_url: Some(reference_url(rule_id, rule_url)),
    }
}

/// Canonical reference URL for a rule. Prefers the rule's own `reference_url`
/// when present; otherwise synthesizes a RELEASE-TAGGED deep link into the
/// builtin rules file, so the link always points at the exact ruleset this
/// binary shipped with (not a moving `main`).
pub fn reference_url(rule_id: &str, rule_url: Option<&str>) -> String {
    match rule_url {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => format!(
            "https://github.com/tymrtn/diskspace/blob/v{}/rules/builtin.yaml#{}",
            env!("CARGO_PKG_VERSION"),
            rule_id
        ),
    }
}

/// Enrich a candidate in place with the three agent-surface fields:
/// `reference_url`, `consequence_contract` (derived from `c.consequences`), and
/// advisory `metrics` (best-effort `compute_metrics(...).ok()`).
///
/// ADVISORY ONLY: this never mutates `size_bytes` / `confidence` and is never
/// part of the pressure-test path, so it cannot influence ranking or the gate.
///
/// PERF: `compute_metrics` reads the append-only df/series/history logs per call.
/// For the candidate set (tens, not the 589k-entry scan cache) this is
/// acceptable; we keep it best-effort and swallow errors with `.ok()`.
pub fn enrich_candidate(c: &mut Candidate, rule: &Rule, prof: &Profile) {
    let url = reference_url(&rule.id, rule.reference_url.as_deref());

    c.consequence_contract = c
        .consequences
        .as_ref()
        .map(|cons| contract_from_consequences(cons, &rule.id, rule.reference_url.as_deref()));

    // Attach metrics ONLY when there's an actual measurement signal. When no series
    // exists yet, `compute_metrics` returns an all-`None` `Metrics` with
    // `metric_confidence: 0.0` — emitting that would mislead an agent into reading a
    // hard 0% as "measured and nil" rather than "no data". Dropping it to `None`
    // (the field is `skip_serializing_if = "Option::is_none"`) makes the JSON OMIT
    // `metrics` entirely, the honest "metrics_available: false" signal.
    c.metrics = metrics::compute_metrics(&c.path, prof)
        .ok()
        .filter(|m| !m.has_no_signal());
    c.reference_url = Some(url);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::candidate::{Candidate, Category};
    use crate::core::rules::Consequences;
    use std::path::PathBuf;

    fn cons(recovery: &str) -> Consequences {
        Consequences {
            recovery: recovery.to_string(),
            rebuild_seconds: Some(120),
            impact: "rebuilt on next run".into(),
            recovery_cmd: Some("npm install".into()),
        }
    }

    fn rule_with(id: &str, url: Option<&str>, c: Option<Consequences>) -> Rule {
        Rule {
            id: id.to_string(),
            category: "dev-artifact".into(),
            path_pattern: "~/x".into(),
            domain: None,
            base_confidence: 0.9,
            reason: "test".into(),
            exclude_if_recent_access_days: None,
            exclude_if_recent_modified_days: None,
            consequences: c,
            reference_url: url.map(|s| s.to_string()),
        }
    }

    fn candidate(path: &str, c: Option<Consequences>) -> Candidate {
        Candidate {
            id: "rule-abc".into(),
            rule_id: "rule".into(),
            path: PathBuf::from(path),
            size_bytes: 1024,
            category: Category::DevArtifact,
            confidence: 0.9,
            reason: "test".into(),
            domain: None,
            modified: None,
            accessed: None,
            consequences: c,
            consequence_contract: None,
            metrics: None,
            reference_url: None,
        }
    }

    #[test]
    fn contract_maps_recovery_class_verbatim() {
        for recovery in [
            "auto",
            "redownload",
            "rebuild",
            "recreate",
            "manual",
            "irreversible",
        ] {
            let k = contract_from_consequences(&cons(recovery), "node_modules", None);
            assert_eq!(
                k.recovery_class, recovery,
                "recovery_class must mirror Consequences.recovery verbatim"
            );
            assert_eq!(k.recovery_cost_seconds, Some(120));
            assert_eq!(k.impact, "rebuilt on next run");
            assert_eq!(k.recovery_cmd.as_deref(), Some("npm install"));
        }
    }

    #[test]
    fn reference_url_uses_rule_url_when_present() {
        let u = reference_url("node_modules", Some("https://docs.example/rule"));
        assert_eq!(u, "https://docs.example/rule");
    }

    #[test]
    fn reference_url_synthesizes_release_tagged_fallback() {
        let u = reference_url("node_modules", None);
        let expected = format!(
            "https://github.com/tymrtn/diskspace/blob/v{}/rules/builtin.yaml#node_modules",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(u, expected);
        // The tag must be the exact release version, never a moving branch.
        assert!(u.contains(&format!("/blob/v{}/", env!("CARGO_PKG_VERSION"))));
        assert!(!u.contains("/blob/main/"));
    }

    #[test]
    fn reference_url_empty_rule_url_falls_back() {
        // An empty string is treated as "no URL" and synthesizes the fallback.
        let u = reference_url("foo", Some(""));
        assert!(u.contains("/rules/builtin.yaml#foo"));
    }

    #[test]
    fn contract_carries_reference_url() {
        let with_url = contract_from_consequences(&cons("rebuild"), "foo", Some("https://x/y"));
        assert_eq!(with_url.reference_url.as_deref(), Some("https://x/y"));

        let synthesized = contract_from_consequences(&cons("rebuild"), "foo", None);
        assert!(synthesized
            .reference_url
            .as_deref()
            .unwrap()
            .contains("/rules/builtin.yaml#foo"));
    }

    #[test]
    fn enrich_populates_contract_and_reference_url() {
        let prof = Profile::default();
        let mut c = candidate("/tmp/does-not-matter", Some(cons("redownload")));
        let rule = rule_with("rule", None, Some(cons("redownload")));

        enrich_candidate(&mut c, &rule, &prof);

        // reference_url is always set.
        assert!(c.reference_url.is_some());
        assert!(c
            .reference_url
            .as_deref()
            .unwrap()
            .contains("/rules/builtin.yaml#rule"));

        // consequence_contract derived from the candidate's own consequences.
        let k = c.consequence_contract.expect("contract present");
        assert_eq!(k.recovery_class, "redownload");
        assert_eq!(k.impact, "rebuilt on next run");

        // metrics is best-effort: Option, may be Some(default) or None — but the
        // call must not panic and must leave the field a valid Option.
        let _ = c.metrics; // presence is environment-dependent; no assertion on value
    }

    #[test]
    fn enrich_emits_no_metrics_when_series_has_no_signal() {
        // With NO series data for the path, enrichment must leave `metrics` as
        // `None` (so the JSON OMITS it) rather than attaching a misleading all-None
        // `Metrics` with `metric_confidence: 0.0`. This guards audit #9.
        let prof = Profile::default();
        // A path that has certainly never been observed in any series.
        let mut c = candidate(
            "/tmp/diskspace-no-series-ever-3f9a2c/never",
            Some(cons("redownload")),
        );
        let rule = rule_with("rule", None, Some(cons("redownload")));

        enrich_candidate(&mut c, &rule, &prof);

        // The metrics field is omitted on serialize (skip_serializing_if = is_none),
        // so the agent reads no `metrics` key — the honest "no data yet" signal.
        let v = serde_json::to_value(&c).unwrap();
        assert!(
            v.get("metrics").is_none(),
            "an all-None metrics (no series) must be DROPPED, not emitted as metric_confidence:0.0"
        );
    }

    #[test]
    fn metrics_has_no_signal_detects_empty_vs_populated() {
        use crate::core::metrics::Metrics;
        // Default = the all-None shape `compute_metrics` returns with no series.
        assert!(
            Metrics::default().has_no_signal(),
            "the default (all-None, 0.0 confidence) carries no signal"
        );
        // Any single populated field flips it.
        let m = Metrics {
            staleness_days: Some(3),
            ..Default::default()
        };
        assert!(!m.has_no_signal(), "a populated field is a real signal");
        let m2 = Metrics {
            metric_confidence: 0.6,
            ..Default::default()
        };
        assert!(
            !m2.has_no_signal(),
            "a positive confidence means contributing samples exist"
        );
    }

    #[test]
    fn enrich_leaves_contract_none_when_no_consequences() {
        let prof = Profile::default();
        let mut c = candidate("/tmp/no-cons", None);
        let rule = rule_with("rule", None, None);

        enrich_candidate(&mut c, &rule, &prof);

        assert!(
            c.consequence_contract.is_none(),
            "no consequences → no contract"
        );
        // reference_url is still set even without consequences.
        assert!(c.reference_url.is_some());
    }

    #[test]
    fn enrich_does_not_change_score_inputs() {
        // ADVISORY-ONLY guarantee at the value level: enrichment must not touch
        // size_bytes or confidence (the only score() inputs).
        let prof = Profile::default();
        let mut c = candidate("/tmp/x", Some(cons("rebuild")));
        let before_size = c.size_bytes;
        let before_conf = c.confidence;
        let before_score = c.score();
        let rule = rule_with("rule", None, Some(cons("rebuild")));

        enrich_candidate(&mut c, &rule, &prof);

        assert_eq!(c.size_bytes, before_size);
        assert_eq!(c.confidence, before_conf);
        assert_eq!(c.score(), before_score, "enrichment must not change score");
    }
}

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A declarative cleanup rule loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub category: String,
    /// Glob pattern relative to home or absolute
    pub path_pattern: String,
    pub domain: Option<String>,
    pub base_confidence: f32,
    pub reason: String,
    /// Skip candidate if accessed within this many days
    #[serde(default)]
    pub exclude_if_recent_access_days: Option<u32>,
    /// Skip candidate if modified within this many days
    #[serde(default)]
    pub exclude_if_recent_modified_days: Option<u32>,
    /// What happens if you delete this — recovery cost, performance impact, etc.
    #[serde(default)]
    pub consequences: Option<Consequences>,
}

/// Consequence metadata: what happens if a user deletes a candidate matching this rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consequences {
    /// How the data comes back. One of: "auto", "redownload", "rebuild", "recreate", "manual", "irreversible"
    pub recovery: String,
    /// Rough time cost to recover, in seconds. None if "manual" or "irreversible".
    #[serde(default)]
    pub rebuild_seconds: Option<u32>,
    /// One-line description of what the user will notice
    pub impact: String,
    /// Optional: command to recover, if any
    #[serde(default)]
    pub recovery_cmd: Option<String>,
}

static BUILTIN_RULES_YAML: &str = include_str!("../../rules/builtin.yaml");

pub fn load_builtin() -> Result<Vec<Rule>> {
    let rules: Vec<Rule> = serde_yaml::from_str(BUILTIN_RULES_YAML)?;
    Ok(rules)
}

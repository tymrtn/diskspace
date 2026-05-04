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
}

static BUILTIN_RULES_YAML: &str = include_str!("../../rules/builtin.yaml");

pub fn load_builtin() -> Result<Vec<Rule>> {
    let rules: Vec<Rule> = serde_yaml::from_str(BUILTIN_RULES_YAML)?;
    Ok(rules)
}

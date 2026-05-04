use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub focus: Focus,
    #[serde(default)]
    pub domains: HashMap<String, Domain>,
    #[serde(default)]
    pub paths: PathPolicies,
    #[serde(default)]
    pub preferences: Preferences,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Focus {
    pub current: Option<String>,
    pub updated: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Domain {
    pub active: bool,
    #[serde(default)]
    pub never_did: bool,
    pub last_active: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PathPolicies {
    #[serde(default)]
    pub never_touch: Vec<String>,
    #[serde(default)]
    pub always_safe: Vec<String>,
    #[serde(default)]
    pub never_suggest: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Preferences {
    pub quarantine_retention_days: u32,
    pub min_candidate_size_gb: f32,
    pub confirm_before_quarantine: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            quarantine_retention_days: 30,
            min_candidate_size_gb: 0.1,
            confirm_before_quarantine: true,
        }
    }
}

pub fn profile_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    PathBuf::from(home).join(".disk-advisor").join("profile.toml")
}

pub fn load() -> Result<Profile> {
    let path = profile_path();
    if !path.exists() {
        return Ok(Profile::default());
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("reading profile at {}", path.display()))?;
    let profile: Profile = toml::from_str(&content)
        .with_context(|| "parsing profile.toml — run `disk-advisor profile edit` to fix it")?;
    Ok(profile)
}

#[allow(dead_code)]
pub fn save(profile: &Profile) -> Result<()> {
    let path = profile_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(profile)?;
    std::fs::write(&path, content)?;
    Ok(())
}

pub fn data_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    PathBuf::from(home).join(".disk-advisor")
}

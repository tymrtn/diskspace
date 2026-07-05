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
    pub airlock_retention_days: u32,
    pub min_candidate_size_gb: f32,
    pub confirm_before_airlock: bool,
    /// Below this much free space, `doctor` switches from airlock-then-purge
    /// (reversible) to immediate-delete (irreversible) so bytes free up now.
    #[serde(default = "default_pressure_threshold_gb")]
    pub disk_pressure_threshold_gb: f32,
    /// Default path to the signed capability grant (`grant.json`) the actor reads
    /// when no `--grant <path>` is passed on the command line. `None` falls back to
    /// `grant::grant_path()` (`~/.diskspace/grant.json`). Lets a user pin a grant
    /// location in the profile without re-passing the flag on every invocation.
    /// Additive + serde-default so legacy profiles still parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_path: Option<String>,
    /// Standing opt-in for `watch` to autonomously reclaim SAFE regenerable caches
    /// (recovery ∈ {auto, redownload, rebuild}) when disk pressure hits the urgent
    /// threshold. This is the user's durable consent — the background monitor has
    /// no authority to delete anything unless this is `true`. Defaults to `false`
    /// (notify-only), so legacy profiles and fresh installs stay alert-only until
    /// the user explicitly turns self-healing on. Never touches project envs
    /// (recovery == "recreate"), databases, or secret stores — the safety floor and
    /// the recovery-class filter both exclude them.
    #[serde(default)]
    pub watch_autoreclaim: bool,
}

fn default_pressure_threshold_gb() -> f32 {
    5.0
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            airlock_retention_days: 7,
            min_candidate_size_gb: 0.1,
            confirm_before_airlock: true,
            disk_pressure_threshold_gb: 5.0,
            grant_path: None,
            watch_autoreclaim: false,
        }
    }
}

pub fn profile_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    PathBuf::from(home).join(".diskspace").join("profile.toml")
}

pub fn load() -> Result<Profile> {
    let path = profile_path();
    if !path.exists() {
        return Ok(Profile::default());
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("reading profile at {}", path.display()))?;
    let profile: Profile = toml::from_str(&content)
        .with_context(|| "parsing profile.toml — run `diskspace profile edit` to fix it")?;
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
    let new_dir = PathBuf::from(&home).join(".diskspace");

    // Chain migration: .disk-advisor → .diskspace, .disk-space → .diskspace.
    // Idempotent; runs at most once per historical name.
    if !new_dir.exists() {
        let intermediate = PathBuf::from(&home).join(".disk-space");
        let original = PathBuf::from(&home).join(".disk-advisor");
        if intermediate.exists() {
            let _ = std::fs::rename(&intermediate, &new_dir);
        } else if original.exists() {
            let _ = std::fs::rename(&original, &new_dir);
        }
    }

    new_dir
}

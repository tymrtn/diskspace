use anyhow::{bail, Context as _, Result};
use console::Style;

use crate::output::Context;
use crate::profile::{self, Profile};

pub fn get(ctx: &Context) -> Result<()> {
    let path = profile::profile_path();
    if !path.exists() {
        if ctx.json {
            println!("{}", serde_json::to_string_pretty(&Profile::default())?);
        } else {
            println!("\n  No profile yet. Run `disk-advisor profile edit` to create one.\n");
        }
        return Ok(());
    }

    let content = std::fs::read_to_string(&path).context("reading profile")?;

    if ctx.json {
        let prof: Profile = toml::from_str(&content).context("parsing profile")?;
        println!("{}", serde_json::to_string_pretty(&prof)?);
    } else {
        let bold = Style::new().bold();
        println!();
        println!("  {}", ctx.style(&path.display().to_string(), &bold));
        println!();
        for line in content.lines() {
            println!("  {}", line);
        }
        println!();
    }

    Ok(())
}

pub fn set(assignment: &str, ctx: &Context) -> Result<()> {
    let (key, value) = assignment
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("Expected key=value, got: {}", assignment))?;

    let path = profile::profile_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let content = if path.exists() {
        std::fs::read_to_string(&path)?
    } else {
        String::new()
    };

    let mut doc: toml_edit::DocumentMut = content.parse().context("parsing profile.toml")?;

    set_toml_key(&mut doc, key, value)?;
    std::fs::write(&path, doc.to_string())?;

    if ctx.json {
        println!(r#"{{"set":"{}","value":"{}"}}"#, key, value);
    } else {
        let bold = Style::new().bold();
        println!("\n  {} {} = {}\n", ctx.style("set", &bold), key, value);
    }

    Ok(())
}

pub fn edit(ctx: &Context) -> Result<()> {
    let path = profile::profile_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if !path.exists() {
        let default_content = default_profile_toml();
        std::fs::write(&path, default_content)?;
    }

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .with_context(|| format!("launching editor: {}", editor))?;

    if !status.success() {
        bail!("Editor exited with error");
    }

    if ctx.json {
        println!(r#"{{"edited":"{}"}}"#, path.display());
    } else {
        println!("\n  Profile saved.\n");
    }

    Ok(())
}

fn set_toml_key(doc: &mut toml_edit::DocumentMut, key: &str, value: &str) -> Result<()> {
    let parts: Vec<&str> = key.split('.').collect();
    if parts.is_empty() {
        bail!("Empty key");
    }

    let bool_val: Option<bool> = match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    };

    let toml_value = if let Some(b) = bool_val {
        toml_edit::value(b)
    } else if let Ok(n) = value.parse::<i64>() {
        toml_edit::value(n)
    } else if let Ok(f) = value.parse::<f64>() {
        toml_edit::value(f)
    } else {
        toml_edit::value(value)
    };

    match parts.as_slice() {
        [k] => {
            doc[k] = toml_value;
        }
        [t, k] => {
            doc[t][k] = toml_value;
        }
        [t, sub, k] => {
            doc[t][sub][k] = toml_value;
        }
        _ => bail!("Key too deep (max 3 levels): {}", key),
    }

    Ok(())
}

fn default_profile_toml() -> &'static str {
    r#"# disk-advisor profile
# Edit this file to personalize your cleanup recommendations.
# Your agent can also write to this with: disk-advisor profile set key=value

[focus]
current = ""
updated = ""

[domains]
# Set active = false for domains you no longer work in.
# disk-advisor will rank those candidates higher.
#
# ios_development = { active = false, last_active = "2024-11" }
# web_development = { active = true }
# python_development = { active = true }
# rust_development = { active = true }
# docker = { active = true }
# android_development = { active = false }
# music_production = { active = false, never_did = true }
# video_editing = { active = false }
# virtualization = { active = false }

[paths]
never_touch = [
    # "~/Documents/**",
    # "~/Clients/**",
]
always_safe = [
    # "~/Library/Developer/Xcode/DerivedData/**",
]
never_suggest = []

[preferences]
airlock_retention_days = 30
min_candidate_size_gb = 0.1
confirm_before_airlock = true
"#
}

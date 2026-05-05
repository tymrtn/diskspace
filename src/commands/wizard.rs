use anyhow::Result;
use console::{Style, Term};
use std::collections::HashMap;
use std::io::Write;

use crate::output::Context;
use crate::profile::{self, Domain, Focus, PathPolicies, Preferences, Profile};

struct DomainChoice {
    key: &'static str,
    label: &'static str,
    hint: &'static str,
}

const DOMAINS: &[DomainChoice] = &[
    DomainChoice {
        key: "web_development",
        label: "Web development",
        hint: "React, Node, npm, .next, webpack",
    },
    DomainChoice {
        key: "ios_development",
        label: "iOS / macOS",
        hint: "Xcode, Swift, DerivedData, simulators",
    },
    DomainChoice {
        key: "android_development",
        label: "Android",
        hint: "Android Studio, AVDs, Gradle cache",
    },
    DomainChoice {
        key: "data_science",
        label: "Python / data science",
        hint: "pip, venv, Jupyter, conda, .venv",
    },
    DomainChoice {
        key: "rust_development",
        label: "Rust / systems",
        hint: "cargo, target/, crates registry",
    },
    DomainChoice {
        key: "go_development",
        label: "Go",
        hint: "go/pkg, module cache, build cache",
    },
    DomainChoice {
        key: "docker",
        label: "Docker / containers",
        hint: "images, volumes, overlay storage",
    },
    DomainChoice {
        key: "video_editing",
        label: "Video editing",
        hint: "Premiere, DaVinci Resolve, render caches",
    },
    DomainChoice {
        key: "music_production",
        label: "Music production",
        hint: "Logic Pro, Ableton, audio plugins",
    },
    DomainChoice {
        key: "game_development",
        label: "Game development",
        hint: "Unity Library, Unreal Intermediate",
    },
];

/// Returns true if the wizard should run: no profile exists, interactive TTY, not agent mode.
pub fn should_run(ctx: &Context) -> bool {
    !ctx.json && !ctx.yes && console::user_attended() && !profile::profile_path().exists()
}

pub fn run(ctx: &Context) -> Result<()> {
    if ctx.json {
        return Ok(());
    }

    let dim = Style::new().dim();
    let cyan = Style::new().cyan().bold();
    let bold = Style::new().bold();
    let green = Style::new().green().bold();
    let yellow = Style::new().yellow();

    println!();
    println!(
        "  {}",
        ctx.style(&crate::output::rule("crew briefing", 54), &dim)
    );
    println!();
    println!(
        "  {}",
        ctx.style(
            "Welcome aboard. Let's calibrate the cargo manifest.",
            &bold
        )
    );
    println!(
        "  {}",
        ctx.style(
            "30 seconds — knowing your work makes detection far more accurate.",
            &dim
        )
    );
    println!();
    println!(
        "  {}",
        ctx.style("What kind of work do you do on this ship?", &bold)
    );
    println!();

    for (i, d) in DOMAINS.iter().enumerate() {
        println!(
            "  {}  {:<28}  {}",
            ctx.style(&format!("{:>2}", i + 1), &cyan),
            ctx.style(d.label, &bold),
            ctx.style(d.hint, &dim),
        );
    }

    println!();
    println!(
        "  {}",
        ctx.style(
            "Enter numbers separated by commas (e.g. 1,3) or press Enter to skip:",
            &dim
        )
    );
    print!("  {} ", ctx.style(">", &yellow));
    std::io::stdout().flush()?;

    let term = Term::stdout();
    let line = term.read_line().unwrap_or_default();
    let line = line.trim().to_string();

    let selected: Vec<usize> = line
        .split(',')
        .filter_map(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1 && n <= DOMAINS.len())
        .map(|n| n - 1)
        .collect();

    let mut domains: HashMap<String, Domain> = HashMap::new();
    for (i, d) in DOMAINS.iter().enumerate() {
        domains.insert(
            d.key.to_string(),
            Domain {
                active: selected.contains(&i),
                never_did: false,
                last_active: None,
            },
        );
    }

    let profile = Profile {
        focus: Focus {
            current: None,
            updated: Some(chrono::Utc::now().format("%Y-%m-%d").to_string()),
        },
        domains,
        paths: PathPolicies::default(),
        preferences: Preferences::default(),
    };

    let path = profile::profile_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(&profile)?;
    std::fs::write(&path, content)?;

    println!();
    if selected.is_empty() {
        println!(
            "  {}  {}",
            ctx.style("○", &dim),
            ctx.style(
                "Skipped — run `disk-space profile edit` to personalize later",
                &dim
            )
        );
    } else {
        let labels: Vec<&str> = selected.iter().map(|&i| DOMAINS[i].label).collect();
        println!(
            "  {}  {}",
            ctx.style("✓", &green),
            ctx.style(
                &format!("Profile written  ·  active: {}", labels.join(", ")),
                &bold
            )
        );
    }
    println!();

    Ok(())
}

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
    /// Optional canonical reference (docs / rule source) for this rule. When
    /// absent, the agent surface synthesizes a release-tagged URL into
    /// `rules/builtin.yaml`. Additive + serde-default so legacy rule YAML
    /// (no `reference_url`) still parses.
    #[serde(default)]
    pub reference_url: Option<String>,
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

/// Match a rule glob against a path the way every rule is written: `*` and `?`
/// stay inside one path component, `**` spans directories. With the glob
/// crate's defaults a trailing `/*` would match every file beneath the
/// directory and bloat the survey cache with the whole tree.
pub fn glob_matches(pat: &glob::Pattern, path: &std::path::Path) -> bool {
    pat.matches_path_with(
        path,
        glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: false,
        },
    )
}

pub fn load_builtin() -> Result<Vec<Rule>> {
    let rules: Vec<Rule> = serde_yaml::from_str(BUILTIN_RULES_YAML)?;
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_parse() {
        let rules = load_builtin().expect("builtin rules parse");
        assert!(!rules.is_empty(), "builtin.yaml has rules");
    }

    /// Agent worktree rules match one worktree at a time: the directory one
    /// level below the worktrees folder, never the folder itself or its contents.
    #[test]
    fn agent_worktree_rules_match_one_level_below_the_worktrees_folder() {
        let rules = load_builtin().unwrap();
        let home = std::path::Path::new("/home/u");
        for (id, hit, misses) in [
            (
                "repo-dot-worktrees",
                "/home/u/code/repo/.worktrees/feat-x",
                [
                    "/home/u/code/repo/.worktrees",
                    "/home/u/code/repo/.worktrees/feat-x/src",
                ],
            ),
            (
                "claude-code-worktrees",
                "/home/u/code/repo/.claude/worktrees/feat-x",
                [
                    "/home/u/code/repo/.claude/worktrees",
                    "/home/u/code/repo/.claude/worktrees/feat-x/src",
                ],
            ),
            (
                "hermes-worktrees",
                "/home/u/.hermes/profiles/nagatha/worktrees/feat-x",
                [
                    "/home/u/.hermes/profiles/nagatha/worktrees",
                    "/home/u/.hermes/profiles/nagatha/worktrees/feat-x/src",
                ],
            ),
        ] {
            let rule = rules
                .iter()
                .find(|r| r.id == id)
                .unwrap_or_else(|| panic!("rule {} exists", id));
            let pat =
                glob::Pattern::new(&crate::core::scanner::expand_home(&rule.path_pattern, home))
                    .unwrap();
            let path = std::path::Path::new;
            assert!(glob_matches(&pat, path(hit)), "{} matches {}", id, hit);
            for miss in misses {
                assert!(
                    !glob_matches(&pat, path(miss)),
                    "{} must not match {}",
                    id,
                    miss
                );
            }
            let cons = rule.consequences.as_ref().expect("consequences stated");
            assert_eq!(cons.recovery, "irreversible", "{}", id);
        }
    }

    /// Rule globs match path components: `*` never crosses a `/`, so a rule
    /// ending in `/*` names the directory one level down, not every file
    /// beneath it. `**` still spans directories.
    #[test]
    fn single_star_never_crosses_a_path_separator() {
        let pat = glob::Pattern::new("**/stale/*").unwrap();
        assert!(glob_matches(&pat, std::path::Path::new("/a/b/stale/x")));
        assert!(!glob_matches(&pat, std::path::Path::new("/a/b/stale/x/y")));
        assert!(!glob_matches(&pat, std::path::Path::new("/a/b/stale")));
        let deep = glob::Pattern::new("**/_archive/**/node_modules").unwrap();
        assert!(glob_matches(
            &deep,
            std::path::Path::new("/a/_archive/p/q/node_modules")
        ));
    }

    #[test]
    fn legacy_rule_without_reference_url_parses() {
        // A pre-P2 rule (no `reference_url` key) must still deserialize, with the
        // field defaulting to None. Back-compat for the 10-line YAML contract.
        let yaml = r#"
- id: node_modules
  category: dev-artifact
  path_pattern: "**/node_modules"
  domain: null
  base_confidence: 0.9
  reason: "rebuildable JS deps"
"#;
        let rules: Vec<Rule> = serde_yaml::from_str(yaml).expect("legacy rule parses");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "node_modules");
        assert_eq!(
            rules[0].reference_url, None,
            "missing reference_url defaults to None"
        );
        assert!(rules[0].consequences.is_none());
    }

    #[test]
    fn rule_with_reference_url_parses() {
        let yaml = r#"
- id: foo
  category: app-cache
  path_pattern: "~/Library/Caches/foo"
  domain: null
  base_confidence: 0.8
  reason: "app cache"
  reference_url: "https://docs.example/foo"
"#;
        let rules: Vec<Rule> = serde_yaml::from_str(yaml).expect("rule with url parses");
        assert_eq!(
            rules[0].reference_url.as_deref(),
            Some("https://docs.example/foo")
        );
    }
}

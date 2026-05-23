# Contributing to diskspace

Two easy ways in: **add a new rule**, or **backfill a consequence block** on a rule that doesn't have one yet. Both require zero Rust.

## The easiest contribution: adding a rule

The rule library is the main contribution surface. Adding a rule requires no Rust — just a ~12-line YAML entry in [`rules/builtin.yaml`](rules/builtin.yaml).

```yaml
- id: your-rule-id            # kebab-case, unique
  category: dev-artifact      # dev-artifact | app-cache | download-entropy | vm-disk
  path_pattern: "~/Library/Caches/SomeApp"  # glob, ~ expands to $HOME
  domain: your_domain         # optional: ties rule to a profile domain
  base_confidence: 0.85       # 0.0–1.0, adjusted at runtime by profile + recency
  reason: "One sentence — why is this safe to delete?"
  exclude_if_recent_access_days: 7   # optional: skip if accessed within N days
  exclude_if_recent_modified_days: 7 # optional: skip if modified within N days
  consequences:                      # optional but recommended (M6)
    recovery: rebuild                # auto | redownload | rebuild | recreate | manual | irreversible
    rebuild_seconds: 120             # rough cost-to-recover (omit for manual/irreversible)
    impact: "What the user will notice if they delete this"
    recovery_cmd: "command to recover, if any"
```

### Consequences guidelines

The `consequences` block is what `diskspace check` and agents use to explain what happens if a candidate is deleted. Be honest and specific.

| `recovery` value | Meaning |
|---|---|
| `auto` | Regenerated transparently with no user action |
| `rebuild` | Tool rebuilds on next use (cargo, xcode, npm) — slower next build |
| `redownload` | Requires internet to fetch packages (npm install, brew install) |
| `recreate` | User must run a command (`python -m venv`, etc.) |
| `manual` | User has to remember/recreate state themselves |
| `irreversible` | Data is gone — only use for genuine cleanup of user-deletable cruft |

### Confidence guidelines

| Range | Meaning |
|---|---|
| 0.85–0.95 | Rebuilt automatically, no data loss possible |
| 0.70–0.84 | Rebuilt automatically but may affect performance briefly |
| 0.55–0.69 | Safe in most cases but user should confirm |
| below 0.55 | High risk — prefer not to include |

### Rules we won't accept

- Anything below 0.50 confidence with no domain guard
- Rules that match source code directories (not build artifacts)
- Rules that match `~/Documents`, `~/Desktop` broadly
- Rules without a consequences block for anything below confidence 0.85
- Rules that hide a re-download in the consequences (e.g. Chrome on-device AI models that silently come back unless a setting is changed first — the impact line must call this out)

## Easy second contribution: backfill a consequences block

16 of 91 rules in `rules/builtin.yaml` don't have a `consequences:` block yet. Adding one is a great first PR — pick one of those rules, figure out what actually happens when its target is deleted (try it on a scratch directory), and add the block. Confidence floor for rules without consequences should be ≥ 0.85; everything below needs an impact statement.

## Running tests

```bash
cargo test
cargo clippy -- -D warnings
```

## Code style

- `cargo fmt` before committing
- No unsafe code
- Keep `src/commands/` thin — business logic belongs in `src/core/`
- New commands need both human output and `--json` output

## Opening a PR

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-rule-name`
3. Add your rule to `rules/builtin.yaml`
4. Run `cargo test` and `cargo clippy`
5. Open a PR with a short description of what the rule catches and why it's safe

For code changes, describe what you changed and why in the PR body.

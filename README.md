# diskspace

**Find the dead weight in your cargo hold.**

A personalized disk-cleanup CLI that finds *your* low-hanging fruit, pressure-tests each candidate, and reclaims space safely — with a reversible airlock so nothing is permanently deleted until you say so.

```
   ·      ·    ✦    ·       ·  ✦   ·    ·   ·     ·
        ___ ___ ___ _  __  ___ ___  _   ___ ___
       |   \_ _/ __| |/ / / __| _ \/_\ / __| __|
       | |) | |\__ \ ' <  \__ \  _/ _ \ (__| _|
       |___/___|___/_|\_\ |___/_|/_/ \_\___|___|
   ·    ·  ✦   ·   ·       ·  ·   ✦    ·     ·
```

Spiritual peers: `ripgrep`, `fd`, `dust`, `bat` — tools that do one thing with care.

One binary. No GUI. No cloud. No telemetry. PolyForm Noncommercial 1.0.0.

---

## The problem

Every dev Mac accumulates hundreds of GB in DerivedData, node_modules, Docker volumes, Homebrew caches, and VM disks. Existing tools are either too blunt (nuke everything), too manual (scroll through a list), or too dumb (no awareness of what you actually use). `diskspace` finds *your* candidates — informed by your profile and usage patterns — and only acts on them reversibly.

## Install

```bash
cargo install diskspace
```

Or download the universal Mac binary from the [latest release](https://github.com/tymrtn/diskspace/releases/latest).

## Quick start

```bash
diskspace scan              # survey your cargo hold
diskspace detect            # find dead weight, ranked by yield × confidence
diskspace check <id>        # pressure-test before venting
diskspace airlock <id>      # stage cargo for safe disposal (reversible)
diskspace restore <id>      # bring it back
diskspace reclaim           # jettison high-confidence weight NOW (skips airlock)
diskspace status            # show what's in the airlock
```

## How it works

### 1. Scan

`diskspace scan` walks your filesystem in parallel, annotates entries by category, and caches the result. iCloud Drive evicted files and Dropbox Smart Sync online-only files are skipped — only locally-stored bytes count.

Categories: `dev-artifact`, `app-cache`, `download-entropy`, `vm-disk`.

### 2. Detect

`diskspace detect` applies a declarative rule library to the scan and ranks candidates by `yield × confidence`. Rules cover the highest-value targets out of the box:

| Category | Examples |
|---|---|
| `dev-artifact` | `node_modules`, `.venv`, `DerivedData`, `target/`, Homebrew cache, Docker volumes |
| `app-cache` | `~/Library/Caches`, Slack/Chrome/Spotify caches |
| `download-entropy` | old DMGs, unzipped installers, files untouched > 12 months |
| `vm-disk` | Parallels `.pvm`, Android AVDs |

Each candidate shows its confidence score and the path. Run `--verbose` for the full reasoning trace.

### 3. Check

`diskspace check <id>` pressure-tests a candidate through a chain of validators before you act on it:

1. Re-stat: size hasn't changed since detect
2. Liveness: no open file handles, no writes in last 24h, no owning process running
3. Profile policy: not in your `never_touch` list, domain marked inactive
4. Project recency: no recent git activity in parent project

Outputs a human-readable reasoning trace. Fails loudly if any validator rejects.

### 4. Airlock

`diskspace airlock <id>` moves the candidate to `~/.diskspace/airlock/` with a manifest. Restore is always available for 7 days (configurable). Auto-purge runs after the retention window.

Pass `--immediate` to skip the airlock and permanently delete — only allowed for candidates with confidence ≥ 0.85.

### 5. Reclaim

`diskspace reclaim` is the **"I need space NOW"** path. It picks the top high-confidence candidates (confidence ≥ 0.85), runs pressure tests on each, and permanently deletes the survivors with one confirmation. Reports the actual `df` free-space delta before/after — no fictional accounting.

This is the right call when your disk is critical: airlocking a 5GB folder on the same volume doesn't free space until purge. Reclaim does the real thing for stuff that doesn't need reversibility (npm cache, DerivedData, Homebrew).

## Personalization

`diskspace` gets smarter when it knows what you do. On first run, the **crew briefing** asks what kind of work you do — pick from a menu. The result lands in `~/.diskspace/profile.toml`:

```toml
[focus]
current = "web development, infra"

[domains]
ios_development = { active = false, last_active = "2024-11" }
music_production = { active = false, never_did = true }
docker = { active = true }

[paths]
never_touch = ["~/Documents/**", "~/Clients/**"]
```

Inactive domains boost candidate confidence. `never_touch` paths are hard-blocked from ever being suggested.

```bash
diskspace profile edit   # open in $EDITOR
diskspace profile get    # print current profile
diskspace profile set domains.ios_development.active=false
```

## Agent usage

Every command supports `--json` output and `--yes` to skip confirmations. The same binary humans use is what agents use — no special mode. The first-run wizard is auto-skipped in non-TTY contexts.

```bash
# scan and get top candidates as JSON
diskspace scan && diskspace detect --json --top 10

# pressure-test the top candidate
diskspace check xcode-derived-data-001 --json

# airlock if safe
diskspace airlock xcode-derived-data-001 --yes --json

# or reclaim a batch of high-confidence stuff in one shot
diskspace reclaim --top 20 --yes --json

# update profile with context from your agent
diskspace profile set domains.ios_development.active=false
```

Exit codes: `0` success · `1` no candidates · `2` pressure-test failed · `3` profile policy blocked · `127` unknown error.

## Contributing

The rule library is the main contribution surface. Adding a rule is a 10-line YAML PR — no Rust required.

```yaml
- id: jetbrains-caches
  category: app-cache
  path_pattern: "~/Library/Caches/JetBrains"
  base_confidence: 0.85
  reason: "JetBrains IDE caches — rebuilt on next IDE launch"
```

Rules live in [`rules/builtin.yaml`](rules/builtin.yaml). Open a PR.

## Roadmap

- **M1** — scan, detect, rule library, profile, styled CLI ✓
- **M2** — check (pressure-test pipeline), airlock, restore, purge ✓
- **M3** — profile domain scoring, agent polish ✓
- **M4** — 58-rule library, GitHub Actions CI, CONTRIBUTING.md ✓
- **M5** — first-run wizard, iCloud/Dropbox placeholder handling, reclaim, brand to diskspace ✓
- **M6** — consequence explanations per candidate: recreation effort, rebuild time, performance impact while gone

## License

Free for personal and non-commercial use under the [PolyForm Noncommercial License 1.0.0](LICENSE).

For commercial use, contact [ty@tmrtn.com](mailto:ty@tmrtn.com) to purchase a license.

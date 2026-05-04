# disk-advisor

A personalized disk-cleanup CLI that finds *your* low-hanging fruit, pressure-tests each candidate, and reclaims space safely — with a reversible quarantine so nothing is permanently deleted until you say so.

```
  ·▄▄▄▄  ▪  .▄▄ · ▄ •▄      ▄▄▄· ·▄▄▄▄  ▌ ▐·▪  .▄▄ · ▄▄▄
  ██▪ ██ ██ ▐█ ▀. █▌▄▌▪    ▐█ ▀█ ██▪ ██ ▪█·█▌██ ▐█ ▀. ▀▄ █·
  ▐█· ▐█▌▐█·▄▀▀▀█▄▐▀▀▄·    ▄█▀▀█ ▐█· ▐█▌▐█▐█•▐█·▄▀▀▀█▄▐▀▀▄
  ██. ██ ▐█▌▐█▄▪▐█▐█.█▌    ▐█ ▪▐▌██. ██  ███ ▐█▌▐█▄▪▐█▐█•█▌
  ▀▀▀▀▀• ▀▀▀ ▀▀▀▀ ·▀  ▀     ▀  ▀ ▀▀▀▀▀• . ▀  ▀▀▀ ▀▀▀▀ .▀  ▀
```

Spiritual peers: `ripgrep`, `fd`, `dust`, `bat` — tools that do one thing with care.

One binary. No GUI. No cloud. No telemetry. PolyForm Noncommercial 1.0.0.

---

## The problem

Every dev Mac accumulates hundreds of GB in DerivedData, node_modules, Docker volumes, Homebrew caches, and VM disks. Existing tools are either too blunt (nuke everything), too manual (scroll through a list), or too dumb (no awareness of what you actually use). `disk-advisor` finds *your* candidates — informed by your profile and usage patterns — and only acts on them reversibly.

## Install

```bash
cargo install disk-advisor
```

## Quick start

```bash
disk-advisor scan          # scan your home directory
disk-advisor detect        # find cleanup candidates ranked by yield × confidence
disk-advisor check <id>    # pressure-test a candidate before acting  (M2)
disk-advisor quarantine <id>  # reversibly reclaim space              (M2)
disk-advisor restore <id>  # undo a quarantine                        (M2)
disk-advisor status        # show what's held in quarantine
```

## How it works

### 1. Scan

`disk-advisor scan` walks your filesystem in parallel, annotates entries by category, and caches the result. Subsequent scans are incremental.

Categories: `dev-artifact`, `app-cache`, `download-entropy`, `vm-disk`.

### 2. Detect

`disk-advisor detect` applies a declarative rule library to the scan and ranks candidates by `yield × confidence`. Rules cover the highest-value targets out of the box:

| Category | Examples |
|---|---|
| `dev-artifact` | `node_modules`, `.venv`, `DerivedData`, `target/`, Homebrew cache, Docker volumes |
| `app-cache` | `~/Library/Caches`, Slack/Chrome/Spotify caches |
| `download-entropy` | old DMGs, unzipped installers, files untouched > 12 months |
| `vm-disk` | Parallels `.pvm`, Android AVDs |

Each candidate shows its confidence score and the path. Run `--verbose` for the full reasoning trace.

### 3. Check *(coming in M2)*

`disk-advisor check <id>` pressure-tests a candidate through a chain of validators before you act on it:

1. Re-stat: size hasn't changed since detect
2. Liveness: no open file handles, no writes in last 24h, no owning process running
3. Profile policy: not in your `never_touch` list, domain marked inactive
4. Project recency: no recent git activity in parent project

Outputs a human-readable reasoning trace. Fails loudly if any validator rejects.

### 4. Quarantine *(coming in M2)*

`disk-advisor quarantine <id>` moves the candidate to `~/.disk-advisor/quarantine/` with a manifest. Space is freed immediately. Nothing is permanently deleted — restore is always available for 30 days (configurable).

`disk-advisor purge` is the only irreversible operation, and it's always explicit.

## Personalization

`disk-advisor` gets smarter when it knows what you do. Edit `~/.disk-advisor/profile.toml`:

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
disk-advisor profile edit   # open in $EDITOR
disk-advisor profile get    # print current profile
disk-advisor profile set domains.ios_development.active=false
```

## Agent usage

Every command supports `--json` output and `--yes` to skip confirmations. The same binary humans use is what agents use — no special mode.

```bash
# scan and get top candidates as JSON
disk-advisor scan && disk-advisor detect --json --top 10

# pressure-test the top candidate
disk-advisor check xcode-derived-data-001 --json

# quarantine if safe
disk-advisor quarantine xcode-derived-data-001 --yes --json

# update profile with context from your agent
disk-advisor profile set domains.ios_development.active=false
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

- **M1** — scan, detect, rule library (20 rules), profile, styled CLI ✓
- **M2** — check (pressure-test pipeline), quarantine, restore, purge
- **M3** — profile domain scoring, agent polish
- **M4** — 50+ rules, Homebrew cask, CI
- **M5** — real-machine hardening, open source launch

## License

Free for personal and non-commercial use under the [PolyForm Noncommercial License 1.0.0](LICENSE).

For commercial use, contact [ty@tmrtn.com](mailto:ty@tmrtn.com) to purchase a license.

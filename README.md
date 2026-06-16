# diskspace

**Find the dead weight in your cargo hold.**

A personalized disk-cleanup CLI for macOS that finds *your* low-hanging fruit, pressure-tests each candidate against live disk state, and reclaims space safely — with a reversible airlock so nothing is permanently deleted until you say so.

```
   ·      ·    ✦    ·       ·  ✦   ·    ·   ·     ·
        ___ ___ ___ _  _____ ___  _   ___ ___
       |   \_ _/ __| |/ / __| _ \/_\ / __| __|
       | |) | |\__ \ ' <\__ \  _/ _ \ (__| _|
       |___/___|___/_|\_\___/_|/_/ \_\___|___|
   ·    ·  ✦   ·   ·       ·  ·   ✦    ·     ·
```

Spiritual peers: `ripgrep`, `fd`, `dust`, `bat` — tools that do one thing with care.

One binary. No GUI. No cloud. No telemetry. Code-signed and notarized. PolyForm Noncommercial 1.0.0.

---

## The problem

Every dev Mac accumulates hundreds of GB in DerivedData, node_modules, Docker volumes, Homebrew caches, browser caches, and on-device AI models that silently re-download themselves. Existing tools are either too blunt (nuke everything), too manual (scroll through a list), or too dumb (no awareness of what you actually use).

`diskspace` finds *your* candidates — informed by your profile, usage patterns, and pressure-test results — and only acts on them reversibly. Bytes that come back automatically (caches, build artifacts) get treated differently from bytes that don't (downloads, project state).

## Install

```bash
brew install tymrtn/diskspace/diskspace
```

Or with cargo:

```bash
cargo install diskspace-cli
```

(`diskspace` was squatted on crates.io, so the package name is `diskspace-cli`. The installed binary is still `diskspace`.)

Or download the universal Mac binary from the [latest release](https://github.com/tymrtn/diskspace/releases/latest). The binary is code-signed (Developer ID Application: Xoder PR LLC) and notarized.

## Quick start

```bash
diskspace                         # crew briefing on first run, then welcome
diskspace scan                    # survey your cargo hold
diskspace detect                  # rank candidates by yield × confidence
diskspace explain <path>          # rule match + consequences + recommended command
diskspace check <id>              # pressure-test before venting
diskspace airlock <id>            # stage cargo for safe disposal (reversible)
diskspace restore <id>            # bring it back
diskspace undo                    # reverse the last reversible action
diskspace receipt                 # show the actions ledger
diskspace doctor --need 20G       # emergency one-shot recovery
diskspace hunt                    # find big directories no rule covers
diskspace reclaim                 # jettison high-confidence weight NOW (no airlock)
diskspace purge                   # permanently delete airlock contents
diskspace status                  # show what's in the airlock
diskspace watch install           # background disk-pressure monitor (see below)
```

## How it works

### 1. Scan

`diskspace scan` walks your filesystem in parallel, annotates entries by category, and caches the result. iCloud Drive evicted files and Dropbox Smart Sync online-only files are skipped — only locally-stored bytes count. Sparse files (VM disks like OrbStack's `data.img`) report actual on-disk allocation, not logical size.

Categories: `dev-artifact`, `app-cache`, `download-entropy`, `vm-disk`.

### 2. Detect

`diskspace detect` applies a declarative rule library (91 rules covering the highest-value targets) and ranks candidates by `yield × confidence`. The rule library is YAML — adding new coverage is a 10-line PR, no Rust required.

| Category | Examples |
|---|---|
| `dev-artifact` | `node_modules`, `.venv`, DerivedData, `target/`, Cargo registry, Homebrew cache, Docker volumes, JetBrains caches |
| `app-cache` | `~/Library/Caches`, Slack/Chrome/Spotify caches, Chrome on-device AI models, Hermes/Codex caches |
| `download-entropy` | old DMGs, unzipped installers, files untouched > 12 months, `~/Downloads` screenshots |
| `vm-disk` | Parallels `.pvm`, Android AVDs |

### 3. Explain

`diskspace explain <path>` is the trust front-door. Given any path, it shows:

- The matching rule (or "no rule matches")
- The consequences block: how recovery works, what you lose if you delete, the recovery command if any
- A live pressure-test against the four validators below
- The recommended command (`airlock` vs `reclaim` vs `--immediate`)

Use it to audit individual paths before acting.

### 4. Check (pressure-test)

`diskspace check <id>` runs a candidate through four validators:

1. **Re-stat** — size hasn't changed since detect
2. **Liveness** — no open file handles, no writes in last 24h, owning process not running
3. **Profile policy** — not in your `never_touch` list, domain marked inactive
4. **Project recency** — no recent git activity in the enclosing project

Outputs a human-readable reasoning trace. Fails loudly if any validator rejects. This is the safety boundary — confidence is just a sort key.

### 5. Airlock + restore + purge

`diskspace airlock <id>` moves the candidate to `~/.diskspace/airlock/` with a manifest. Restore is always available; default retention is 7 days. Auto-purge runs after the retention window.

Airlock is **honest about space**: a same-volume move reports "staged for purge — run `diskspace purge` to actually free"; a cross-volume copy+remove reports "freed and held in airlock for restore." No fictional accounting.

`diskspace undo` is a friendlier `restore` — it reads the receipts ledger and reverses the most recent reversible action.

### 6. Reclaim (permanent delete)

`diskspace reclaim` is the **"I need space NOW"** path. Picks the top high-confidence candidates (≥ 0.85), pressure-tests each, and permanently deletes the survivors with one confirmation. Reports actual `df` free-space delta before/after.

For candidates below the 0.85 floor, `airlock --immediate` plus `--unsafe-confidence` plus retyping the candidate id is required. **No global `--force` flag.** The friction is the point — it forces a deliberate per-item decision.

### 7. Doctor (emergency one-shot)

```bash
diskspace doctor --need 20G --yes
```

End-to-end emergency recovery: refreshes the scan, picks the smallest safe set of candidates to hit the target, pressure-tests them, executes, reports `df` delta. Prefers reversible-then-purge when you have headroom; immediate-delete when space is critical.

### 8. Watch (background monitor)

```bash
diskspace watch install      # registers a launchd agent
diskspace watch status       # last check, level, threshold
diskspace watch uninstall    # remove it
```

Checks `df` every 5 minutes. **10% free** fires a soft macOS notification suggesting `diskspace detect`. **5% free** flips to urgent and recommends `doctor`. The agent ships as a Developer-ID-signed `.app` bundle (`DiskspaceWatch.app`) so System Settings → Login Items shows a real icon and identity, not a blank tile.

Notifications are deduped via a state file — you don't get pinged every 5 minutes once you've already been told.

### 9. Receipts ledger

Every action writes a JSON line to `~/.diskspace/history.jsonl`:

```json
{"ts":"...","command":"airlock","rule_id":"chrome-cache","path":"...","size_bytes":114765824,
 "df_before":68115202048,"df_after":68229967872,"actually_freed":114765824,
 "reversible":true,"undo_cmd":"diskspace restore chrome-cache-b9782a5b"}
```

`diskspace receipt` renders this human-readably. Full audit trail of what was done, when, by which rule, with what actual disk impact.

## Personalization

`diskspace` gets smarter when it knows what you do. On first run, the **crew briefing** asks about your work — pick from a menu. The result lands in `~/.diskspace/profile.toml`:

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
diskspace profile edit
diskspace profile get
diskspace profile set domains.ios_development.active=false
```

## Agent usage

Every command supports `--json` output and `--yes` to skip confirmations. **The same binary humans use is what agents use** — no special mode. First-run wizard auto-skips in non-TTY contexts.

`detect --json` returns an object envelope — `{"meta": {...}, "candidates": [...]}` — where `meta` carries `schema_version`, `immediate_threshold`, and the full-set `total_reclaimable_bytes`/`total_candidates`. Iterate `.candidates[]` (each candidate adds `recommended_command` + `recovery_class`); the bare-array form from earlier builds is gone (see the CHANGELOG schema note).

```bash
# scan and get top candidates as JSON (iterate .candidates[])
diskspace scan && diskspace detect --json --top 10

# pressure-test the top candidate
diskspace check xcode-derived-data-001 --json

# airlock if safe
diskspace airlock xcode-derived-data-001 --yes --json

# or one-shot emergency
diskspace doctor --need 30G --yes --json

# explain a path
diskspace explain ~/Library/Caches/Google/Chrome --json

# update profile
diskspace profile set domains.ios_development.active=false
```

Exit codes: `0` success · `1` no candidates · `2` pressure-test failed · `3` profile policy blocked · `127` unknown error.

## Claude Code plugin

This repo doubles as a [Claude Code](https://docs.claude.com/en/docs/claude-code) plugin marketplace. Install the skill so an agent reaches for `diskspace` the moment a build dies with *"No space left on device"* — safely, because the airlock + pressure-test make it the rare cleanup tool that's safe to auto-invoke:

```
/plugin marketplace add tymrtn/diskspace
/plugin install diskspace@diskspace
```

The plugin ships one skill (a deterministic `doctor`/exit-code runbook over this CLI); it expects the `diskspace` binary on `PATH` (see [Install](#install)). Manifests live in [`.claude-plugin/`](.claude-plugin/marketplace.json) and [`plugins/diskspace/`](plugins/diskspace).

## Trust model

Diskspace's whole pitch is that you can trust it without watching it. The structural pieces:

- **Pressure tests are the safety boundary, not confidence.** Confidence is a sort key. Pressure-test failure blocks the action regardless of score.
- **Reversibility by default.** `airlock` is the recommended path for everything below 0.85 confidence. Reclaim and `--immediate` require typed consent above their thresholds.
- **No global `--force` flag.** Bypassing safety must be per-target, requires retyping the candidate id verbatim.
- **Honest accounting.** Same-volume moves don't pretend to free space.
- **Receipts ledger.** Every action is recorded with full provenance and actual `df` deltas.
- **Consequence metadata.** Each rule declares what happens when you delete: how recovery works, what breaks, what command brings it back. Many rules also warn about gotchas — e.g., deleting Chrome's on-device AI model store re-downloads unless you first disable on-device AI in Settings.

No telemetry. No network calls except the optional notarization-stapling check on first launch. Everything is `$HOME`-scoped — never asks for sudo.

## Contributing

The rule library is the main contribution surface. Adding a rule is a 10-line YAML PR.

```yaml
- id: jetbrains-caches
  category: app-cache
  path_pattern: "~/Library/Caches/JetBrains"
  base_confidence: 0.85
  reason: "JetBrains IDE caches — rebuilt on next IDE launch"
  consequences:
    recovery: rebuild
    rebuild_seconds: 30
    impact: "First indexer pass per project will take a bit longer"
```

Rules live in [`rules/builtin.yaml`](rules/builtin.yaml). Currently **75 of 91** rules have consequence metadata — backfilling the remaining 16 is a great first PR. See [CONTRIBUTING.md](CONTRIBUTING.md) for confidence guidelines and review criteria.

## Roadmap

- **M1–M5** — scan, detect, rule library, profile, pressure-test, airlock, reclaim, first-run wizard ✓
- **M6** — consequence metadata per rule ✓
- **M7** — distribution (crates.io, Homebrew tap, notarization) ✓
- **M8** — scan.json cache fix, sparse-file accounting, expanded rule library ✓
- **M9** — typed-consent override, honest accounting, `explain`, `doctor`, receipts ledger ✓
- **M10** — `undo`, `watch` daemon with launchd + `.app` bundle, consequence backfill (32 rules), Chromium on-device AI model rules ✓
- **M11** — Time Machine local snapshots, per-version Xcode, Dropbox/iCloud advisor (suggestion-only), domain-specialized profiles

See the [latest release](https://github.com/tymrtn/diskspace/releases/latest) for what's new, and [CHANGELOG.md](https://github.com/tymrtn/diskspace/releases) (releases page) for full history.

## License

Free for personal and non-commercial use under the [PolyForm Noncommercial License 1.0.0](LICENSE).

For commercial use, contact [ty@tmrtn.com](mailto:ty@tmrtn.com) to purchase a license.

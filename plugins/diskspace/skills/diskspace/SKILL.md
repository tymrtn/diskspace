---
name: diskspace
description: Recover disk space on macOS safely and reversibly. USE THIS the moment a build, install, test, or command fails with "No space left on device" / ENOSPC / errno 28 / "write error - disk full" / "could not write to disk", a failed Docker, cargo, npm, pip, or xcodebuild run that ran out of space, or the macOS "startup disk almost full" warning. Also use when asked to free up space, reclaim disk, or clean caches, node_modules, DerivedData, Docker, Xcode, Homebrew, or large old downloads. The diskspace CLI is safe to auto-invoke (reversible airlock + 4-validator pressure-test) where a blunt rm -rf would not be.
allowed-tools: Bash
---

# diskspace — safe, reversible disk recovery on macOS

If you reached this skill because a command just failed on disk space, the fast path is one call:

```bash
diskspace doctor --need 20G --yes --json   # frees ~20 GB reversibly, then read actually_freed
```

Then re-run the command that failed. The rest of this skill is the safe, deliberate workflow and the rules that make auto-invocation safe.

## Trust model (read before acting)

- **The pressure-test is the safety boundary, not the confidence score.** If it fails (exit `2`), STOP. Do not retry with force.
- **Airlock is the default.** Everything goes to a reversible holding area first; `restore`/`undo` always work. Permanent deletion is a separate, deliberate step.
- **There is no `--force`.** Bypassing safety is per-item and requires retyping the candidate id — which `--yes` cannot satisfy. Don't try to defeat it.
- **`$HOME`-scoped, never sudo, no telemetry.**

Binary name is `diskspace`. Every command supports `--json` (machine output) and `--yes`/`-y` (skip prompts).

## Install if missing

```bash
command -v diskspace >/dev/null || brew install tymrtn/diskspace/diskspace
# or, if brew is unavailable:
command -v diskspace >/dev/null || cargo install diskspace-cli   # installs the `diskspace` binary
```

## Golden path (headless / agent-safe)

The recommended sequence. Reversible at every step.

```bash
diskspace scan                          # snapshot the filesystem -> ~/.diskspace/scan.json
diskspace detect --json --top 10        # rank candidates (yield × confidence); note the candidate ids
diskspace check <candidate_id> --json   # pressure-test ONE candidate before touching it
diskspace airlock <candidate_id> --yes --json   # reversibly stage it (NOT a permanent delete)
```

Reverse anything:

```bash
diskspace restore <candidate_id>        # bring one back
diskspace undo                          # reverse the most recent reversible action
diskspace status                        # what's in the airlock + when it auto-purges
diskspace receipt --last 20             # full action ledger with real df deltas
```

## Emergency one-shot

When the disk is critically full and you just need space back:

```bash
diskspace doctor --need 20G --yes --json
```

`doctor` runs scan → detect → pressure-test → execute to hit the target. It prefers reversible-then-purge when there's headroom and only escalates to immediate deletion when space is critical. `--need` is optional (defaults to the pressure threshold + 1 GB). Read the JSON `actually_freed` (the real `df` delta), not the requested target.

Note: a same-volume airlock is a rename — it **stages** bytes but doesn't free them until `purge`. On a critically-full single-volume disk, run `diskspace purge --older-than 0 --yes` after airlocking (or let `doctor` go immediate) to actually reclaim space.

## Decision guide

| Situation | Command |
|-----------|---------|
| Build/CI just died on ENOSPC; need space now | `diskspace doctor --need 20G --yes --json` |
| Routine, careful cleanup | `scan` → `detect` → `check <id>` → `airlock <id>` |
| "Is it safe to delete this path?" | `diskspace explain <path>` (rule + consequences + live test + recommended cmd) |
| Disk full but nothing matches a rule | `diskspace hunt --top 15` (largest uncovered dirs) |
| Permanently free top high-confidence items | `diskspace reclaim` (see caveats) |
| Free the airlock for real | `diskspace purge` (irreversible) |

Note: `check` takes a **candidate id** (from `detect`); `explain` takes a **path**. `airlock <target>` also accepts a raw path if you skip `detect`.

## Exit codes — react correctly

| Code | Meaning | What to do |
|------|---------|-----------|
| `0` | success | proceed; report `actually_freed` from JSON, then retry the failed command |
| `1` | no candidates found | nothing to reclaim here; consider `hunt` or report "nothing safe to free" |
| `2` | pressure-test failed (safety boundary) | **STOP.** A path is live/in-use/protected. Do NOT force it. Pick a different candidate or surface to the human. |
| `3` | profile policy blocked | the path is in `never_touch` / an active domain — respect it; do not override |
| `127` | unknown error | inspect stderr; do not retry blindly |

## Safety rules — CRITICAL

- **Never run `reclaim`, `airlock --immediate`, or `purge` without explicit human go-ahead.** These either permanently delete (`reclaim`, `purge`) or skip the reversible airlock (`--immediate`). Prefer plain `airlock`, or `doctor` (which defaults to reversible when there's headroom).
- `reclaim` permanently deletes the top high-confidence (≥0.85) candidates after pressure-testing — there is no airlock to restore from. `reclaim --top N`; `reclaim --unsafe-confidence` drops the 0.85 floor and forces per-item id confirmation (can't be `--yes`-ed).
- `purge` permanently removes airlocked items. Use `purge --dry-run` first; never purge space the user may still want back.
- `doctor` may execute cleanup to hit its target — fine for unattended recovery on your own machine; announce the plan before running it on shared or precious data.
- A `2` from the pressure-test is a hard stop, not a hint to escalate. There is no global force flag by design.
- Honor `never_touch` (exit `3`). Don't edit the profile to unblock a path unless the human asks.

## Background monitor (human opt-in)

```bash
diskspace watch install     # launchd agent; soft notify at 10% free, urgent at 5%
diskspace watch status      # last check, level, threshold
diskspace watch uninstall
```

## What NOT to do

- Don't hand-`rm -rf` caches/`node_modules`/`DerivedData` when `diskspace` is available — you lose the pressure-test, the consequence metadata, and reversibility.
- Don't bypass or retry past a pressure-test failure.
- Don't `reclaim`/`purge` to win back a few bytes the user might need; airlock (or `doctor` with headroom) is nearly always the right call.
- Don't assume a command exists beyond the list above (`scan`, `detect`, `check`, `explain`, `airlock`, `restore`, `purge`, `reclaim`, `hunt`, `receipt`, `doctor`, `undo`, `status`, `watch`, `profile`). Run `diskspace --help` if unsure.

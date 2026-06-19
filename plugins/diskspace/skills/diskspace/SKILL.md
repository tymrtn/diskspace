---
name: diskspace
description: Safely find and reclaim disk space on macOS with the diskspace CLI (reversible airlock + 4-validator pressure-test). Use when a build, install, or command fails with "No space left on device" / ENOSPC / errno 28 / "disk full", when the startup disk is full or "almost full", or when asked to free up space or clean caches, node_modules, DerivedData, Docker, Xcode, Homebrew, or large old downloads. Triggers - disk full, out of disk space, no space left on device, free up space, reclaim disk, clean up mac storage, low disk.
allowed-tools: Bash
---

# diskspace — a disk-recovery capability for agents

`diskspace` is not an `rm` wrapper. It is a **capability upgrade**: it turns "is it safe to delete this?" into a machine-readable contract. Every candidate carries a *consequence contract* (what breaks, how to get it back, how long that takes) and *advisory metrics* (burn rate, days-to-full, regrowth). The same binary humans use is the one agents use — every command supports `--json` and `--yes`/`-y`.

The trust model — internalize it before acting:

- **The pressure-test is the boundary, not the confidence score.** If it fails (exit `2`), STOP. Never override it.
- **Metrics never override safety.** They inform *which* candidate and *whether to ask a human*. They never widen the gate, reorder by themselves, or flip `safe`. They are best-effort and may be `null` until history accumulates — do NOT treat them as authoritative.
- **Airlock is the default.** Reversible holding area first; `restore`/`undo` always work. Permanent deletion is a separate, deliberate step.
- **Autonomous deletion needs a signed grant.** `guard`/`plan`/`apply` all route through the SAME pressure-test gate (the hard boundary). In the default (non-`actuation`) build there is no autonomous deletion: they fall back to the human-consent path. In an `actuation` build, a non-interactive (`--json`/`--yes`) `doctor`/`apply` — and `guard` always, since it is inherently headless — REFUSES with `{"error":"no_grant"}` (exit `4`) unless a valid, signed grant token is present. A grant can only ever SHRINK what acts; it can never make an unsafe candidate actionable and never overrides `never_touch`.

```
┌─ AGENT CONSTRAINTS (non-negotiable) ─────────────────────────────────┐
│ • Never sudo. $HOME-scoped only. No network calls.                   │
│ • The pressure-test is the boundary. Exit 2 = STOP. Never override.  │
│ • There is NO --force. Drift / unsafe = hard refusal, by design.     │
│ • Metrics are advisory. They never override the safety gate.         │
│ • Autonomous deletion needs a SIGNED grant (actuation builds). With  │
│   none, guard / non-interactive doctor & apply refuse (exit 4). A    │
│   grant only SHRINKS what acts — never overrides the gate/never_touch.│
└──────────────────────────────────────────────────────────────────────┘
```

## Install if missing

```bash
command -v diskspace >/dev/null || brew install tymrtn/diskspace/diskspace
# or, if brew is unavailable:
command -v diskspace >/dev/null || cargo install diskspace-cli   # installs the `diskspace` binary
```

## The agent-facing JSON contract

`detect`, `check`, and `inspect` (alias: `explain`) enrich every item with three additive blocks (all back-compat; absent on legacy data). `survey --json` attaches one whole-`$HOME` `metrics` block.

- **`consequence_contract`** — `{ recovery_class, recovery_cost_seconds, impact, recovery_cmd, reference_url }`
  - `recovery_class` ∈ `auto | redownload | rebuild | recreate | manual | irreversible`
  - `recovery_cost_seconds` — rough rebuild time (may be absent)
  - `impact` — one-line human-readable consequence
  - `recovery_cmd` — exact command to get it back, if any
  - `reference_url` — release-tagged deep link into the ruleset
- **`metrics`** — `{ burn_rate_bytes_per_day, days_to_full, regrowth_slope_bytes_per_day, staleness_days, metric_confidence }`. Every field is soft: `null` means "not enough data yet", never "zero". `burn_rate > 0` = filling; `days_to_full` is emitted only while filling. `metric_confidence` ∈ `0.0..1.0`.
- **`reference_url`** — canonical link for the matching rule.

Example `diskspace check <id> --json` (trimmed):

```json
{
  "candidate_id": "node_modules-1a2b3c",
  "safe": true,
  "confidence": 0.92,
  "consequence_contract": {
    "recovery_class": "redownload",
    "recovery_cost_seconds": 120,
    "impact": "Reinstalled on next `npm install`",
    "recovery_cmd": "npm install",
    "reference_url": "https://github.com/tymrtn/diskspace/blob/v0.8.0/rules/builtin.yaml#node_modules"
  },
  "metrics": {
    "burn_rate_bytes_per_day": 3221225472,
    "days_to_full": 6,
    "regrowth_slope_bytes_per_day": null,
    "staleness_days": 41,
    "metric_confidence": 0.66
  },
  "reference_url": "https://github.com/tymrtn/diskspace/blob/v0.8.0/rules/builtin.yaml#node_modules"
}
```

## Agent decision model

Read the contract, then decide:

1. **`safe == false` / exit `2`** → **STOP.** The path is live, in-use, or policy-blocked. Never retry with force. Pick another candidate or surface to the human.
2. **`metric_confidence < 0.5`** → the metrics are too thin to trust; **fall back to rule `confidence`** for ranking. Do not present a low-confidence `days_to_full` as fact.
3. **`recovery_cost_seconds > 300`** (rebuild costs more than ~5 min) → **surface to a human** before reclaiming; this is expensive to undo even if reversible.
4. **`recovery_class == "irreversible"` or `"manual"`** → prefer `airlock`; never `reclaim`/`purge` without explicit human go-ahead.
5. Otherwise rank by rule `confidence × size`, prefer airlock, and report `actually_freed` (the real `df` delta) — not the requested target.

## Golden path (headless / agent-safe)

```bash
diskspace survey                        # snapshot -> ~/.diskspace/scan.json (+ whole-$HOME metrics in --json); was `scan`
diskspace detect --json --top 10        # ranked candidates w/ consequence_contract + metrics; note ids
diskspace check <candidate_id> --json   # pressure-test ONE candidate; read its contract before acting
diskspace airlock <candidate_id> --yes --json   # reversibly stage it (NOT a permanent delete)
```

Reverse anything: `diskspace restore <id>` · `diskspace undo` · `diskspace status` · `diskspace receipt --last 20`.

## guard / plan / apply (shipped)

Three agent primitives. **All three route through the SAME pressure-test gate. There is no `--force`.**

### `guard` — ENOSPC self-heal wrapper

```bash
diskspace guard --exec "cargo build --release" --need 10G   # --need optional, default 5G
```

Runs the command **via ARGV** (tokenized with shell-words — NEVER `sh -c`, so no shell-injection surface). If it fails with ENOSPC (exit 28, or "No space left on device" / "errno 28" / "enospc" on stderr), `guard` frees space through the existing `doctor` recovery path (same pressure-test) and re-runs the command **exactly once**. No retry loop. It emits one JSON trace on stdout always: `{cmd, first_exit, enospc_detected, freed_bytes, second_exit, success, re_execed}` (plus an additive `error` field on a refusal). If nothing could be freed, it does NOT re-run — it reports the original failure honestly.

In an **`actuation` build**, `guard` is inherently headless, so it **requires a signed grant** before freeing anything: with no valid grant on disk (and no `--grant`), the recovery refuses and the trace carries `"error":"no_grant"` (non-zero exit) — nothing is deleted or airlocked. In the default build, `guard` has no grant gate and follows the existing path.

### `plan` → hash, then `apply <hash>` — TOCTOU-safe two-phase recovery

```bash
diskspace plan --need 20G --json        # SELECTION ONLY: survey→pressure-test→pick. Touches nothing.
# → prints plan_hash + "apply_cmd": "diskspace apply <hash>"
diskspace apply <hash> --json           # RE-VALIDATES live, then acts
```

- `plan` does selection only and **never touches the filesystem** — no airlock, no delete. It content-addresses the *intended actions* `(candidate_id, path, size_bytes, mode)` into `plan_hash` and persists the plan under `~/.diskspace/plans/`.
- `apply` is **TOCTOU-safe**: before acting it (1) recomputes the hash and refuses on mismatch (tampered/stale plan), (2) re-stats every target and refuses if it vanished or drifted >10% in size, and (3) **RE-RUNS the live pressure-test** — it NEVER trusts the `safe` captured at plan time. Any single drift refuses the WHOLE apply (all-or-nothing). A now-unsafe gate exits `2`; other refusals exit `1`. Only after every step clears does it execute via the same airlock/immediate path with history receipts.

## grant — signed capability tokens (autonomous actuation)

`diskspace grant …` exists in **every** build (it is not feature-gated). It mints and inspects the ed25519-signed grant token that authorizes autonomous deletion in an `actuation` build. The threat model is "cooperating-agent capability": the grant does not defend against a malicious local process (which could `rm -rf` without diskspace), it (1) stops a cooperating agent from minting itself broader authority — the PRIVATE key lives OFF-BOX with the user; the actor box holds only the public key and merely VERIFIES — and (2) bounds an honest-but-buggy agent to a category / recovery-class ceiling / `max_bytes` / `min_confidence` floor / `path_scope` / expiry, with a tamper-evident audit trail.

```bash
# OFF-BOX (on the user's Mac, where the private key lives):
diskspace grant keygen --out ~/secret/grant.key          # writes private key (0600) + ~/.diskspace/grant.pub
diskspace grant issue \
  --category build-recovery --recovery-ceiling rebuild \
  --max-bytes 20G --min-confidence 0.85 \
  --path-scope '~/Library/Caches/**' --expires-in 2h \
  --priv-key ~/secret/grant.key                          # writes signed ~/.diskspace/grant.json

# ON THE ACTOR BOX (verifies only — never has the private key):
diskspace grant show --json                              # {present, valid, grant} or {present:false}
```

- `--min-confidence` MUST be finite and in `0.0..=1.0`; a NaN/out-of-range floor is rejected at issue time (a NaN floor would otherwise silently void the floor).
- The grant is consulted **only after** the pressure-test passes. It can relax the confidence floor / substitute for typed-id consent, but it can **never** make an unsafe candidate actionable and **never** overrides `never_touch`. A denied step is skipped, not forced.
- A present-but-invalid grant is a HARD error (`{"error":"invalid_grant"}`, exit `2`) — it never silently degrades to "no grant / human consent".

## Emergency one-shot

```bash
diskspace doctor --need 20G --yes --json
```

`doctor` runs survey → detect → pressure-test → execute to hit the target (reversible-then-purge when there's headroom, immediate only when critical). `--need` defaults to the pressure threshold + 1 GB. Read JSON `actually_freed`, not the requested target.

## Decision guide

| Situation | Command |
|-----------|---------|
| Build died on ENOSPC; want auto-recover + retry | `diskspace guard --exec "<cmd>" --need 20G` |
| Build died; want a reviewable plan before acting | `diskspace plan --need 20G` → review → `diskspace apply <hash>` |
| Need space NOW, no review | `diskspace doctor --need 20G --yes --json` |
| Routine, careful cleanup | `survey` → `detect` → `check <id>` → `airlock <id>` |
| "Is it safe to delete this path?" | `diskspace inspect <path> --json` (alias: `explain`) (rule + consequence_contract + metrics + live test + recommended cmd) |
| Disk full but nothing matches a rule | `diskspace scan --top 15` (alias: `hunt`) (sweep for largest uncovered dirs; needs a prior `survey`) |
| Free the airlock for real | `diskspace purge` (irreversible) |

Note: `check` and `apply` take ids/hashes; `inspect` (alias: `explain`) takes a **path**. `airlock <target>` also accepts a raw path.

## Exit codes — react correctly

| Code | Meaning | What to do |
|------|---------|-----------|
| `0` | success | proceed; report `actually_freed` from JSON |
| `1` | no candidates / plan refused (stale, missing, size drift, parse) | nothing safe here, or the plan no longer matches disk — re-`plan`; consider `scan` (alias: `hunt`) |
| `2` | **pressure-test failed (the boundary)**, OR a present-but-invalid grant (`{"error":"invalid_grant"}`) | **STOP.** Path is live/in-use/protected, or `apply` found it now-unsafe, or the grant signature/expiry/schema failed. Do NOT force. Re-issue a valid grant or pick another candidate. |
| `3` | profile policy blocked, OR grant denied this item (`{"error":"grant_denied"}` on `airlock`/`reclaim`) | path is in `never_touch` / an active domain, or it fell outside the grant's ceiling/floor/budget/scope — respect it; do not override |
| `4` | **no grant** under `actuation` (`{"error":"no_grant"}`) | a non-interactive `doctor`/`apply` or any `guard` needs a signed grant — issue one with `diskspace grant issue …`, or run interactively for human consent |
| `127` | unknown error | inspect stderr; do not retry blindly |

## Safety rules — CRITICAL

- **Never run `reclaim`, `airlock --immediate`, or `purge` without explicit human go-ahead.** These permanently delete (`reclaim`, `purge`) or skip the reversible airlock (`--immediate`). Prefer plain `airlock`.
- `reclaim` permanently deletes the top high-confidence (≥0.85) candidates after pressure-testing — no airlock to restore from. `reclaim --unsafe-confidence` drops the floor and forces per-item id confirmation (can't be `--yes`-ed).
- A `2` from the pressure-test (or from `apply` re-validation) is a hard stop, not a hint to escalate. There is no global force flag by design.
- Honor `never_touch` (exit `3`). Don't edit the profile to unblock a path unless the human asks.
- Treat `metrics` as advice. A scary `days_to_full` is a reason to *prioritize* and possibly *ask a human* — never a reason to bypass the gate.

## Personalization (optional)

```bash
diskspace profile get
diskspace profile set domains.ios_development.active=false   # boosts confidence of inactive-domain artifacts
diskspace profile edit                                       # edit lists like paths.never_touch in $EDITOR
```

## Background monitor (human opt-in)

```bash
diskspace watch install     # launchd agent; soft notify at 10% free, urgent at 5%; also feeds metrics history
diskspace watch status
diskspace watch uninstall
```

## What NOT to do

- Don't hand-`rm -rf` caches/`node_modules`/`DerivedData` when `diskspace` is available — you lose the pressure-test, the consequence contract, and reversibility.
- Don't bypass or retry past a pressure-test failure, and don't `--force` (it doesn't exist).
- Don't trust `metrics` as authoritative — `metric_confidence < 0.5` means fall back to rule confidence.
- Don't try to mint a grant on the actor box — `grant keygen`/`issue` need the PRIVATE key, which lives OFF-BOX with the user. The actor only ever VERIFIES (`grant show`). A grant never overrides the pressure-test or `never_touch`; it only narrows what may act.
- Don't assume a command exists beyond: `survey` (was `scan`), `detect`, `check`, `inspect` (alias `explain`), `airlock`, `restore`, `purge`, `reclaim`, `scan` (the uncharted-dir sweep, alias `hunt`), `receipt`, `doctor`, `guard`, `plan`, `apply`, `grant`, `undo`, `status`, `watch`, `profile`. Note `scan` now means the uncharted-dir sweep (was `hunt`); the full categorized walk is `survey`. Run `diskspace --help` if unsure.

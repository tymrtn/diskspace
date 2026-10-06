# Changelog

All notable changes to `diskspace` are recorded here. Dates are `YYYY-MM-DD`.

## [Unreleased]

### Changed (watch auto-reclaim: one gated, reversible path)

- **Every unattended delete now goes through `core::autonomy::reclaim`.** The
  watch tick used to filter candidates and call `remove_dir_all` inline. It now
  hands them to a single gate: standing opt-in (`preferences.watch_autoreclaim`)
  → regenerable tier (confidence ≥ 0.85, recovery `auto`/`redownload`/`rebuild`)
  → `pressure_test` → the new unattended checks (no symlinked component below
  `$HOME`, strict containment, not cloud-synced, no model weights / patches /
  version-controlled source / credentials inside) → act. Each refused candidate
  is recorded with the stage that refused it. Grants are never consulted on this
  path in any build; in `actuation` builds they only relax bounds elsewhere.
- **Survivors are airlocked, not deleted, unless free space is already below
  `preferences.disk_pressure_threshold_gb`** (same rule `doctor` uses, because a
  same-volume airlock frees nothing until purge). Airlocked items get a
  reversible receipt with `diskspace restore <id>`.
- **Recovery is measured, not estimated.** `watch run --json` `autoreclaim` now
  carries `incident_id`, `disposition` (`"airlock"` / `"delete"` / `null`),
  `items`, `refused`, `bytes_estimated` (scan sizes) and `actually_freed` (df
  delta on `$HOME`'s volume; 0 for a same-volume airlock). The former
  `bytes_freed` field, which reported the scan estimate, is gone. Receipts in
  `history.jsonl` carry `trigger`, `incident_id` and `disposition` in `context`.
- **New `critical` level below 1% free.** `watch run` and `watch status` report
  `level: "critical"` (additive JSON value; consumers matching on
  `ok`/`soft`/`urgent` should add it). Critical re-notifies on every 5-minute
  tick and retries autonomous reclaim after 10 minutes instead of 30.
- **Headroom policy.** New optional `preferences.headroom_gb`. With
  `watch_autoreclaim` on, the monitor also runs its gated reclaim whenever
  MEASURED free space is below that floor, even while the percentage level is
  still `ok`. The burn-rate forecast is still advisory and never triggers it.
- **Incidents.** `watch_state.json` gains an `incidents` list (serde-default,
  capped at 30): one record per trigger kind per UTC day
  (`urgent-20261006`, `critical-…`, `headroom-…`) with passes, items, refused,
  `bytes_estimated` and summed `actually_freed`. Receipts carry the same id.
- Unattended-gate fixes: a trailing `..` no longer slips containment; a `.git`
  FILE (worktree / submodule) counts as source; `.mlpackage` / `.mlmodelc` bundle
  directories count as model weights; an unreadable directory entry refuses
  instead of being skipped; a `$HOME` reached through a symlink is no longer
  refused wholesale.

### Added (instant known-state panel)

- **`diskspace investigate`** and the bare `diskspace` launch now open with
  everything the watcher already knows, drawn from persisted state without a
  scan: live `df`, the watch's last sample (level, % free, age, monitoring
  on/off), the survey's age and scope (STALE past 24h, `unknown` when absent),
  the largest known owners strictly below the survey root, rule-matched bytes as
  an *estimate*, the 7-day free-space sparkline and advisory trend, the latest
  incident with its *measured* recovery, and next actions. `investigate --json`
  emits the same document. Both views are read-only and never create or touch
  `scan.json`.
- `watch status` now shares its launchd check with the panel; the bare launch's
  previous one-line disk/profile/survey status is replaced by the panel.

### Fixed (watch notifications)

- **`watch run` sends a due notification before auto-reclaim and the advisory
  recorder.** Those scans can run well past their 5-second budget on a large
  HOME (`tick_state.json` is parsed outside it), and the alert used to wait
  behind them. Notification bookkeeping is now saved before the scans start, and
  a failed state save is logged instead of ignored. The scans' budget starts
  after notification delivery, so a slow `osascript` cannot use it up.
- **The re-notify clock advances only when the OS accepts the notification.**
  A failed `osascript` launch, nonzero exit, or hang (killed after 10s) is logged
  to stderr, leaves `last_notified_ts` / `last_notified_pct` /
  `last_trend_notified_ts` untouched, and retries on the next tick. A failed
  recovery ping is not retried: recovery is still announced once. `osascript`
  stderr is drained while it runs and collected only within the 10s limit. New
  serde-default state field `notify_retry_pending`.
- **`watch run --json`:** `notified` and `trend_notified` keep their names and
  boolean type, but now mean "submitted to the OS notifier this tick" instead of
  "a notification was due". New `notification` / `trend_notification` fields are
  `null` when nothing was due, otherwise `{"status": "submitted"}`,
  `{"status": "failed", "error": "..."}`, or `{"status": "unsupported"}`
  (non-macOS builds, which now report `notified: false`). `submitted` means
  `osascript` exited 0; macOS offers no receipt that a banner was displayed.

### Changed (agent-facing — `detect --json` schema)

- **`diskspace detect --json` now emits an OBJECT envelope, not a bare array.**
  The root is `{"meta": {...}, "candidates": [...]}` where `meta` carries
  `schema_version` (currently `2`), `immediate_threshold`, and the FULL-set
  `total_reclaimable_bytes` / `total_candidates`. The pre-P2 form was a bare
  JSON array of candidates. **Migration:** a consumer that did `jq '.[]'` or
  deserialized the root as `Vec<Candidate>` must switch to `jq '.candidates[]'`
  (or read `.meta` first and branch on `meta.schema_version`). The PER-CANDIDATE
  keys remain additive — every legacy candidate field is untouched, and each
  candidate gains `recommended_command` and `recovery_class`.
- **`recommended_command` (in both `detect --json` and `explain --json`) now
  honors a candidate's EFFECTIVE confidence.** A recency-touched regenerable
  candidate whose confidence was decayed below the 0.85 immediate threshold is
  recommended via the reversible airlock, never `--immediate` — so the
  serialized `confidence` and `recommended_command` can no longer contradict
  each other.

### Added

- **`diskspace grant keygen | issue | show`** — ed25519-signed capability tokens
  that bound an autonomous actor. These subcommands ship in **every** build (they
  are NOT gated behind the `actuation` feature): security comes from WHERE the
  private key lives (off-box, with the user), not from a build flag. `keygen`/
  `issue` use the PRIVATE key and run off-box; `show` only verifies the public
  grant and is safe on the actor box.
  - A grant carries a category, a recovery-class ceiling, a `max_bytes` budget, a
    `min_confidence` floor, an optional `path_scope` glob, and an expiry.
  - `--min-confidence` is rejected at issue time unless it is finite and in
    `0.0..=1.0` (a NaN floor would otherwise silently void the floor).
  - The audit log (`~/.diskspace/grants.jsonl`) records a per-action fingerprint
    derived from the grant signature — binding, never leaking the signature.

### Changed (behavior change — actuation builds only)

- In a build with the **`actuation`** feature, a non-interactive (`--json`/`--yes`)
  `doctor` or `apply` that will MUTATE the filesystem now **REFUSES without a valid
  signed grant**, emitting `{"error":"no_grant"}` and exiting `4` before doing any
  work. `guard` is inherently headless, so it requires a grant **unconditionally**
  (its trace carries `"error":"no_grant"` and it mutates nothing without one).
  - The grant is consulted ONLY AFTER the pressure-test passes. It can relax the
    confidence floor / substitute for typed-id consent, but it can NEVER make an
    unsafe candidate actionable and NEVER overrides `never_touch`.
  - **The default build (actuation OFF) is unchanged**: there is no grant gate and
    the existing human-consent flow applies. This is the configuration shipped by
    `cargo install diskspace-cli`, `cargo binstall`, and the Homebrew tap.

### Exit codes (agent-facing)

- `2` — pressure-test failed (the boundary) OR a present-but-invalid grant
  (`{"error":"invalid_grant"}`).
- `3` — profile policy blocked OR grant denied this item
  (`{"error":"grant_denied"}` on `airlock`/`reclaim`).
- `4` — no grant under `actuation` (`{"error":"no_grant"}`).

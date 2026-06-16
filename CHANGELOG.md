# Changelog

All notable changes to `diskspace` are recorded here. Dates are `YYYY-MM-DD`.

## [Unreleased]

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

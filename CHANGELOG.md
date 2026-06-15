# Changelog

All notable changes to `diskspace` are recorded here. Dates are `YYYY-MM-DD`.

## [Unreleased]

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

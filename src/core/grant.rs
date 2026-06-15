//! Capability grants — the ed25519 authority bound for an autonomous actor.
//!
//! # Threat model (locked with the user — this module builds exactly to it)
//!
//! "COOPERATING-AGENT CAPABILITY." A malicious process running as the user can
//! already `rm -rf` anything *without* diskspace, so a grant does NOT try to
//! defend against that. Its three jobs are:
//!
//!   1. **Stop a cooperating agent from ESCALATING its own authority** — minting
//!      itself a broader grant than the user issued. An ed25519 signature, whose
//!      PRIVATE key lives OFF-BOX with the user, prevents this: the actor/agent
//!      holds ONLY the public key and merely VERIFIES. It cannot forge a grant
//!      it would then accept.
//!   2. **Bound an honest-but-buggy agent** to a category, a recovery-class
//!      ceiling, a `max_bytes` spend, a `min_confidence` floor, an optional
//!      `path_scope`, and an expiry.
//!   3. **Leave a tamper-evident audit trail** ([`audit`]).
//!
//! Spend-tracking and expiry are best-effort under this lens (a cooperating
//! agent could choose not to record spend; the point is the *bound*, signed by
//! the user, that an honest agent respects and a buggy one is clamped by).
//!
//! # Where a grant sits relative to the hard gate
//!
//! The pressure-test ([`crate::commands::check::pressure_test`]) is the HARD
//! gate and stays metrics-blind. A grant is consulted ONLY AFTER `pressure_test`
//! returns `safe == true`. A grant can relax the confidence floor / substitute
//! for typed-id consent, but it can NEVER make an unsafe candidate actionable
//! and NEVER override `never_touch` (`policy_check` runs INSIDE `pressure_test`,
//! BEFORE any grant logic). [`allows`] is a PURE function — it decides only
//! whether an already-`safe` candidate falls within the issued bound.
//!
//! # Why two key anchors
//!
//! [`validate`] verifies against a TRUSTED public key resolved in this order:
//!   * **Compile-time pin** (hardened): if the `DISKSPACE_GRANT_PUBKEY`
//!     environment variable is set AT BUILD TIME, that 32-byte hex key is baked
//!     into the binary (via [`option_env!`]) and is the sole trust anchor.
//!     Nothing on disk can change it. Use this when the actor box is
//!     adversarial. NOTE: `option_env!` is resolved by the compiler, so pinning
//!     a (different) key only takes effect on an actual RECOMPILE of this crate
//!     — do a clean build (`cargo clean -p diskspace-cli` or touch a source
//!     file) when setting/changing the pin so Cargo doesn't serve a cached
//!     binary built without it.
//!   * **File anchor** (default): `~/.diskspace/grant.pub`. This assumes a
//!     COOPERATING agent per the threat model — the agent could overwrite
//!     `grant.pub`, but a cooperating agent will not, and the off-box private
//!     key is still required to mint a grant the verifier accepts.
//!
//! # On-disk layout (all under `~/.diskspace`, never sudo, HOME-scoped)
//!   * `grant.json`  — the issued, signed [`Grant`] (or absent → human consent).
//!   * `grant.pub`   — the trusted public key (hex), unless compile-pinned.
//!   * `grants.jsonl`— the tamper-evident audit log (fs4 LOCKED append).
#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use fs4::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::core::rules::Consequences;
use crate::profile;

/// Schema version stamped on every [`Grant`]. Bump on incompatible shape change;
/// [`validate`] rejects any grant whose `schema_version` it does not understand.
pub const GRANT_SCHEMA: u32 = 1;

// Build-time public-key pin. Resolved by `build.rs`-less `env!`-style lookup at
// COMPILE time via `option_env!`, so when set it is baked into the binary and
// cannot be changed on disk (the hardened anchor).
const COMPILE_PUBKEY: Option<&str> = option_env!("DISKSPACE_GRANT_PUBKEY");

// ---------------------------------------------------------------------------
// Recovery class
// ---------------------------------------------------------------------------

/// The recovery cost of deleting a thing, as an ORDERED ladder.
///
/// `derive(PartialOrd, Ord)` makes the variant declaration order the comparison
/// order: `Auto` is lowest (cheapest to recover), `Irreversible` is highest
/// (can never come back). A grant carries a `recovery_class_ceiling`; an action
/// is in-bound only when its class is `<=` the ceiling, so a `BuildRecovery`
/// grant capped at `Rebuild` admits `Auto`/`Redownload`/`Rebuild` but rejects
/// `Recreate`/`Manual`/`Irreversible`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecoveryClass {
    /// Comes back on its own with no user action (e.g. regenerated on next run).
    Auto,
    /// Re-fetched from the network (package caches, downloaded archives).
    Redownload,
    /// Rebuilt from source already on disk (build artifacts, derived data).
    Rebuild,
    /// Re-created by hand from scratch, but mechanically (re-run a generator).
    Recreate,
    /// Manual, non-mechanical effort to reconstruct.
    Manual,
    /// Gone for good — no recovery path. The FAIL-CLOSED default.
    Irreversible,
}

/// Map a [`Consequences::recovery`] string onto a [`RecoveryClass`].
///
/// FAIL-CLOSED: any unknown token — and, at the call sites, a *missing*
/// `Consequences` — collapses to [`RecoveryClass::Irreversible`], the highest
/// (most-restrictive) class. A typo or a new, unrecognized recovery word can
/// therefore only ever make an action HARDER to authorize, never easier.
pub fn parse_recovery_class(s: &str) -> RecoveryClass {
    match s.trim().to_ascii_lowercase().as_str() {
        "auto" => RecoveryClass::Auto,
        "redownload" => RecoveryClass::Redownload,
        "rebuild" => RecoveryClass::Rebuild,
        "recreate" => RecoveryClass::Recreate,
        "manual" => RecoveryClass::Manual,
        "irreversible" => RecoveryClass::Irreversible,
        // UNKNOWN / None => Irreversible (fail-closed).
        _ => RecoveryClass::Irreversible,
    }
}

/// The recovery class of a candidate from its optional [`Consequences`].
/// `None` consequences => [`RecoveryClass::Irreversible`] (fail-closed): if we
/// don't KNOW how a thing recovers, we treat it as if it never does.
fn recovery_class_of(cons: Option<&Consequences>) -> RecoveryClass {
    match cons {
        Some(c) => parse_recovery_class(&c.recovery),
        None => RecoveryClass::Irreversible,
    }
}

// ---------------------------------------------------------------------------
// Grant category + the grant itself
// ---------------------------------------------------------------------------

/// The broad intent a grant authorizes. Advisory/labelling only — the hard
/// bound is the numeric/class fields below — but it lets the audit log and the
/// issuer reason about *why* a grant exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantCategory {
    /// Free space to unblock a build (rebuildable/redownloadable artifacts).
    BuildRecovery,
    /// Routine cache/temp hygiene.
    RoutineCleanup,
    /// Broadest autonomy — still bounded by ceiling/bytes/confidence/scope.
    AgentAutonomy,
}

/// A signed capability grant: the bound an off-box issuer hands the actor.
///
/// The [`signature`] is an ed25519 signature over the CANONICAL body — every
/// field EXCEPT `signature`, serialized deterministically by
/// [`canonical_body`]. Tamper with any bound field and verification fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub schema_version: u32,
    pub category: GrantCategory,
    /// Highest recovery class this grant will authorize (inclusive).
    pub recovery_class_ceiling: RecoveryClass,
    /// Cumulative byte budget. `spent + bytes` must stay `<=` this.
    pub max_bytes: u64,
    /// Confidence floor — a candidate's confidence must be `>=` this.
    pub min_confidence: f32,
    /// Optional glob (`~` expands to `$HOME`) the path must match. `None` => any
    /// path (still HOME-scoped by the rest of the system).
    pub path_scope: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Random nonce — makes each grant unique (and feeds the audit fingerprint).
    pub nonce: String,
    /// ed25519 signature (hex) over [`canonical_body`].
    pub signature: String,
}

/// The outcome of consulting a grant for one prospective action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantDecision {
    /// In-bound: the grant authorizes this action.
    Allow,
    /// Out-of-bound, with EXACTLY ONE reason.
    Deny(String),
}

// ---------------------------------------------------------------------------
// Canonical signing body
// ---------------------------------------------------------------------------

/// The deterministic byte string that is signed/verified. It is EXACTLY the
/// grant's bound fields (everything except `signature`), serialized in a fixed
/// order with no floating-point ambiguity, so an issuer and a verifier always
/// reconstruct identical bytes.
///
/// `min_confidence` is emitted via `{:?}` on the `f32` so the textual form is
/// stable and round-trips bit-for-bit (avoids locale/format drift). Every other
/// field has a canonical textual form already.
fn canonical_body(g: &Grant) -> String {
    let scope = g.path_scope.as_deref().unwrap_or("");
    format!(
        "v={schema}\ncategory={cat:?}\nceiling={ceil:?}\nmax_bytes={max}\nmin_confidence={conf:?}\npath_scope={scope}\nissued_at={iss}\nexpires_at={exp}\nnonce={nonce}",
        schema = g.schema_version,
        cat = g.category,
        ceil = g.recovery_class_ceiling,
        max = g.max_bytes,
        conf = g.min_confidence,
        scope = scope,
        iss = g.issued_at.to_rfc3339(),
        exp = g.expires_at.to_rfc3339(),
        nonce = g.nonce,
    )
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

/// Why a grant failed [`validate`]. Distinct variants so callers (and tests)
/// can branch on the exact failure mode.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("grant expired at {0}")]
    Expired(String),
    #[error("grant signature does not verify against the trusted public key")]
    BadSignature,
    #[error("grant schema {found} is not supported (expected {expected})")]
    Schema { found: u32, expected: u32 },
    #[error("no trusted public key: {0}")]
    NoPubkey(String),
    #[error("malformed grant: {0}")]
    Malformed(String),
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// `~/.diskspace/grant.json` — the issued, signed grant.
pub fn grant_path() -> PathBuf {
    profile::data_dir().join("grant.json")
}

/// `~/.diskspace/grant.pub` — the trusted public key (hex), file anchor.
pub fn pubkey_path() -> PathBuf {
    profile::data_dir().join("grant.pub")
}

/// `~/.diskspace/grants.jsonl` — the tamper-evident audit log.
pub fn audit_path() -> PathBuf {
    profile::data_dir().join("grants.jsonl")
}

// ---------------------------------------------------------------------------
// Trusted public key resolution
// ---------------------------------------------------------------------------

/// Resolve the trusted verifying key: the compile-time pin if set (hardened),
/// otherwise `grant.pub` (file anchor). `pubkey_path` is parameterized so tests
/// and the loader can point at a tempdir.
fn trusted_pubkey_in(pubkey_path: &Path) -> std::result::Result<VerifyingKey, GrantError> {
    if let Some(hex) = COMPILE_PUBKEY {
        return verifying_key_from_hex(hex.trim());
    }
    let raw = std::fs::read_to_string(pubkey_path)
        .map_err(|e| GrantError::NoPubkey(format!("reading {}: {e}", pubkey_path.display())))?;
    verifying_key_from_hex(raw.trim())
}

fn verifying_key_from_hex(hex: &str) -> std::result::Result<VerifyingKey, GrantError> {
    let bytes = decode_hex(hex)
        .ok_or_else(|| GrantError::NoPubkey("public key is not valid hex".into()))?;
    let arr: [u8; PUBLIC_KEY_LENGTH] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| GrantError::NoPubkey("public key is not 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|_| GrantError::NoPubkey("public key is not a valid ed25519 point".into()))
}

// ---------------------------------------------------------------------------
// Load + validate
// ---------------------------------------------------------------------------

/// Load the grant from `path` (defaults to [`grant_path`]).
///
/// Returns `Ok(None)` when NO grant file exists — the caller then falls back to
/// the human-consent flow. When a file exists it is parsed AND validated; a
/// present-but-invalid grant is an error (fail-closed: a corrupt or tampered
/// grant must not silently degrade to "no grant / human consent" and slip past,
/// it must be surfaced).
pub fn load(path: Option<&Path>) -> Result<Option<Grant>> {
    let owned;
    let p = match path {
        Some(p) => p,
        None => {
            owned = grant_path();
            &owned
        }
    };
    if !p.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(p)?;
    let grant: Grant =
        serde_json::from_str(&content).map_err(|e| GrantError::Malformed(e.to_string()))?;

    // Resolve the trusted pubkey alongside the grant file (same data_dir) unless
    // compile-pinned. Validate before handing the grant back.
    let pub_anchor = p
        .parent()
        .map(|d| d.join("grant.pub"))
        .unwrap_or_else(pubkey_path);
    validate_in(&grant, &pub_anchor)?;
    Ok(Some(grant))
}

/// Validate a grant against the trusted public key at [`pubkey_path`].
/// Checks, in order: schema understood; not expired; signature verifies.
pub fn validate(g: &Grant) -> std::result::Result<(), GrantError> {
    validate_in(g, &pubkey_path())
}

/// [`validate`] with the pubkey anchor parameterized (tests/loader seam).
pub fn validate_in(g: &Grant, pubkey_path: &Path) -> std::result::Result<(), GrantError> {
    if g.schema_version != GRANT_SCHEMA {
        return Err(GrantError::Schema {
            found: g.schema_version,
            expected: GRANT_SCHEMA,
        });
    }
    if Utc::now() >= g.expires_at {
        return Err(GrantError::Expired(g.expires_at.to_rfc3339()));
    }
    let vk = trusted_pubkey_in(pubkey_path)?;
    let sig_bytes = decode_hex(&g.signature).ok_or(GrantError::BadSignature)?;
    let sig_arr: [u8; SIGNATURE_LENGTH] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| GrantError::BadSignature)?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(canonical_body(g).as_bytes(), &sig)
        .map_err(|_| GrantError::BadSignature)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// allows() — the PURE in-bound decision
// ---------------------------------------------------------------------------

/// Decide whether `g` authorizes deleting `bytes` at `path` with `confidence`,
/// given `cons` (the candidate's consequences) and `spent` (bytes already
/// consumed under this grant).
///
/// PURE: no I/O, no clock except the grant's own expiry, no signature check
/// (call [`validate`] first — `allows` assumes the grant is authentic and only
/// asks whether the action falls inside its bound). Returns EXACTLY ONE
/// [`GrantDecision::Deny`] reason, evaluated in a fixed precedence so the result
/// is deterministic:
///
///   1. expired
///   2. confidence below floor
///   3. recovery class above ceiling (None cons => Irreversible, fail-closed)
///   4. byte budget exceeded
///   5. path outside scope
///
/// If none trip, [`GrantDecision::Allow`].
pub fn allows(
    g: &Grant,
    cons: Option<&Consequences>,
    confidence: f32,
    bytes: u64,
    path: &Path,
    spent: u64,
) -> GrantDecision {
    // 1. Expiry. (allows() owns its own expiry check so a stale grant can never
    //    authorize even if validate() was somehow skipped.)
    if Utc::now() >= g.expires_at {
        return GrantDecision::Deny(format!("grant expired at {}", g.expires_at.to_rfc3339()));
    }

    // 2. Confidence floor. FAIL-CLOSED on non-finite values: a NaN floor makes
    //    EVERY IEEE comparison false (so `confidence < floor` never trips and the
    //    floor is silently void), and a NaN candidate confidence would likewise
    //    slip the comparison. Treat either non-finite value as an automatic Deny so
    //    the grant's most important numeric bound can never be disabled by a NaN.
    if !g.min_confidence.is_finite() || !confidence.is_finite() || confidence < g.min_confidence {
        return GrantDecision::Deny(format!(
            "confidence {:.3} below grant floor {:.3}",
            confidence, g.min_confidence
        ));
    }

    // 3. Recovery-class ceiling. FAIL-CLOSED on unknown/None => Irreversible.
    let class = recovery_class_of(cons);
    if class > g.recovery_class_ceiling {
        return GrantDecision::Deny(format!(
            "recovery class {:?} exceeds grant ceiling {:?}",
            class, g.recovery_class_ceiling
        ));
    }

    // 4. Byte budget (saturating so a pathological spend can't wrap).
    if spent.saturating_add(bytes) > g.max_bytes {
        return GrantDecision::Deny(format!(
            "byte budget exceeded: spent {} + {} > max {}",
            spent, bytes, g.max_bytes
        ));
    }

    // 5. Path scope glob (same expand_home + glob semantics as never_touch).
    if let Some(scope) = &g.path_scope {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
        let expanded = crate::core::scanner::expand_home(scope, Path::new(&home));
        let in_scope = glob::Pattern::new(&expanded)
            .map(|pat| pat.matches_path(path))
            .unwrap_or(false);
        if !in_scope {
            return GrantDecision::Deny(format!(
                "path {} outside grant scope {}",
                path.display(),
                scope
            ));
        }
    }

    GrantDecision::Allow
}

// ---------------------------------------------------------------------------
// Audit log — tamper-evident, fs4 LOCKED append (series.rs pattern)
// ---------------------------------------------------------------------------

/// One line in `grants.jsonl`. Carries a grant FINGERPRINT — a SHA-256 of the
/// grant's SIGNATURE bytes — so the entry BINDS to a specific issued grant
/// WITHOUT ever recording the signature or any secret. Because the signature is
/// itself an ed25519 signature over the canonical body (and the private key is
/// off-box), this fingerprint cannot be reproduced by anyone who only sees the
/// world-readable `nonce`/`pubkey`: it is forge-resistant, not a mere correlation
/// id. (Two distinct keys can never collide on a nonce here either.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: DateTime<Utc>,
    /// SHA-256 hex of the grant SIGNATURE bytes — binds the line to the exact
    /// issued grant, leaks neither the signature nor any secret.
    pub grant_fingerprint: String,
    /// What was attempted (e.g. "airlock", "reclaim").
    pub action: String,
    pub path: PathBuf,
    pub bytes: u64,
    /// "allow" or "deny".
    pub decision: String,
    /// The single deny reason, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
}

/// The grant fingerprint: `sha256(signature_bytes)` as hex. Pure; never includes
/// the signature itself or any secret. Hashing the SIGNATURE (an ed25519 sig over
/// the canonical body, mintable only with the off-box private key) BINDS the audit
/// line to the exact issued grant and cannot be reproduced from the world-readable
/// `nonce`+`pubkey`. The fingerprint is robust to the trust anchor changing after
/// validation, because it never re-reads the anchor.
///
/// If the grant's signature is absent or not valid hex (e.g. an in-memory grant
/// that was never signed), we emit the structured marker `"unsigned"` rather than
/// a hash that would look valid.
fn fingerprint(g: &Grant) -> String {
    match decode_hex(&g.signature) {
        Some(sig_bytes) if !sig_bytes.is_empty() => {
            let mut h = Sha256::new();
            h.update(&sig_bytes);
            encode_hex(&h.finalize())
        }
        _ => "unsigned".to_string(),
    }
}

/// Append one audit line for `g`'s consultation. Best-effort and LOCKED:
/// uses the fs4 exclusive-lock append (the `series.rs` pattern, NOT the lockless
/// `history.rs` open/close-per-line), so concurrent actors never tear a line.
/// Never records the signature or any secret — only the fingerprint.
pub fn audit(g: &Grant, action: &str, path: &Path, bytes: u64, decision: &GrantDecision) {
    if let Err(e) = audit_in(&audit_path(), g, action, path, bytes, decision) {
        eprintln!("(grant: failed to write audit entry: {})", e);
    }
}

fn audit_in(
    log_path: &Path,
    g: &Grant,
    action: &str,
    path: &Path,
    bytes: u64,
    decision: &GrantDecision,
) -> Result<()> {
    let (decision_str, deny_reason) = match decision {
        GrantDecision::Allow => ("allow".to_string(), None),
        GrantDecision::Deny(r) => ("deny".to_string(), Some(r.clone())),
    };
    let entry = AuditEntry {
        ts: Utc::now(),
        grant_fingerprint: fingerprint(g),
        action: action.to_string(),
        path: path.to_path_buf(),
        bytes,
        decision: decision_str,
        deny_reason,
    };

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Serialize before taking the lock so a bad value never holds the lock or
    // leaves a half-written line.
    let line = serde_json::to_string(&entry)?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    // ONE exclusive lock around the append — concurrent writers block here, so
    // lines never interleave or tear (mirrors series::append_batch_in).
    FileExt::lock(&file)?;
    let write_res = (|| -> std::io::Result<()> {
        let mut w = &file;
        writeln!(w, "{}", line)?;
        w.flush()?;
        Ok(())
    })();
    let unlock_res = FileExt::unlock(&file);
    write_res?;
    unlock_res?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Off-box mint tools — these use the PRIVATE key
// ---------------------------------------------------------------------------
//
// These run on the user's Mac (where the private key lives), NOT on the actor
// box. They are ALWAYS compiled in: security comes from WHERE the private key
// file is, never from a build flag. The actor box simply never has the private
// key, so it can VERIFY grants but never MINT them.

/// Generate a fresh ed25519 keypair. Writes the SECRET key (hex) to
/// `priv_out` with mode 0600, and the PUBLIC key (hex) to `pub_out` (defaults to
/// [`pubkey_path`] when `None`). Returns the public key hex.
pub fn keygen(priv_out: &Path, pub_out: Option<&Path>) -> Result<String> {
    use rand::rngs::OsRng;
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();

    let priv_hex = encode_hex(&signing.to_bytes());
    let pub_hex = encode_hex(verifying.as_bytes());

    if let Some(parent) = priv_out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_private_0600(priv_out, &priv_hex)?;

    let pub_path = pub_out.map(Path::to_path_buf).unwrap_or_else(pubkey_path);
    if let Some(parent) = pub_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&pub_path, format!("{pub_hex}\n"))?;

    Ok(pub_hex)
}

/// Write the private key with restrictive perms (0600 on unix). On non-unix we
/// fall back to a plain write (the perms model differs); the security story is
/// still "this file only exists on the user's box."
fn write_private_0600(path: &Path, contents: &str) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(contents.as_bytes())?;
    f.write_all(b"\n")?;
    f.flush()?;
    Ok(())
}

/// The parameters an issuer supplies to mint a grant.
#[derive(Debug, Clone)]
pub struct IssueParams {
    pub category: GrantCategory,
    pub recovery_class_ceiling: RecoveryClass,
    pub max_bytes: u64,
    pub min_confidence: f32,
    pub path_scope: Option<String>,
    /// How long from now the grant is valid.
    pub valid_for: chrono::Duration,
}

/// Mint AND sign a [`Grant`] using the private key at `privkey_path`. Runs
/// off-box. The nonce is freshly random; `issued_at`/`expires_at` are stamped
/// from the current clock and `params.valid_for`.
pub fn issue(params: &IssueParams, privkey_path: &Path) -> Result<Grant> {
    // Reject a non-finite or out-of-range confidence floor BEFORE signing. A NaN
    // floor would sign and verify cleanly yet silently void the floor (every IEEE
    // comparison with NaN is false), so the most important numeric bound must be
    // validated at mint time, not just defended against in `allows`.
    if !params.min_confidence.is_finite() || !(0.0..=1.0).contains(&params.min_confidence) {
        return Err(anyhow::anyhow!(
            "min_confidence must be a finite value in 0.0..=1.0, got {}",
            params.min_confidence
        ));
    }

    let signing = load_signing_key(privkey_path)?;

    let now = Utc::now();
    let nonce = random_nonce();
    let mut grant = Grant {
        schema_version: GRANT_SCHEMA,
        category: params.category,
        recovery_class_ceiling: params.recovery_class_ceiling,
        max_bytes: params.max_bytes,
        min_confidence: params.min_confidence,
        path_scope: params.path_scope.clone(),
        issued_at: now,
        expires_at: now + params.valid_for,
        nonce,
        signature: String::new(),
    };
    let sig = signing.sign(canonical_body(&grant).as_bytes());
    grant.signature = encode_hex(&sig.to_bytes());
    Ok(grant)
}

/// Load + parse a hex-encoded ed25519 secret key from `path` into a `SigningKey`.
fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let raw = std::fs::read_to_string(path)?;
    let bytes =
        decode_hex(raw.trim()).ok_or_else(|| anyhow::anyhow!("private key is not valid hex"))?;
    let arr: [u8; SECRET_KEY_LENGTH] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key is not 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// A 128-bit random nonce as hex.
fn random_nonce() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    encode_hex(&buf)
}

// ---------------------------------------------------------------------------
// Tiny hex helpers (avoid pulling a hex crate for two functions)
// ---------------------------------------------------------------------------

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    // Odd-length hex is invalid. Low-bit test is equivalent to `len % 2 != 0`
    // but avoids the `manual_is_multiple_of` lint (whose suggested
    // `is_multiple_of` only stabilized in a recent toolchain — keep this
    // portable to the edition-2021 baseline).
    if s.len() & 1 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Throwaway base dir under the OS temp dir, cleaned on drop. Tests pass it
    /// to the `*_in` seams so they never touch the real `~/.diskspace`.
    struct TempBase {
        path: PathBuf,
    }
    impl TempBase {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "diskspace-grant-test-{}-{}-{}",
                tag,
                std::process::id(),
                Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self { path: p }
        }
        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }
    impl Drop for TempBase {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn cons(recovery: &str) -> Consequences {
        Consequences {
            recovery: recovery.to_string(),
            rebuild_seconds: None,
            impact: "test".into(),
            recovery_cmd: None,
        }
    }

    /// keygen into a tempdir; return (priv_path, pub_path).
    fn keypair(base: &TempBase) -> (PathBuf, PathBuf) {
        let priv_p = base.join("grant.key");
        let pub_p = base.join("grant.pub");
        keygen(&priv_p, Some(&pub_p)).unwrap();
        (priv_p, pub_p)
    }

    fn default_params() -> IssueParams {
        IssueParams {
            category: GrantCategory::BuildRecovery,
            recovery_class_ceiling: RecoveryClass::Rebuild,
            max_bytes: 1_000,
            min_confidence: 0.80,
            path_scope: None,
            valid_for: chrono::Duration::hours(1),
        }
    }

    // -- recovery class ----------------------------------------------------

    #[test]
    fn parse_recovery_class_all_six_plus_unknown() {
        assert_eq!(parse_recovery_class("auto"), RecoveryClass::Auto);
        assert_eq!(
            parse_recovery_class("redownload"),
            RecoveryClass::Redownload
        );
        assert_eq!(parse_recovery_class("rebuild"), RecoveryClass::Rebuild);
        assert_eq!(parse_recovery_class("recreate"), RecoveryClass::Recreate);
        assert_eq!(parse_recovery_class("manual"), RecoveryClass::Manual);
        assert_eq!(
            parse_recovery_class("irreversible"),
            RecoveryClass::Irreversible
        );
        // case-insensitive + whitespace tolerant
        assert_eq!(parse_recovery_class("  REBUILD "), RecoveryClass::Rebuild);
        // UNKNOWN => Irreversible (fail-closed)
        assert_eq!(parse_recovery_class("wat"), RecoveryClass::Irreversible);
        assert_eq!(parse_recovery_class(""), RecoveryClass::Irreversible);
    }

    #[test]
    fn recovery_class_ord_matches_documented_ascending_order() {
        // Auto < Redownload < Rebuild < Recreate < Manual < Irreversible
        let ladder = [
            RecoveryClass::Auto,
            RecoveryClass::Redownload,
            RecoveryClass::Rebuild,
            RecoveryClass::Recreate,
            RecoveryClass::Manual,
            RecoveryClass::Irreversible,
        ];
        for w in ladder.windows(2) {
            assert!(w[0] < w[1], "{:?} must be < {:?}", w[0], w[1]);
        }
        assert_eq!(*ladder.iter().min().unwrap(), RecoveryClass::Auto);
        assert_eq!(*ladder.iter().max().unwrap(), RecoveryClass::Irreversible);
    }

    #[test]
    fn missing_consequences_is_irreversible_fail_closed() {
        assert_eq!(recovery_class_of(None), RecoveryClass::Irreversible);
        assert_eq!(recovery_class_of(Some(&cons("auto"))), RecoveryClass::Auto);
    }

    // -- sign / verify round-trip -----------------------------------------

    #[test]
    fn sign_then_verify_round_trip() {
        let base = TempBase::new("roundtrip");
        let (priv_p, pub_p) = keypair(&base);
        let grant = issue(&default_params(), &priv_p).unwrap();
        // valid signature verifies against the matching pubkey
        validate_in(&grant, &pub_p).expect("freshly-signed grant verifies");
    }

    #[test]
    fn tampered_body_fails_verification() {
        let base = TempBase::new("tamper");
        let (priv_p, pub_p) = keypair(&base);
        let mut grant = issue(&default_params(), &priv_p).unwrap();
        // Mutate a bound field WITHOUT re-signing — signature now covers stale bytes.
        grant.max_bytes += 1;
        let err = validate_in(&grant, &pub_p).unwrap_err();
        assert_eq!(err, GrantError::BadSignature);
    }

    #[test]
    fn tampered_ceiling_fails_verification() {
        let base = TempBase::new("tamper-ceiling");
        let (priv_p, pub_p) = keypair(&base);
        let mut grant = issue(&default_params(), &priv_p).unwrap();
        // The most security-relevant escalation: widen the recovery ceiling.
        grant.recovery_class_ceiling = RecoveryClass::Irreversible;
        let err = validate_in(&grant, &pub_p).unwrap_err();
        assert_eq!(err, GrantError::BadSignature);
    }

    #[test]
    fn wrong_key_fails_verification() {
        let base_a = TempBase::new("key-a");
        let base_b = TempBase::new("key-b");
        let (priv_a, _pub_a) = keypair(&base_a);
        let (_priv_b, pub_b) = keypair(&base_b);
        // Sign with key A, verify against key B's pubkey → BadSignature.
        let grant = issue(&default_params(), &priv_a).unwrap();
        let err = validate_in(&grant, &pub_b).unwrap_err();
        assert_eq!(err, GrantError::BadSignature);
    }

    #[test]
    fn expired_grant_fails_validate() {
        let base = TempBase::new("expired");
        let (priv_p, pub_p) = keypair(&base);
        let mut params = default_params();
        params.valid_for = chrono::Duration::seconds(-10); // already expired
        let grant = issue(&params, &priv_p).unwrap();
        let err = validate_in(&grant, &pub_p).unwrap_err();
        match err {
            GrantError::Expired(_) => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn unknown_schema_fails_validate() {
        let base = TempBase::new("schema");
        let (priv_p, pub_p) = keypair(&base);
        let mut grant = issue(&default_params(), &priv_p).unwrap();
        grant.schema_version = GRANT_SCHEMA + 1;
        let err = validate_in(&grant, &pub_p).unwrap_err();
        match err {
            GrantError::Schema { found, expected } => {
                assert_eq!(found, GRANT_SCHEMA + 1);
                assert_eq!(expected, GRANT_SCHEMA);
            }
            other => panic!("expected Schema, got {other:?}"),
        }
    }

    // -- load() ------------------------------------------------------------

    #[test]
    fn load_none_when_no_file() {
        let base = TempBase::new("load-none");
        let missing = base.join("grant.json");
        assert!(load(Some(&missing)).unwrap().is_none());
    }

    #[test]
    fn load_parses_and_validates_a_real_grant() {
        let base = TempBase::new("load-real");
        let (priv_p, _pub_p) = keypair(&base); // writes grant.pub alongside
        let grant = issue(&default_params(), &priv_p).unwrap();
        let gpath = base.join("grant.json");
        std::fs::write(&gpath, serde_json::to_string_pretty(&grant).unwrap()).unwrap();
        let loaded = load(Some(&gpath)).unwrap().expect("grant loads");
        assert_eq!(loaded.nonce, grant.nonce);
    }

    #[test]
    fn load_tampered_grant_is_error_not_none() {
        // A present-but-invalid grant must fail loudly, NOT degrade to None and
        // silently slip past into "no grant / human consent".
        let base = TempBase::new("load-tampered");
        let (priv_p, _pub_p) = keypair(&base);
        let mut grant = issue(&default_params(), &priv_p).unwrap();
        grant.max_bytes += 9999; // invalidate signature
        let gpath = base.join("grant.json");
        std::fs::write(&gpath, serde_json::to_string_pretty(&grant).unwrap()).unwrap();
        assert!(load(Some(&gpath)).is_err(), "tampered grant must error");
    }

    // -- allows() BOUNDARY MATRIX -----------------------------------------
    //
    // A signed, currently-valid grant with: ceiling=Rebuild, min_conf=0.80,
    // max_bytes=1000, scope set. We flip ONE dimension at a time across:
    //   {class <= / > ceiling} x {conf >= / < min} x {bytes <= / > max}
    //   x {path in / out scope} x {expired}
    // asserting exactly one Deny reason and the fail-closed default.

    fn scoped_grant(base: &TempBase) -> Grant {
        let priv_p = base.join("grant.key");
        let pub_p = base.join("grant.pub");
        keygen(&priv_p, Some(&pub_p)).unwrap();
        let params = IssueParams {
            category: GrantCategory::BuildRecovery,
            recovery_class_ceiling: RecoveryClass::Rebuild,
            max_bytes: 1_000,
            min_confidence: 0.80,
            path_scope: Some("/tmp/scope/**".to_string()),
            valid_for: chrono::Duration::hours(1),
        };
        issue(&params, &priv_p).unwrap()
    }

    fn in_path() -> PathBuf {
        PathBuf::from("/tmp/scope/sub/thing")
    }
    fn out_path() -> PathBuf {
        PathBuf::from("/var/elsewhere/thing")
    }

    #[test]
    fn allows_all_in_bound_is_allow() {
        let base = TempBase::new("allow-allin");
        let g = scoped_grant(&base);
        // class Rebuild (== ceiling), conf 0.90 (>= 0.80), 500 bytes (<= 1000),
        // path in scope, not expired.
        let d = allows(&g, Some(&cons("rebuild")), 0.90, 500, &in_path(), 0);
        assert_eq!(d, GrantDecision::Allow);
    }

    #[test]
    fn allows_class_above_ceiling_denies() {
        let base = TempBase::new("deny-class");
        let g = scoped_grant(&base);
        // recreate > rebuild ceiling. Everything else in-bound → exactly one deny.
        let d = allows(&g, Some(&cons("recreate")), 0.90, 500, &in_path(), 0);
        match d {
            GrantDecision::Deny(r) => assert!(r.contains("ceiling"), "got: {r}"),
            GrantDecision::Allow => panic!("class above ceiling must deny"),
        }
    }

    #[test]
    fn allows_class_at_and_below_ceiling_ok() {
        let base = TempBase::new("class-le");
        let g = scoped_grant(&base);
        for c in ["auto", "redownload", "rebuild"] {
            assert_eq!(
                allows(&g, Some(&cons(c)), 0.90, 500, &in_path(), 0),
                GrantDecision::Allow,
                "class {c} <= rebuild ceiling should allow"
            );
        }
    }

    #[test]
    fn allows_none_cons_is_irreversible_denied_unless_ceiling_irreversible() {
        let base = TempBase::new("none-cons");
        let g = scoped_grant(&base); // ceiling = Rebuild
                                     // None => Irreversible > Rebuild → deny on ceiling.
        let d = allows(&g, None, 0.90, 500, &in_path(), 0);
        match d {
            GrantDecision::Deny(r) => assert!(r.contains("ceiling"), "got: {r}"),
            GrantDecision::Allow => panic!("None cons must fail closed to Irreversible"),
        }

        // Now an Irreversible-ceiling grant: None cons is admitted (class==ceiling).
        let base2 = TempBase::new("none-cons-irrev");
        let priv_p = base2.join("grant.key");
        let pub_p = base2.join("grant.pub");
        keygen(&priv_p, Some(&pub_p)).unwrap();
        let params = IssueParams {
            category: GrantCategory::AgentAutonomy,
            recovery_class_ceiling: RecoveryClass::Irreversible,
            max_bytes: 1_000,
            min_confidence: 0.80,
            path_scope: None,
            valid_for: chrono::Duration::hours(1),
        };
        let g2 = issue(&params, &priv_p).unwrap();
        assert_eq!(
            allows(&g2, None, 0.90, 500, &in_path(), 0),
            GrantDecision::Allow,
            "None cons (Irreversible) admitted only when ceiling is Irreversible"
        );
    }

    #[test]
    fn allows_confidence_below_floor_denies() {
        let base = TempBase::new("deny-conf");
        let g = scoped_grant(&base);
        let d = allows(&g, Some(&cons("rebuild")), 0.79, 500, &in_path(), 0);
        match d {
            GrantDecision::Deny(r) => assert!(r.contains("confidence"), "got: {r}"),
            GrantDecision::Allow => panic!("below-floor confidence must deny"),
        }
    }

    #[test]
    fn issue_rejects_non_finite_or_out_of_range_min_confidence() {
        let base = TempBase::new("issue-nan");
        let (priv_p, _pub_p) = keypair(&base);
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.1, 1.1] {
            let mut params = default_params();
            params.min_confidence = bad;
            assert!(
                issue(&params, &priv_p).is_err(),
                "issue must reject min_confidence {bad}"
            );
        }
    }

    #[test]
    fn allows_nan_floor_denies_fail_closed() {
        // A NaN floor must DENY, never silently admit. We can't mint one via
        // issue() (it now rejects), so we hand-construct + sign a grant whose
        // canonical body carries NaN, proving allows() is defensive even if a NaN
        // floor somehow reaches it (e.g. a future shape change or a raw grant).
        let base = TempBase::new("nan-floor");
        let priv_p = base.join("grant.key");
        let pub_p = base.join("grant.pub");
        keygen(&priv_p, Some(&pub_p)).unwrap();
        let signing = load_signing_key(&priv_p).unwrap();
        let now = Utc::now();
        let mut g = Grant {
            schema_version: GRANT_SCHEMA,
            category: GrantCategory::BuildRecovery,
            recovery_class_ceiling: RecoveryClass::Rebuild,
            max_bytes: 1_000,
            min_confidence: f32::NAN,
            path_scope: None,
            issued_at: now,
            expires_at: now + chrono::Duration::hours(1),
            nonce: random_nonce(),
            signature: String::new(),
        };
        let sig = signing.sign(canonical_body(&g).as_bytes());
        g.signature = encode_hex(&sig.to_bytes());
        // The NaN-floor grant still VERIFIES (NaN round-trips via {:?})…
        validate_in(&g, &pub_p).expect("hand-signed NaN-floor grant verifies");
        // …but allows() must DENY even a perfect-confidence candidate, not admit it.
        match allows(&g, Some(&cons("rebuild")), 1.0, 1, &in_path(), 0) {
            GrantDecision::Deny(r) => assert!(r.contains("confidence"), "got: {r}"),
            GrantDecision::Allow => panic!("a NaN floor must DENY, never admit"),
        }
        // A NaN candidate confidence is likewise denied (against a normal floor).
        let g2 = scoped_grant(&base);
        match allows(&g2, Some(&cons("rebuild")), f32::NAN, 1, &in_path(), 0) {
            GrantDecision::Deny(r) => assert!(r.contains("confidence"), "got: {r}"),
            GrantDecision::Allow => panic!("a NaN candidate confidence must DENY"),
        }
    }

    #[test]
    fn allows_confidence_at_floor_ok() {
        let base = TempBase::new("conf-eq");
        let g = scoped_grant(&base);
        assert_eq!(
            allows(&g, Some(&cons("rebuild")), 0.80, 500, &in_path(), 0),
            GrantDecision::Allow,
            "confidence == floor is in-bound"
        );
    }

    #[test]
    fn allows_bytes_over_budget_denies() {
        let base = TempBase::new("deny-bytes");
        let g = scoped_grant(&base);
        // spent 600 + 500 = 1100 > 1000.
        let d = allows(&g, Some(&cons("rebuild")), 0.90, 500, &in_path(), 600);
        match d {
            GrantDecision::Deny(r) => assert!(r.contains("budget"), "got: {r}"),
            GrantDecision::Allow => panic!("over-budget must deny"),
        }
    }

    #[test]
    fn allows_bytes_exactly_budget_ok() {
        let base = TempBase::new("bytes-eq");
        let g = scoped_grant(&base);
        // spent 500 + 500 == 1000 (<=).
        assert_eq!(
            allows(&g, Some(&cons("rebuild")), 0.90, 500, &in_path(), 500),
            GrantDecision::Allow
        );
    }

    #[test]
    fn allows_path_out_of_scope_denies() {
        let base = TempBase::new("deny-path");
        let g = scoped_grant(&base);
        let d = allows(&g, Some(&cons("rebuild")), 0.90, 500, &out_path(), 0);
        match d {
            GrantDecision::Deny(r) => assert!(r.contains("scope"), "got: {r}"),
            GrantDecision::Allow => panic!("out-of-scope path must deny"),
        }
    }

    #[test]
    fn allows_no_scope_admits_any_path() {
        let base = TempBase::new("no-scope");
        let priv_p = base.join("grant.key");
        let pub_p = base.join("grant.pub");
        keygen(&priv_p, Some(&pub_p)).unwrap();
        let params = IssueParams {
            category: GrantCategory::RoutineCleanup,
            recovery_class_ceiling: RecoveryClass::Rebuild,
            max_bytes: 1_000,
            min_confidence: 0.80,
            path_scope: None,
            valid_for: chrono::Duration::hours(1),
        };
        let g = issue(&params, &priv_p).unwrap();
        assert_eq!(
            allows(&g, Some(&cons("rebuild")), 0.90, 500, &out_path(), 0),
            GrantDecision::Allow,
            "no path_scope => any path admitted"
        );
    }

    #[test]
    fn allows_expired_denies_first() {
        let base = TempBase::new("deny-expired");
        let priv_p = base.join("grant.key");
        let pub_p = base.join("grant.pub");
        keygen(&priv_p, Some(&pub_p)).unwrap();
        let mut params = default_params();
        params.path_scope = Some("/tmp/scope/**".to_string());
        params.valid_for = chrono::Duration::seconds(-5); // expired
        let g = issue(&params, &priv_p).unwrap();
        // Even with EVERYTHING else also out of bound, expiry is reported first.
        let d = allows(&g, None, 0.0, u64::MAX, &out_path(), u64::MAX);
        match d {
            GrantDecision::Deny(r) => assert!(r.contains("expired"), "got: {r}"),
            GrantDecision::Allow => panic!("expired grant must deny"),
        }
    }

    #[test]
    fn allows_precedence_is_deterministic_single_reason() {
        // Confidence fails AND bytes fail AND path fails simultaneously; the
        // documented precedence (conf before bytes before path) means we must
        // see EXACTLY the confidence reason, and only one.
        let base = TempBase::new("precedence");
        let g = scoped_grant(&base);
        let d = allows(&g, Some(&cons("rebuild")), 0.10, 9_999, &out_path(), 9_999);
        match d {
            GrantDecision::Deny(r) => {
                assert!(
                    r.contains("confidence"),
                    "precedence: confidence first, got: {r}"
                );
                assert!(!r.contains("budget"));
                assert!(!r.contains("scope"));
            }
            GrantDecision::Allow => panic!("must deny"),
        }
    }

    // -- audit -------------------------------------------------------------

    #[test]
    fn audit_appends_locked_line_with_fingerprint_no_signature() {
        let base = TempBase::new("audit");
        let priv_p = base.join("grant.key");
        let pub_p = base.join("grant.pub");
        keygen(&priv_p, Some(&pub_p)).unwrap();
        let g = issue(&default_params(), &priv_p).unwrap();
        let log = base.join("grants.jsonl");

        let allow = GrantDecision::Allow;
        let deny = GrantDecision::Deny("confidence 0.100 below grant floor 0.800".into());
        audit_in(&log, &g, "airlock", Path::new("/tmp/x"), 123, &allow).unwrap();
        audit_in(&log, &g, "reclaim", Path::new("/tmp/y"), 9, &deny).unwrap();

        let content = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2);

        // Never leak the signature or secret.
        assert!(
            !content.contains(&g.signature),
            "audit log must NOT contain the signature"
        );
        // The fingerprint is derived from the signature but is NOT the signature,
        // and is NOT reproducible from the world-readable nonce/pubkey.
        let _ = &pub_p; // pubkey is no longer needed to fingerprint

        let e0: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(e0.decision, "allow");
        assert_eq!(e0.action, "airlock");
        assert_eq!(e0.bytes, 123);
        assert!(e0.deny_reason.is_none());
        assert!(!e0.grant_fingerprint.is_empty());

        let e1: AuditEntry = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(e1.decision, "deny");
        assert!(e1.deny_reason.is_some());

        // Fingerprint is stable for the same grant.
        assert_eq!(e0.grant_fingerprint, e1.grant_fingerprint);
        let expected_fp = fingerprint(&g);
        assert_eq!(e0.grant_fingerprint, expected_fp);
        // It is sha256(signature), NOT the signature, and NOT the public nonce.
        assert_ne!(e0.grant_fingerprint, g.signature);
        assert_ne!(e0.grant_fingerprint, g.nonce);
        assert_ne!(e0.grant_fingerprint, "unsigned");

        // An UNSIGNED grant fingerprints to the structured marker, never a
        // hash that would look valid.
        let mut unsigned = g.clone();
        unsigned.signature = String::new();
        assert_eq!(fingerprint(&unsigned), "unsigned");
    }

    // -- keygen perms ------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn keygen_writes_private_key_0600() {
        use std::os::unix::fs::PermissionsExt;
        let base = TempBase::new("perms");
        let priv_p = base.join("grant.key");
        let pub_p = base.join("grant.pub");
        keygen(&priv_p, Some(&pub_p)).unwrap();
        let mode = std::fs::metadata(&priv_p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "private key must be mode 0600");
    }

    // -- hex helpers -------------------------------------------------------

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 15, 16, 255, 128, 42];
        let hex = encode_hex(&bytes);
        assert_eq!(hex, "00010f10ff802a");
        assert_eq!(decode_hex(&hex).unwrap(), bytes);
        assert!(decode_hex("xyz").is_none()); // odd length / non-hex
        assert!(decode_hex("zz").is_none());
    }

    #[test]
    fn canonical_body_is_stable_across_clones() {
        let base = TempBase::new("canon");
        let (priv_p, _pub_p) = keypair(&base);
        let g = issue(&default_params(), &priv_p).unwrap();
        let g2 = g.clone();
        assert_eq!(canonical_body(&g), canonical_body(&g2));
        // Signature covers exactly the canonical body — re-deriving must match.
        assert!(!g.signature.is_empty());
    }
}

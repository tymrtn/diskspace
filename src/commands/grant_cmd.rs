//! `diskspace grant …` — the OFF-BOX mint tools, surfaced on the CLI.
//!
//! These subcommands are ALWAYS available regardless of the `actuation` feature:
//! security is from WHERE the private key lives, not from a build flag. `keygen`
//! and `issue` use the PRIVATE key and are meant to run on the user's Mac;
//! `show` only reads the public grant/pubkey and is safe anywhere.
//!
//! See [`crate::core::grant`] for the threat model and the signed-capability
//! design these commands drive.

use anyhow::{anyhow, Context as _, Result};
use std::path::{Path, PathBuf};

use crate::core::grant::{self, GrantCategory, IssueParams, RecoveryClass};
use crate::output::Context;
use crate::profile;

/// `diskspace grant keygen --out <priv>` — generate a keypair. The private key
/// goes to `--out` (mode 0600); the public key to `~/.diskspace/grant.pub` (or
/// `--pub-out`). The PRIVATE key must stay off the actor box.
pub fn keygen(out: &Path, pub_out: Option<&Path>, ctx: &Context) -> Result<()> {
    let pub_hex = grant::keygen(out, pub_out)?;
    let pub_path = pub_out
        .map(Path::to_path_buf)
        .unwrap_or_else(grant::pubkey_path);

    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "private_key": out.display().to_string(),
                "public_key_path": pub_path.display().to_string(),
                "public_key": pub_hex,
            })
        );
    } else {
        println!();
        println!("  keypair generated");
        println!(
            "    private key  {}  (mode 0600 — keep OFF the actor box)",
            out.display()
        );
        println!("    public key   {}", pub_path.display());
        println!("    pubkey hex   {}", pub_hex);
        println!();
        println!("  To pin the key into the binary (hardened anchor), build with:");
        println!(
            "    DISKSPACE_GRANT_PUBKEY={} cargo build --release",
            pub_hex
        );
        println!();
    }
    Ok(())
}

/// `diskspace grant issue …` — mint + sign a grant with the private key.
#[allow(clippy::too_many_arguments)]
pub fn issue(
    category: &str,
    max_bytes: &str,
    recovery_ceiling: &str,
    min_confidence: f32,
    path_scope: Option<&str>,
    expires_in: &str,
    priv_key: &Path,
    out: Option<&Path>,
    ctx: &Context,
) -> Result<()> {
    let params = IssueParams {
        category: parse_category(category)?,
        recovery_class_ceiling: parse_ceiling(recovery_ceiling),
        max_bytes: parse_bytes(max_bytes)?,
        min_confidence,
        path_scope: path_scope.map(str::to_string),
        valid_for: parse_duration(expires_in)?,
    };
    let grant = grant::issue(&params, priv_key)
        .with_context(|| format!("signing grant with private key {}", priv_key.display()))?;

    let json = serde_json::to_string_pretty(&grant)?;
    // Default: write to ~/.diskspace/grant.json so the actor picks it up.
    let dest = out.map(Path::to_path_buf).unwrap_or_else(grant::grant_path);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&dest, &json)?;

    if ctx.json {
        println!("{}", json);
    } else {
        println!();
        println!("  grant issued → {}", dest.display());
        println!("    category     {:?}", grant.category);
        println!("    ceiling      {:?}", grant.recovery_class_ceiling);
        println!("    max_bytes    {}", grant.max_bytes);
        println!("    min_conf     {}", grant.min_confidence);
        println!(
            "    path_scope   {}",
            grant.path_scope.as_deref().unwrap_or("(any)")
        );
        println!("    expires_at   {}", grant.expires_at.to_rfc3339());
        println!();
    }
    Ok(())
}

/// `diskspace grant show` — print the active grant + validation status.
pub fn show(ctx: &Context) -> Result<()> {
    let gpath = grant::grant_path();
    match grant::load(Some(&gpath)) {
        Ok(Some(g)) => {
            if ctx.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "present": true,
                        "valid": true,
                        "grant": serde_json::to_value(&g)?,
                    })
                );
            } else {
                println!();
                println!("  active grant — {}", gpath.display());
                println!("    category     {:?}", g.category);
                println!("    ceiling      {:?}", g.recovery_class_ceiling);
                println!("    max_bytes    {}", g.max_bytes);
                println!("    min_conf     {}", g.min_confidence);
                println!(
                    "    path_scope   {}",
                    g.path_scope.as_deref().unwrap_or("(any)")
                );
                println!("    expires_at   {}", g.expires_at.to_rfc3339());
                println!("    signature    VERIFIED");
                println!();
            }
        }
        Ok(None) => {
            if ctx.json {
                println!("{}", serde_json::json!({ "present": false }));
            } else {
                println!();
                println!("  no grant — actions fall back to human consent.");
                println!("    expected at {}", gpath.display());
                println!();
            }
        }
        Err(e) => {
            // Present-but-invalid: surface loudly, don't pretend there's no grant.
            if ctx.json {
                println!(
                    "{}",
                    serde_json::json!({ "present": true, "valid": false, "error": e.to_string() })
                );
            } else {
                println!();
                println!("  grant present but INVALID: {}", e);
                println!("    at {}", gpath.display());
                println!();
            }
            std::process::exit(2);
        }
    }
    Ok(())
}

// -- parsers ---------------------------------------------------------------

fn parse_category(s: &str) -> Result<GrantCategory> {
    match s
        .trim()
        .to_ascii_lowercase()
        .replace(['-', '_'], "")
        .as_str()
    {
        "buildrecovery" => Ok(GrantCategory::BuildRecovery),
        "routinecleanup" => Ok(GrantCategory::RoutineCleanup),
        "agentautonomy" => Ok(GrantCategory::AgentAutonomy),
        other => Err(anyhow!(
            "unknown category '{other}' (use build-recovery | routine-cleanup | agent-autonomy)"
        )),
    }
}

/// Recovery ceiling parser. Reuses the grant module's fail-closed mapping, so an
/// unknown ceiling string becomes `Irreversible` (the broadest) — but here the
/// issuer is the trusted off-box user, and a too-broad ceiling on a typo would
/// be SURPRISING, so we reject unknowns instead of silently widening. (The
/// fail-closed direction matters at the VERIFIER; at the trusted issuer we'd
/// rather error than mint something unintended.)
fn parse_ceiling(s: &str) -> RecoveryClass {
    grant::parse_recovery_class(s)
}

/// Parse a byte size like `20G`, `500M`, `1024`. Mirrors the doctor `need`
/// grammar (decimal SI-ish suffixes; bare number = bytes).
fn parse_bytes(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("empty byte size"));
    }
    let (num, mult): (&str, u64) = match s.chars().last().unwrap().to_ascii_uppercase() {
        'K' => (&s[..s.len() - 1], 1_000),
        'M' => (&s[..s.len() - 1], 1_000_000),
        'G' => (&s[..s.len() - 1], 1_000_000_000),
        'T' => (&s[..s.len() - 1], 1_000_000_000_000),
        'B' => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    let value: f64 = num
        .trim()
        .parse()
        .with_context(|| format!("invalid byte size '{s}'"))?;
    if value < 0.0 {
        return Err(anyhow!("byte size cannot be negative: {s}"));
    }
    Ok((value * mult as f64) as u64)
}

/// Parse a human duration like `2h`, `30m`, `7d`, `90s`. Bare number = seconds.
fn parse_duration(s: &str) -> Result<chrono::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("empty duration"));
    }
    let (num, unit_secs): (&str, i64) = match s.chars().last().unwrap().to_ascii_lowercase() {
        's' => (&s[..s.len() - 1], 1),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3_600),
        'd' => (&s[..s.len() - 1], 86_400),
        'w' => (&s[..s.len() - 1], 604_800),
        _ => (s, 1),
    };
    let value: i64 = num
        .trim()
        .parse()
        .with_context(|| format!("invalid duration '{s}'"))?;
    if value <= 0 {
        return Err(anyhow!("duration must be positive: {s}"));
    }
    Ok(chrono::Duration::seconds(value * unit_secs))
}

// Keep an unused-import-free surface when only some helpers are exercised.
#[allow(dead_code)]
fn _data_dir_anchor() -> PathBuf {
    profile::data_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_category_accepts_aliases() {
        assert_eq!(
            parse_category("build-recovery").unwrap(),
            GrantCategory::BuildRecovery
        );
        assert_eq!(
            parse_category("AGENT_AUTONOMY").unwrap(),
            GrantCategory::AgentAutonomy
        );
        assert!(parse_category("nope").is_err());
    }

    #[test]
    fn parse_bytes_suffixes() {
        assert_eq!(parse_bytes("1024").unwrap(), 1024);
        assert_eq!(parse_bytes("20G").unwrap(), 20_000_000_000);
        assert_eq!(parse_bytes("500M").unwrap(), 500_000_000);
        assert_eq!(parse_bytes("2K").unwrap(), 2_000);
        assert!(parse_bytes("").is_err());
        assert!(parse_bytes("-5G").is_err());
    }

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("2h").unwrap(), chrono::Duration::hours(2));
        assert_eq!(
            parse_duration("30m").unwrap(),
            chrono::Duration::minutes(30)
        );
        assert_eq!(parse_duration("7d").unwrap(), chrono::Duration::days(7));
        assert_eq!(parse_duration("90").unwrap(), chrono::Duration::seconds(90));
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn parse_ceiling_fail_closed() {
        assert_eq!(parse_ceiling("rebuild"), RecoveryClass::Rebuild);
        assert_eq!(parse_ceiling("bogus"), RecoveryClass::Irreversible);
    }
}

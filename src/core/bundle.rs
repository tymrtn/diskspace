//! macOS `.app` bundle scaffolding for the watch agent.
//!
//! macOS Login Items / Background Items pulls its display name + icon from a
//! `.app` bundle's `Info.plist`, not from a raw Mach-O binary. So when the
//! launchd agent points at `/opt/homebrew/bin/diskspace` directly, the System
//! Settings tile shows up with a generic icon and "Xoder PR LLC" as the owner.
//!
//! `ensure_bundle` materializes a minimal bundle at
//!   `~/Library/Application Support/diskspace/DiskspaceWatch.app/`
//! containing:
//!   * `Contents/Info.plist`            — identifier, name, LSUIElement, icon ref
//!   * `Contents/MacOS/DiskspaceWatch`  — copy of the running diskspace binary
//!   * `Contents/Resources/AppIcon.icns` — embedded at compile time via include_bytes!
//!
//! The launchd plist's `ProgramArguments[0]` should point at
//! `DiskspaceWatch.app/Contents/MacOS/DiskspaceWatch` so the OS finds the
//! parent bundle and renders the icon.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Raw bytes of the bundled icon — see assets/icon/AppIcon.icns.
const APP_ICON_ICNS: &[u8] = include_bytes!("../../assets/icon/AppIcon.icns");

const BUNDLE_NAME: &str = "DiskspaceWatch.app";
const BUNDLE_EXECUTABLE: &str = "DiskspaceWatch";
const BUNDLE_IDENTIFIER: &str = "com.tymrtn.diskspace.watch";

/// Build (or refresh) the watch app bundle. Returns the absolute path to the
/// executable inside the bundle, which is what the launchd plist should call.
pub fn ensure_bundle() -> Result<PathBuf> {
    let bundle_root = bundle_root_path()?;
    let contents = bundle_root.join("Contents");
    let macos_dir = contents.join("MacOS");
    let resources_dir = contents.join("Resources");
    fs::create_dir_all(&macos_dir).context("creating bundle MacOS/")?;
    fs::create_dir_all(&resources_dir).context("creating bundle Resources/")?;

    // Info.plist
    let info_plist = info_plist_xml();
    fs::write(contents.join("Info.plist"), info_plist).context("writing Info.plist")?;

    // AppIcon.icns — overwrite every time so an upgraded version refreshes the asset.
    fs::write(resources_dir.join("AppIcon.icns"), APP_ICON_ICNS).context("writing AppIcon.icns")?;

    // The executable inside the bundle is a copy of the currently-running diskspace
    // binary. This makes the bundle self-contained and avoids depending on a
    // specific install path. Re-running `watch install` after a brew upgrade
    // refreshes this copy.
    let src_bin = std::env::current_exe().context("resolving current diskspace binary")?;
    let dst_bin = macos_dir.join(BUNDLE_EXECUTABLE);

    // Best-effort: replace existing binary atomically.
    if dst_bin.exists() {
        let _ = fs::remove_file(&dst_bin);
    }
    fs::copy(&src_bin, &dst_bin)
        .with_context(|| format!("copying {} -> {}", src_bin.display(), dst_bin.display()))?;
    set_executable(&dst_bin)?;

    // Sign the bundle so macOS Gatekeeper has something to validate.
    // Preference order:
    //   1. A "Developer ID Application" identity from the keychain (best —
    //      preserves the inner binary's notarized signature and gives the
    //      bundle a real, attributable signature). This applies on the
    //      developer's machine and on any other Mac that happens to have a
    //      Developer ID cert installed.
    //   2. Ad-hoc fallback when no Developer ID identity is available
    //      (the case on most end-user machines). Ad-hoc is valid but
    //      Gatekeeper will still reject the bundle for interactive
    //      launches — launchd doesn't care, which is what we need.
    let _ = sign_bundle(&bundle_root);

    Ok(dst_bin)
}

/// Sign the bundle. Prefers Developer ID Application from the keychain,
/// falls back to ad-hoc. Best-effort; signature failures aren't fatal because
/// launchd will still run the agent regardless.
fn sign_bundle(bundle: &Path) -> Result<()> {
    if let Some(identity) = find_developer_id_identity() {
        // Use the Developer ID cert. Notably we do NOT pass `--deep` here,
        // so the inner Mach-O's existing Developer ID + notarized signature
        // is left intact. codesign only seals the bundle wrapper
        // (Info.plist + Resources + a CodeResources file that records the
        // inner binary's existing signature hash).
        let output = Command::new("codesign")
            .args([
                "--force",
                "--options",
                "runtime",
                "--timestamp",
                "--sign",
                &identity,
            ])
            .arg(bundle)
            .output()
            .context("running codesign with Developer ID")?;
        if output.status.success() {
            return Ok(());
        }
        // If Developer ID signing failed (e.g. timestamp server timeout, or
        // the inner binary's identifier conflicts) fall through to ad-hoc.
        eprintln!(
            "  note: Developer ID signing failed, falling back to ad-hoc: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    adhoc_sign(bundle)
}

/// Returns the full SecIdentity name of the first "Developer ID Application"
/// cert in the user's codesigning keychain, if any.
fn find_developer_id_identity() -> Option<String> {
    let output = Command::new("security")
        .args(["find-identity", "-v", "-p", "codesigning"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Each line looks like:
    //   `  1) <HASH> "Developer ID Application: Xoder PR LLC (RST67A4A6S)"`
    // We want the quoted string for the first line containing
    // "Developer ID Application:".
    for line in stdout.lines() {
        if !line.contains("Developer ID Application:") {
            continue;
        }
        let first = line.find('"')?;
        let last = line.rfind('"')?;
        if last > first {
            return Some(line[first + 1..last].to_string());
        }
    }
    None
}

fn adhoc_sign(bundle: &Path) -> Result<()> {
    let output = Command::new("codesign")
        .args(["--force", "--deep", "--sign", "-"])
        .arg(bundle)
        .output()
        .context("running codesign --sign -")?;
    if !output.status.success() {
        anyhow::bail!(
            "codesign ad-hoc failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Remove the bundle if it exists. Best-effort.
pub fn remove_bundle() -> Result<()> {
    let bundle_root = bundle_root_path()?;
    if bundle_root.exists() {
        fs::remove_dir_all(&bundle_root)
            .with_context(|| format!("removing bundle at {}", bundle_root.display()))?;
    }
    Ok(())
}

pub fn bundle_root_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("diskspace")
        .join(BUNDLE_NAME))
}

fn info_plist_xml() -> String {
    let version = env!("CARGO_PKG_VERSION");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>diskspace watch</string>
    <key>CFBundleExecutable</key>
    <string>{exe}</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>{id}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>diskspace watch</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>{ver}</string>
    <key>CFBundleVersion</key>
    <string>{ver}</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.utilities</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © Xoder PR LLC</string>
</dict>
</plist>
"#,
        exe = BUNDLE_EXECUTABLE,
        id = BUNDLE_IDENTIFIER,
        ver = version,
    )
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

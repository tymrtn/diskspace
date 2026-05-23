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

    // Ad-hoc sign the whole bundle. Without this, the bundle has no
    // _CodeSignature/CodeResources sealing Info.plist + Resources to the
    // binary, and macOS Gatekeeper throws "DiskspaceWatch.app is damaged"
    // when anything tries to launch it interactively. Ad-hoc signing ("-"
    // identity) gives the bundle a valid local signature without needing
    // the Developer ID cert on the user's machine. --deep replaces the
    // inner binary's signature so it's bound to the bundle.
    let _ = adhoc_sign(&bundle_root);

    Ok(dst_bin)
}

fn adhoc_sign(bundle: &Path) -> Result<()> {
    let output = Command::new("codesign")
        .args(["--force", "--deep", "--sign", "-"])
        .arg(bundle)
        .output()
        .context("running codesign")?;
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

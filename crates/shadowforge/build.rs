//! Build script: embeds git SHA and checks pdfium availability.
//!
//! Sets `SHADOWFORGE_GIT_SHA` at compile time (`cargo:rustc-env=...`) so
//! `shadowforge --version` can report `<crate-version> (<sha>)`. The commit
//! is what distinguishes two builds of the same version.
//!
//! Provenance is best-effort: a source tarball has no `.git`, and some
//! minimal environments have no `git` binary. Both fall back to `"unknown"`
//! rather than failing the build, because a build that refuses to produce a
//! binary is worse than a binary that cannot name its commit.

use std::env;
use std::path::Path;
use std::process::Command;

/// Recorded when the commit cannot be determined.
const UNKNOWN: &str = "unknown";

fn main() {
    emit_git_sha();

    // CARGO_FEATURE_PDF is set by Cargo when the `pdf` feature is enabled.
    // cfg!(feature = ...) does not reflect enabled features in build scripts.
    if env::var("CARGO_FEATURE_PDF").is_ok() {
        check_pdfium_availability();
    }
}

/// Embed the current commit SHA, or `"unknown"` when it cannot be determined.
fn emit_git_sha() {
    // Re-run this script when HEAD moves, when the ref it points at advances,
    // or when the index changes, so a rebuild picks up the new SHA rather
    // than reusing a cached one.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    // The dirty check depends on unstaged edits anywhere in the tree, which
    // touch no single well-known path. Watching a path that never exists
    // makes cargo treat it as always-changed, forcing a rerun so the dirty
    // marker never goes stale between real commits.
    println!("cargo:rerun-if-changed=../../.git/SHADOWFORGE_FORCE_RERUN");
    // Cargo does not re-run a build script when only its environment changes,
    // so a build that reuses a cached layer would keep baking in the commit
    // of the earlier build.
    println!("cargo:rerun-if-env-changed=SHADOWFORGE_GIT_SHA_OVERRIDE");

    let sha = env::var("SHADOWFORGE_GIT_SHA_OVERRIDE")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            git_short_sha().map(|sha| {
                if git_is_dirty() {
                    format!("{sha}-dirty")
                } else {
                    sha
                }
            })
        })
        .unwrap_or_else(|| UNKNOWN.to_owned());

    println!("cargo:rustc-env=SHADOWFORGE_GIT_SHA={sha}");
}

/// Run `git rev-parse --short=12 HEAD` and return the trimmed SHA.
///
/// Returns `None` (never panics) on any failure: `git` missing from `PATH`,
/// non-zero exit status, or non-UTF-8 output.
fn git_short_sha() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8(output.stdout).ok()?;
    let trimmed = sha.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Whether the working tree has uncommitted changes anywhere in the repo.
///
/// Scoped to the whole repo, not just this crate's directory, because
/// `HEAD`'s tree hash covers the whole repo — a change in an unrelated
/// crate still means the SHA alone does not describe the tree that was
/// actually compiled. Returns `false` (never panics) on any failure: with no
/// resolvable `git`, there is nothing to compare against anyway.
fn git_is_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| !output.stdout.is_empty())
}

/// Check if the pdfium shared library is findable; emit a warning only when it is not.
fn check_pdfium_availability() {
    // Re-run this check whenever the user changes the override variable or build target.
    println!("cargo:rerun-if-env-changed=PDFIUM_DYNAMIC_LIB_PATH");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");

    let env_var = "PDFIUM_DYNAMIC_LIB_PATH";
    if let Some(custom_path_os) = env::var_os(env_var) {
        // User explicitly configured the path — validate it contains the pdfium library.
        // Use var_os to accept any valid filesystem path, not just valid UTF-8.
        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        let lib_name: &str = if target_os == "macos" {
            "libpdfium.dylib"
        } else if target_os == "windows" {
            "pdfium.dll"
        } else {
            "libpdfium.so"
        };
        let custom_path_obj = Path::new(&custom_path_os);
        let lib_found = if custom_path_obj.is_dir() {
            custom_path_obj.join(lib_name).exists()
        } else {
            custom_path_obj.exists()
        };
        if !lib_found {
            let display = custom_path_os.to_string_lossy();
            println!(
                "cargo:warning=PDFIUM_DYNAMIC_LIB_PATH='{display}' does not contain {lib_name}. PDF rasterisation will fail at runtime."
            );
        }
        return;
    }

    // Platform-specific library filename for the build target.
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let lib_name: &str = if target_os == "macos" {
        "libpdfium.dylib"
    } else if target_os == "windows" {
        "pdfium.dll"
    } else {
        "libpdfium.so"
    };

    // Standard installation directories per platform.
    let search_dirs: &[&str] = if target_os == "windows" {
        &[
            "C:\\Program Files\\pdfium\\lib",
            "C:\\Program Files (x86)\\pdfium\\lib",
        ]
    } else if target_os == "macos" {
        &[
            "/opt/homebrew/lib",
            "/opt/local/lib",
            "/usr/local/lib",
            "/usr/lib",
        ]
    } else {
        &[
            "/usr/local/lib",
            "/usr/lib",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
        ]
    };

    for dir in search_dirs {
        if Path::new(dir).join(lib_name).exists() {
            // Found in a standard location — no noise.
            return;
        }
    }

    // Not found in any standard location — emit setup instructions.
    println!(
        "cargo:warning=pdfium library ({lib_name}) not found. PDF rasterisation will be unavailable unless pdfium is discoverable via system library paths."
    );
    println!("cargo:warning=");
    println!("cargo:warning=To set up pdfium:");
    println!(
        "cargo:warning=  macOS:   Download from https://github.com/bblanchon/pdfium-binaries/"
    );
    println!(
        "cargo:warning=           Extract and set: export PDFIUM_DYNAMIC_LIB_PATH=/path/to/lib"
    );
    println!(
        "cargo:warning=  Linux:   Download from https://github.com/bblanchon/pdfium-binaries/ or build from source"
    );
    println!(
        "cargo:warning=  Windows: Download from https://github.com/bblanchon/pdfium-binaries/"
    );
    println!("cargo:warning=");
    println!(
        "cargo:warning=Or disable only PDF: cargo build --no-default-features --features corpus,adaptive"
    );
}

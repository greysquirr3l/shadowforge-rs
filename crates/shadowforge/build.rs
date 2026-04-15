//! Build script: embeds git SHA, commit timestamp, and checks pdfium availability.
use std::env;
use std::path::Path;
use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    EmitBuilder::builder()
        .git_sha(false)
        .git_commit_timestamp()
        .emit()?;

    // CARGO_FEATURE_PDF is set by Cargo when the `pdf` feature is enabled.
    // cfg!(feature = ...) does not reflect enabled features in build scripts.
    if env::var("CARGO_FEATURE_PDF").is_ok() {
        check_pdfium_availability();
    }

    Ok(())
}

/// Check if the pdfium shared library is findable; emit a warning only when it is not.
fn check_pdfium_availability() {
    // Re-run this check whenever the user changes the override variable.
    println!("cargo:rerun-if-env-changed=PDFIUM_DYNAMIC_LIB_PATH");

    let env_var = "PDFIUM_DYNAMIC_LIB_PATH";
    if let Ok(custom_path) = env::var(env_var) {
        // User explicitly configured the path — only warn if it does not exist.
        if !Path::new(&custom_path).exists() {
            println!(
                "cargo:warning=PDFIUM_DYNAMIC_LIB_PATH is set to '{custom_path}' but the path does not exist."
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
        "cargo:warning=pdfium library ({lib_name}) not found. PDF features will fail at runtime."
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
    println!("cargo:warning=Or disable PDF: cargo build --no-default-features");
}

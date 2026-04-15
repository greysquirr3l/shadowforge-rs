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
    println!("cargo:warning=Or disable only PDF: cargo build --no-default-features --features corpus,adaptive");
}

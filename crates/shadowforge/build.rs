//! Build script: embeds git SHA, commit timestamp, and checks pdfium availability.
use std::env;
use std::path::Path;
use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    EmitBuilder::builder()
        .git_sha(false)
        .git_commit_timestamp()
        .emit()?;

    // Check if PDF feature is enabled
    if cfg!(feature = "pdf") {
        check_pdfium_availability();
    }

    Ok(())
}

/// Check if pdfium is available; emit helpful message if not.
fn check_pdfium_availability() {
    let pdfium_paths = vec![
        // macOS homebrew (custom install)
        "/opt/homebrew/lib",
        "/usr/local/lib",
        // Linux
        "/usr/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        // Windows
        "C:\\Program Files\\pdfium\\lib",
        "C:\\Program Files (x86)\\pdfium\\lib",
    ];

    let env_var = "PDFIUM_DYNAMIC_LIB_PATH";
    if let Ok(custom_path) = env::var(env_var)
        && Path::new(&custom_path).exists()
    {
        println!("cargo:warning=pdfium detected at {custom_path}");
        return;
    }

    // Check standard paths
    for path in &pdfium_paths {
        if Path::new(path).exists() {
            println!("cargo:warning=pdfium auto-detected at {path}");
            println!("cargo:warning=Set PDFIUM_DYNAMIC_LIB_PATH={path} to use it explicitly");
            return;
        }
    }

    // Not found — emit instructions
    println!("cargo:warning=pdfium library not found. PDF features will fail at runtime.");
    println!("cargo:warning=");
    println!("cargo:warning=To set up pdfium:");
    println!("cargo:warning=  macOS:   Download from https://pdfium.googlesource.com/");
    println!(
        "cargo:warning=           Extract and set: export PDFIUM_DYNAMIC_LIB_PATH=/path/to/lib"
    );
    println!("cargo:warning=  Linux:   apt install libpdfium (if available) or build from source");
    println!("cargo:warning=  Windows: Download prebuilt or build from source");
    println!("cargo:warning=");
    println!("cargo:warning=Or disable PDF: cargo build --no-default-features");
}

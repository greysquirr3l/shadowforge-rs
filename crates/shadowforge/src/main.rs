//! shadowforge — quantum-resistant steganography toolkit.

fn main() {
    if let Err(e) = shadowforge_lib::interface::runner::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

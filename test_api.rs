// Temporary test file to verify API
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() {
    // Test which methods work
    let _rng = ChaCha20Rng::from_entropy();
    println!("Success!");
}

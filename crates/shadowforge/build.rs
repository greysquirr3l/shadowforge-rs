//! Build script: embeds git SHA and commit timestamp via vergen.
use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    EmitBuilder::builder()
        .git_sha(false)
        .git_commit_timestamp()
        .emit()?;
    Ok(())
}

use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    EmitBuilder::builder()
        .git_sha(false) // full SHA, not short
        .git_commit_timestamp()
        .emit()?;
    Ok(())
}

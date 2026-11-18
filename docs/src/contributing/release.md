# Release Process

A release publishes a binary archive for six platforms and the `shadowforge`
crate on crates.io. The release workflow does the work; this page describes
what has to be true before it is allowed to.

## What a Release Requires

Four places carry the version, and all of them have to agree:

| Where | File |
|-------|------|
| The published crate | `crates/shadowforge/Cargo.toml` |
| The recorded version | `VERSION` |
| The changelog | `CHANGELOG.md`, as a `## [x.y.z]` section |
| The git tag | `vX.Y.Z` |

The check is a single command, and it is what both CI and the release
workflow run:

```bash
python3 scripts/release.py check
python3 scripts/release.py check --tag v0.4.0   # additionally checks the tag
```

CI runs the first form on every pull request, so version drift is caught
before it can reach a tag. The release workflow runs the second form before
it builds anything: a mismatch fails the workflow instead of publishing an
artifact labelled with the wrong version.

## Cutting a Release

1. **Move the changelog.** Replace the body of `## [Unreleased]` with a
   section for the new version, dated, and leave an empty `## [Unreleased]`
   above it:

   ```markdown
   ## [Unreleased]

   ## [0.4.0] — 2026-11-17
   ```

   Add the compare link at the bottom of the file and update the
   `[Unreleased]` link to compare against the new tag.

2. **Bump the version** in `crates/shadowforge/Cargo.toml` and `VERSION`.
   The `VERSION` file holds the bare version with no trailing newline.

3. **Check the changelog section exists** for the version being released.
   The release notes published on GitHub are taken from it verbatim, so a
   missing section means an empty release page.

4. **Run the full check suite:**

   ```bash
   make check
   ```

5. **Commit and tag:**

   ```bash
   git commit -am "release: v0.4.0"
   git tag -a v0.4.0 -m "v0.4.0"
   git push origin main --tags
   ```

## What the Workflow Does

Pushing the tag triggers `.github/workflows/release.yml`:

1. **Verify** — the tag, the crate version, the `VERSION` file and the
   changelog are checked against each other.
2. **Build** — six targets are built in parallel (Linux x86-64 and arm64,
   macOS x86-64 and arm64, Windows x86-64 and arm64), each with shell
   completions and the pdfium runtime bundled, then packaged as an archive.
3. **Release** — the archives are collected into a single GitHub release
   with a `SHA256SUMS` file over every archive and the changelog section
   as the release notes.
4. **Publish** — the crate is published to crates.io, skipped if that
   version is already there.

A pull request against `main` runs the same build as a dry run, without
uploading or publishing anything.

## Verifying a Download

Each release carries a `SHA256SUMS` file covering every archive:

```bash
sha256sum -c SHA256SUMS
```

## Choosing a Version

The project is pre-1.0, so the minor number carries breaking changes:

- **Patch** (`0.3.7` → `0.3.8`) — fixes that keep existing payloads
  readable.
- **Minor** (`0.3.7` → `0.4.0`) — a change to an on-disk format, or a
  fix that changes what an existing technique produces.

A change to the payload format of a technique is a minor bump even though
it is a fix: documents written by the previous version cannot be read by
the new one. `0.4.0` is the first such bump — the PDF content-stream
technique gained a length prefix, so payloads embedded with `0.3.x` need
extracting before the upgrade.

## Prereleases

A tag containing `alpha`, `beta` or `rc` publishes as a GitHub prerelease
and skips the crates.io publish. The version in `Cargo.toml` must still
match the tag, including any suffix, and the changelog needs a section
with that exact version.

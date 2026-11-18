#!/usr/bin/env python3
"""Version and changelog checks for the release workflow.

The release publishes a binary archive and a crates.io package, and both
carry the version number. Nothing enforces that the tag being released, the
version in `Cargo.toml`, the version in the `VERSION` file and the
changelog section all agree — a mismatch used to be discoverable only by
downloading the artifact and looking at it.

Two commands:

    release.py check [--tag v0.4.0]
        Verify the versions agree. With `--tag`, also verify the tag
        matches and that the changelog has a section for the version.

    release.py notes <version>
        Print the changelog section for a version, for use as the release
        notes.

Exits non-zero with a diagnostic on any problem.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
VERSION_FILE = ROOT / "VERSION"
CARGO_TOML = ROOT / "crates" / "shadowforge" / "Cargo.toml"

VERSION_HEADING = re.compile(r"^##\s*\[([^\]]+)\]")


def crate_version() -> str:
    """The version declared by the published crate."""
    text = CARGO_TOML.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if match is None:
        raise SystemExit(f"error: no version found in {CARGO_TOML}")
    return match.group(1)


def version_file() -> str:
    """The version recorded in the `VERSION` file."""
    return VERSION_FILE.read_text(encoding="utf-8").strip()


def changelog_section(version: str) -> str | None:
    """The body of the changelog section for `version`, or None if absent."""
    lines = CHANGELOG.read_text(encoding="utf-8").splitlines()

    start: int | None = None
    for index, line in enumerate(lines):
        heading = VERSION_HEADING.match(line)
        if heading is not None and heading.group(1) == version:
            start = index
            break
    if start is None:
        return None

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("## "):
            end = index
            break

    body = "\n".join(lines[start + 1 : end]).strip()
    return body or None


def check(tag: str | None) -> int:
    """Verify the versions agree. Returns a process exit code."""
    problems: list[str] = []

    crate = crate_version()
    recorded = version_file()

    if crate != recorded:
        problems.append(
            f"crate version {crate} does not match the VERSION file ({recorded})"
        )

    if tag is not None:
        tagged = tag[1:] if tag.startswith("v") else tag
        if tagged != crate:
            problems.append(f"tag {tag} does not match the crate version {crate}")
        if changelog_section(crate) is None:
            problems.append(
                f"CHANGELOG.md has no section for {crate}; add one before releasing"
            )

    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    if problems:
        return 1

    target = tag if tag else crate
    print(f"version {crate} is consistent (release: {target})")
    return 0


def notes(version: str) -> int:
    """Print the changelog section for `version`."""
    section = changelog_section(version)
    if section is None:
        print(f"error: CHANGELOG.md has no section for {version}", file=sys.stderr)
        return 1
    print(section)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="verify the versions agree")
    check_parser.add_argument("--tag", help="the release tag, e.g. v0.4.0")

    notes_parser = subparsers.add_parser("notes", help="print a changelog section")
    notes_parser.add_argument("version", help="version, e.g. 0.4.0")

    subparsers.add_parser("version", help="print the crate version")

    args = parser.parse_args()

    if args.command == "check":
        return check(args.tag)
    if args.command == "version":
        print(crate_version())
        return 0
    return notes(args.version)


if __name__ == "__main__":
    raise SystemExit(main())

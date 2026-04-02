#!/usr/bin/env python3
"""
Check cargo-tarpaulin Cobertura XML output against coverage thresholds.

Usage:
    python3 scripts/check_coverage.py coverage/cobertura.xml \
        --overall 85 \
        --module "domain::crypto" 90

Exit codes:
    0  — all thresholds met
    1  — one or more thresholds missed (prints details)
"""

import argparse
import sys
import xml.etree.ElementTree as ET


def line_rate_to_pct(rate: str) -> float:
    return float(rate) * 100.0


def parse_args():
    p = argparse.ArgumentParser(description="Coverage threshold checker")
    p.add_argument("xml", help="Path to Cobertura XML file")
    p.add_argument("--overall", type=float, default=85.0,
                   help="Minimum overall line coverage %% (default: 85)")
    p.add_argument("--module", nargs=2, action="append", metavar=("MODULE", "PCT"),
                   default=[], help="Module-specific threshold: --module path::prefix 90")
    return p.parse_args()


def main():
    args = parse_args()
    tree = ET.parse(args.xml)
    root = tree.getroot()

    failures = []

    # Overall coverage
    overall_rate = root.attrib.get("line-rate", "0")
    overall_pct = line_rate_to_pct(overall_rate)
    print(f"Overall coverage: {overall_pct:.1f}% (threshold: {args.overall}%)")
    if overall_pct < args.overall:
        failures.append(
            f"  FAIL overall: {overall_pct:.1f}% < {args.overall}%"
        )

    # Per-module thresholds
    module_thresholds = {mod: float(pct) for mod, pct in args.module}

    if module_thresholds:
        # Build a map: package name → line-rate
        pkg_coverage: dict[str, tuple[int, int]] = {}
        for pkg in root.iter("package"):
            name = pkg.attrib.get("name", "")
            lines_valid = int(pkg.attrib.get("lines-valid", "0"))
            lines_covered = int(pkg.attrib.get("lines-covered", "0"))
            pkg_coverage[name] = (lines_covered, lines_valid)

        for mod_prefix, threshold in module_thresholds.items():
            # Aggregate all packages whose name starts with the prefix
            # (tarpaulin uses :: separators in package names)
            total_valid = 0
            total_covered = 0
            for pkg_name, (covered, valid) in pkg_coverage.items():
                normalised = pkg_name.replace("/", "::").replace("-", "_")
                if normalised.startswith(mod_prefix.replace("-", "_")):
                    total_valid += valid
                    total_covered += covered

            if total_valid == 0:
                print(f"  WARN {mod_prefix}: no lines found — check module name")
                continue

            mod_pct = (total_covered / total_valid) * 100.0
            status = "OK  " if mod_pct >= threshold else "FAIL"
            print(f"  {status} {mod_prefix}: {mod_pct:.1f}% (threshold: {threshold}%)")
            if mod_pct < threshold:
                failures.append(
                    f"  FAIL {mod_prefix}: {mod_pct:.1f}% < {threshold}%"
                )

    if failures:
        print("\nCoverage thresholds NOT met:")
        for f in failures:
            print(f)
        sys.exit(1)
    else:
        print("\nAll coverage thresholds met.")
        sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : scripts/rsd-bump-version.py
# Purpose : Bump the central software version (VERSION) and open the CHANGELOG entry
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Single entry point for changing the Remote Shutdown version.

``VERSION`` (repository root) is the only place the version is written; every consumer reads
it: ``rsd_master.__version__`` (API ``/api/me``, console footer, discovery answer), the Go
agent (``-X main.version`` at link time), the Debian control files, the MSI ProductVersion
and the macOS pkg.

The script validates Semantic Versioning, refuses to go backwards, and moves the CHANGELOG
``[Unreleased]`` section (Keep a Changelog 1.1.0) under a dated ``[x.y.z]`` heading.

Usage::

    scripts/rsd-bump-version.py patch|minor|major      # 0.2.0 -> 0.2.1 / 0.3.0 / 1.0.0
    scripts/rsd-bump-version.py 1.0.0-rc.1             # explicit version
    scripts/rsd-bump-version.py --show                 # print the current version
    scripts/rsd-bump-version.py minor --dry-run        # show what would change

Exit codes: 0 success, 2 usage error / invalid version, 5 version not greater than the current
one, 4 VERSION or CHANGELOG file missing.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "VERSION"
CHANGELOG = ROOT / "CHANGELOG.md"
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$")

E_USAGE, E_DEPS, E_CONFIG = 2, 4, 5


def parse(version: str) -> tuple[int, int, int, str]:
    """Split a SemVer string into ``(major, minor, patch, prerelease)``.

    Raises:
        ValueError: when the string is not ``MAJOR.MINOR.PATCH[-pre]``.
    """
    m = SEMVER.match(version)
    if not m:
        raise ValueError(f"not a semantic version: {version!r}")
    return int(m[1]), int(m[2]), int(m[3]), m[4] or ""


def sort_key(version: str) -> tuple:
    """Ordering key: a pre-release sorts before its release (1.0.0-rc.1 < 1.0.0)."""
    major, minor, patch, pre = parse(version)
    return major, minor, patch, pre == "", pre


def next_version(current: str, part: str) -> str:
    """Compute the version after ``current`` for ``part`` (major/minor/patch) or an explicit value."""
    major, minor, patch, pre = parse(current)
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    if part == "patch":
        return f"{major}.{minor}.{patch}" if pre else f"{major}.{minor}.{patch + 1}"
    parse(part)
    return part


def roll_changelog(text: str, version: str, today: str) -> str:
    """Rename ``## [Unreleased]`` to ``## [version] - today`` and open a fresh Unreleased section."""
    if f"## [{version}]" in text:
        raise ValueError(f"CHANGELOG already has a [{version}] section")
    if "## [Unreleased]" not in text:
        raise ValueError("CHANGELOG has no [Unreleased] section")
    text = text.replace("## [Unreleased]", f"## [Unreleased]\n\n## [{version}] - {today}", 1)
    return roll_links(text, version)


def roll_links(text: str, version: str) -> str:
    """Point the ``[Unreleased]`` compare link at ``v<version>`` and add the ``[version]`` link."""
    m = re.search(r"^\[Unreleased\]: (?P<base>\S+)/compare/(?P<prev>v\S+)\.\.\.HEAD$", text, re.M)
    if not m:
        return text
    base, prev = m["base"], m["prev"]
    return text.replace(m[0], f"[Unreleased]: {base}/compare/v{version}...HEAD\n"
                              f"[{version}]: {base}/compare/{prev}...v{version}", 1)


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point; returns the process exit code."""
    ap = argparse.ArgumentParser(description="Bump the central Remote Shutdown version (VERSION).")
    ap.add_argument("part", nargs="?", help="major | minor | patch | explicit X.Y.Z[-pre]")
    ap.add_argument("--show", action="store_true", help="print the current version and exit")
    ap.add_argument("--dry-run", action="store_true", help="show the change without writing")
    ap.add_argument("--no-changelog", action="store_true", help="do not touch CHANGELOG.md")
    args = ap.parse_args(argv)

    if not VERSION_FILE.is_file():
        print(f"error: {VERSION_FILE} not found", file=sys.stderr)
        return E_DEPS
    current = VERSION_FILE.read_text(encoding="utf-8").strip()
    if args.show or not args.part:
        print(current)
        return 0 if args.show else E_USAGE
    try:
        new = next_version(current, args.part)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return E_USAGE
    if sort_key(new) <= sort_key(current):
        print(f"error: {new} is not greater than the current version {current}", file=sys.stderr)
        return E_CONFIG

    changelog = None
    if not args.no_changelog:
        if not CHANGELOG.is_file():
            print(f"error: {CHANGELOG} not found (or use --no-changelog)", file=sys.stderr)
            return E_DEPS
        try:
            changelog = roll_changelog(CHANGELOG.read_text(encoding="utf-8"), new, date.today().isoformat())
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return E_CONFIG

    print(f"{current} -> {new}{' (dry run)' if args.dry_run else ''}")
    if args.dry_run:
        return 0
    VERSION_FILE.write_text(new + "\n", encoding="utf-8")
    if changelog is not None:
        CHANGELOG.write_text(changelog, encoding="utf-8")
    print("Next: fill the CHANGELOG entry, rebuild the packages (make packages), then tag v" + new)
    return 0


if __name__ == "__main__":
    sys.exit(main())

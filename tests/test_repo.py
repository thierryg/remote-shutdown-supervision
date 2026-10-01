# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : tests/test_repo.py
# Purpose : Repository rules: i18n completeness, file headers, script conventions, version source
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Checks of the standing rules of AGENTS.md that a machine can verify."""

import json
import re
import subprocess

from conftest import ROOT

STATIC = ROOT / "master" / "rsd_master" / "static"
LOCALES = ["en-US", "fr", "es", "nl", "de", "it", "ru", "zh", "id", "ko", "ja", "th"]


def test_every_locale_has_exactly_the_reference_keys():
    reference = json.loads((STATIC / "i18n" / "en-US.json").read_text(encoding="utf-8"))
    for code in LOCALES:
        data = json.loads((STATIC / "i18n" / f"{code}.json").read_text(encoding="utf-8"))
        assert set(data) == set(reference), code
        for key, text in reference.items():
            assert set(re.findall(r"\{\w+\}", text)) == set(re.findall(r"\{\w+\}", data[key])), (code, key)


def test_every_used_key_exists():
    reference = json.loads((STATIC / "i18n" / "en-US.json").read_text(encoding="utf-8"))
    used = set(re.findall(r'data-i18n="([^"]+)"', (STATIC / "index.html").read_text(encoding="utf-8")))
    used |= set(re.findall(r"\bt\('([a-z_.]+)'", (STATIC / "app.js").read_text(encoding="utf-8")))
    for py in (ROOT / "master" / "rsd_master").glob("*.py"):
        used |= set(re.findall(r'"(error\.[a-z_]+)"', py.read_text(encoding="utf-8")))
    assert not used - set(reference)


def test_console_is_csp_safe():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "style=" not in html and "onclick=" not in html
    assert re.findall(r"<script[^>]*>", html) == ['<script src="/static/app.js">']
    assert not re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|eval\(", (STATIC / "app.js").read_text(encoding="utf-8"))


def source_files():
    """Every hand-written source file that must carry the standard header."""
    patterns = ["master/rsd_master/*.py", "master/rsd_master/static/*.js", "master/rsd_master/static/*.css",
                "master/rsd_master/static/*.html", "agent/*.go", "scripts/*.sh", "scripts/*.py", "scripts/lib/*.sh",
                "tests/*.py", "packaging/**/*.service", "packaging/**/*.wxs", "packaging/**/*.plist",
                "packaging/**/*.xml", "packaging/**/*.timer", "packaging/**/*.spec", "packaging/debian/*/post*", "packaging/debian/*/prerm",
                "Makefile", ".github/workflows/*.yml", ".github/*.yml", ".dockerignore", "*.md", "tests/browser/*.py",
                "docker/*.sh", "docker/Dockerfile.*", "docker/*.yml", "deploy/**/*.md", "deploy/motd/rsd-motd",
                "deploy/motd/10-rsd-master", "deploy/ansible/*.yml", "deploy/ansible/*.cfg", "deploy/ansible/*.sh",
                "deploy/ansible/.ansible-lint", "deploy/ansible/.yamllint", "deploy/ansible/group_vars/**/*.yml",
                "deploy/ansible/inventory/*.yml", "deploy/ansible/roles/**/*.yml", "deploy/ansible/roles/**/*.j2",
                "deploy/ansible/tests/*"]
    for pattern in patterns:
        for path in ROOT.glob(pattern):
            if "collections" not in path.parts and path.is_file():
                yield path


def test_every_source_file_has_the_header():
    missing = []
    for path in source_files():
        head = path.read_text(encoding="utf-8")[:1200]
        if "SPDX-License-Identifier: 0BSD" not in head or "Thierry Gayet <thierry.gayet@labworks.fr>" not in head:
            missing.append(str(path.relative_to(ROOT)))
    assert not missing


def test_scripts_follow_the_conventions():
    scripts = sorted((ROOT / "scripts").glob("*.sh")) + sorted((ROOT / "docker").glob("rsd-*.sh")) + [
        ROOT / "deploy/ansible/rsd-deploy.sh", ROOT / "deploy/ansible/tests/rsd-container-test.sh"]
    for script in scripts:
        if script.name == "rsd-docker-common.sh":  # sourced library, not a command
            continue
        assert script.name.startswith("rsd-"), script.name
        text = script.read_text(encoding="utf-8")
        assert 'main "$@"' in text and "rsd-" in text and "Exit codes:" in text, script.name
        result = subprocess.run([str(script), "--help"], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0 and "Usage:" in result.stdout, script.name
        result = subprocess.run([str(script), "--bogus"], capture_output=True, text=True, timeout=30)
        assert result.returncode == 2, script.name


def test_version_has_a_single_source():
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?", version)
    assert f"## [{version}]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for path in list((ROOT / "master").rglob("*.py")) + list((ROOT / "agent").glob("*.go")):
        # Whole version only (an address such as 192.0.2.1 is not the version 0.2.1).
        assert not re.search(rf"(?<![0-9.]){re.escape(version)}(?![0-9.])", path.read_text(encoding="utf-8")), path

# =============================================================================
# Remote Shutdown - LAN parental control and machine management (master/agent)
# -----------------------------------------------------------------------------
# File    : tests/browser/ui_check.py
# Purpose : Real-browser check of the console (Playwright + Chrome) against a master and a live agent
# Author  : Thierry Gayet <thierry.gayet@labworks.fr>
# Project : remote-shutdown (version: VERSION)
# Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
# =============================================================================
"""Drive the web console in Google Chrome like an administrator would.

Starts a temporary master (``--python``: an interpreter with the master dependencies) and a
real agent built from ``agent/`` (dry run, no popup), then: login with the default account,
forced password change, machine UP with its uptime, per-machine limit, shutdown order with
countdown then cancel, token creation with the three OS commands, settings, audit chain, a
second locale. Fails on any page error or CSP violation. Screenshots go to a temporary
directory (printed). Not collected by pytest: run it with ``make ui-check``.

Exit codes: 0 every check passed, 1 a check failed, 4 prerequisite missing (Go, Chrome).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
WEB, AGENT = 38443, 38444
PASSWORD = "Une-Phrase-Secrete-2026"


def start(python: str, work: Path):
    """Start the master and an enrolled agent; return both processes."""
    env = dict(os.environ, RSD__PATHS__DATA_DIR=str(work / "master"), RSD__SERVER__WEB_PORT=str(WEB),
               RSD__SERVER__AGENT_PORT=str(AGENT), RSD__SERVER__DISCOVERY_ENABLED="no",
               RSD__LOG__LOG_JSON="false", PYTHONPATH=str(ROOT / "master"), RSD_CONFIG="/nonexistent.ini")
    master = subprocess.Popen([python, "-m", "rsd_master", "serve"], env=env,
                              stdout=open(work / "master.log", "w"), stderr=subprocess.STDOUT)
    for _ in range(40):
        if (work / "master" / "pki" / "ca.crt").exists():
            break
        time.sleep(0.25)
    time.sleep(1)
    info = json.loads(subprocess.check_output([python, "-m", "rsd_master", "info"], env=env))
    token = subprocess.check_output([python, "-m", "rsd_master", "create-token"], env=env, text=True).strip()
    binary = work / "rsd-agent"
    subprocess.run(["go", "build", "-o", str(binary), "."], cwd=ROOT / "agent", check=True)
    config = work / "agent.json"
    config.write_text(json.dumps({"master": "127.0.0.1", "web_port": WEB, "agent_port": AGENT, "discovery_port": 0,
                                  "state_dir": str(work / "agent"), "dry_run": True}))
    aenv = dict(os.environ, PATH="/nonexistent", DISPLAY="", WAYLAND_DISPLAY="",
                DBUS_SESSION_BUS_ADDRESS="unix:path=/nonexistent")
    subprocess.run([str(binary), "--config", str(config), "enroll", "--token", token,
                    "--fingerprint", info["ca_fingerprint"]], check=True, env=aenv, capture_output=True)
    agent = subprocess.Popen([str(binary), "--config", str(config), "run"], env=aenv,
                             stdout=open(work / "agent.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(2)
    return master, agent


def check(work: Path) -> list:
    """Run the browser scenario; return the console errors (empty = clean)."""
    errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome")
        page = browser.new_page(ignore_https_errors=True, viewport={"width": 1280, "height": 800}, locale="fr-FR")
        page.on("console", lambda m: m.type == "error" and "401" not in m.text and errors.append(m.text))
        page.on("pageerror", lambda e: errors.append(str(e)))
        shot = lambda name: page.screenshot(path=str(work / f"{name}.png"), full_page=True)  # noqa: E731
        page.goto(f"https://127.0.0.1:{WEB}/")
        page.wait_for_selector("#login-form")
        assert page.text_content("#login-form button") == "Se connecter", "French locale not applied"
        shot("1-login")
        page.fill("input[name=username]", "admin")
        page.fill("input[name=password]", "admin")
        page.click("#login-form button")
        page.wait_for_selector("#page-password:not(.hidden)")
        assert page.is_visible("#password-forced"), "forced password change not shown"
        shot("2-password")
        page.fill("#password-form input[name=current]", "admin")
        page.fill("#password-form input[name=new]", PASSWORD)
        page.fill("#password-form input[name=repeat]", PASSWORD)
        page.click("#password-form button")
        page.wait_for_selector("#machines-body tr .badge.up", timeout=15000)
        shot("3-machines")
        page.click("#machines-body button.ghost")
        page.select_option("#edit-form select[name=limit_mode]", "custom")
        page.fill("#edit-form input[name=h]", "2")
        page.click("#edit-form button[value=ok]")
        # Locator assertions run in Playwright's utility world: the strict CSP forbids page-side eval.
        expect(page.locator("#machines-body")).to_contain_text("2 h 00")
        page.click("#machines-body button.danger")
        page.fill("#shutdown-form input[name=delay]", "900")
        page.click("#shutdown-form button[value=ok]")
        page.wait_for_selector("#machines-body .warn", timeout=10000)
        shot("4-pending")
        page.click("text=Annuler l'arrêt")
        page.wait_for_selector("#machines-body .warn", state="detached", timeout=10000)
        page.click(".tab[data-page=enroll]")
        page.fill("#token-form input[name=label]", "salon")
        page.click("#token-form button")
        page.wait_for_selector("#token-result:not(.hidden)")
        for pre in ("#cmd-linux", "#cmd-linux-rpm", "#cmd-macos", "#cmd-windows"):
            assert "--fingerprint" in page.text_content(pre) or "CA_FINGERPRINT=" in page.text_content(pre), pre
        shot("5-enroll")
        page.click(".tab[data-page=settings]")
        page.wait_for_selector("#settings-form input[name=warning_minutes]")
        shot("6-settings")
        page.click(".tab[data-page=audit]")
        page.wait_for_selector("#audit-chain.up")
        page.select_option("#lang", "ja")
        expect(page.locator(".tab[data-page=audit]")).to_have_text("監査")
        shot("7-audit-ja")
        browser.close()
    return errors


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--python", default=sys.executable, help="interpreter with the master dependencies")
    args = parser.parse_args()
    if not shutil.which("go"):
        print("ui_check: go is required to build the agent", file=sys.stderr)
        return 4
    work = Path(tempfile.mkdtemp(prefix="rsd-ui-"))
    master, agent = start(args.python, work)
    try:
        errors = check(work)
    except Exception as exc:  # noqa: BLE001 - report every failure the same way
        print(f"ui_check: FAILED: {exc} (logs and screenshots in {work})", file=sys.stderr)
        return 1
    finally:
        agent.terminate()
        master.terminate()
    if errors:
        print(f"ui_check: console errors: {errors}", file=sys.stderr)
        return 1
    print(f"ui_check: every check passed (screenshots in {work})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
scripts/maint_kickoff.py
Fills {{TOKENS}} in maintenance templates and writes ready-to-use files.
Run from repo root. No network calls. No external dependencies.

Usage:  python scripts/maint_kickoff.py
Output: maintenance/generated/YYYY_MM/RESEARCH_YYYY_MM.md
        maintenance/generated/YYYY_MM/EXECUTION_YYYY_MM.md
"""

import json
import re
from datetime import datetime
from pathlib import Path


def get_version() -> str:
    toml = Path("packages/aevum-core/pyproject.toml")
    if not toml.exists():
        return "unknown"
    for line in toml.read_text().splitlines():
        if line.strip().startswith("version ="):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def bump_patch(version: str) -> str:
    parts = version.split(".")
    if len(parts) == 3 and parts[-1].isdigit():
        return ".".join(parts[:-1] + [str(int(parts[-1]) + 1)])
    return f"{version}.1"


def load_state() -> dict:
    f = Path("maintenance/last_state.json")
    defaults = {
        "version": "unknown",
        "test_count": "unknown",
        "last_run_date": "never",
        "deferred": [],
    }
    if not f.exists():
        print("  NOTE: maintenance/last_state.json not found — using defaults.")
        return defaults
    return {**defaults, **json.loads(f.read_text())}


def load_scan_results() -> str:
    """Read the latest scan results committed by monthly-maintenance.yml."""
    f = Path("maintenance/scan_results.md")
    if not f.exists():
        return (
            "[ No scan_results.md found — trigger monthly-maintenance workflow first:\n"
            "  GitHub → Actions → monthly-maintenance → Run workflow ]"
        )
    return f.read_text().strip()


def fill(template: str, tokens: dict) -> str:
    """Replace all {{TOKEN}} placeholders with their values."""
    for k, v in tokens.items():
        template = template.replace(k, str(v))
    leftover = re.findall(r"\{\{[A-Z_]+\}\}", template)
    if leftover:
        print(f"  WARNING: unfilled tokens: {set(leftover)}")
    return template


def main() -> None:
    now = datetime.now()
    stamp = now.strftime("%Y_%m")
    version = get_version()
    state = load_state()
    deferred = state.get("deferred", [])

    tokens = {
        "{{GENERATED_TIMESTAMP}}": now.strftime("%Y-%m-%d %H:%M"),
        "{{MONTH_YEAR}}": now.strftime("%B %Y"),
        # e.g. 2026-05 — safe for git branch names
        "{{MONTH_YEAR_SLUG}}": now.strftime("%Y-%m"),
        "{{CURRENT_YEAR}}": str(now.year),
        "{{CURRENT_VERSION}}": version,
        "{{PATCH_VERSION}}": bump_patch(version),
        "{{LAST_TEST_COUNT}}": str(state.get("test_count", "unknown")),
        "{{LAST_RUN_DATE}}": state.get("last_run_date", "never"),
        "{{DEFERRED}}": ", ".join(deferred) if deferred else "none",
        "{{SCAN_RESULTS}}": load_scan_results(),
    }

    templates_dir = Path("maintenance/templates")
    out_dir = Path("maintenance/generated") / stamp
    out_dir.mkdir(parents=True, exist_ok=True)

    for name in ("RESEARCH.md", "EXECUTION.md"):
        src = templates_dir / name
        if not src.exists():
            print(f"  SKIP: {src} not found")
            continue
        dst = out_dir / f"{name.replace('.md', '')}_{stamp}.md"
        dst.write_text(fill(src.read_text(), tokens))
        print(f"  → {dst}")

    print(f"\n  Month: {now.strftime('%B %Y')} | Version: {version} | Patch: {bump_patch(version)}")
    print("\nNext:")
    print("  1. Trigger monthly-maintenance.yml in GitHub Actions (or check last run).")
    print(f"  2. Paste step summary into RESEARCH_{stamp}.md → open in Claude.")
    print(f"  3. Paste Research Report into EXECUTION_{stamp}.md → open in Claude Code.")


if __name__ == "__main__":
    main()

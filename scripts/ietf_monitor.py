#!/usr/bin/env python3
"""Poll IETF Datatracker for status changes on Aevum-relevant drafts.

Persists last-known status to scripts/ietf_monitor_state.json.
The workflow commits the state file back after each run to avoid
re-opening issues for unchanged statuses.
"""

import json
import os
import time
import urllib.request
from pathlib import Path
from urllib.error import URLError

WATCHED_DRAFTS: dict[str, dict[str, object]] = {
    "draft-ietf-scitt-architecture": {
        "note": "SCITT Transparency Services — when RFC: activate ScittTsBackend",
        "watch_for": ["RFC Published", "Publication Requested"],
    },
    "draft-ietf-scitt-scrapi": {
        "note": "SCITT ScrAPI — when RFC: implement ScittTsBackend fully",
        "watch_for": ["RFC Published", "Publication Requested", "Last Call"],
    },
    # draft-ietf-cose-tsa-tst-header-parameter published as RFC 9921 — the
    # per-entry receipt encoder already uses its assigned label 270 (CTT).
    # See aevum-publish/src/aevum/publish/encoder.py and
    # docs/adrs/adr-009-black-box-receipt-format.md.
    "draft-ietf-cose-merkle-tree-proofs": {
        "note": "COSE Merkle proofs — relevant for Tier 1 crash-protected receipts",
        "watch_for": ["RFC Published", "Last Call"],
    },
}

_DATATRACKER = "https://datatracker.ietf.org/api/v1/doc/document"
_GITHUB_API = "https://api.github.com"
_REPO = os.environ.get("GITHUB_REPOSITORY", "aevum-labs/aevum")
_TOKEN = os.environ.get("GITHUB_TOKEN", "")
_HEADERS = {
    "Authorization": f"Bearer {_TOKEN}",
    "User-Agent": "aevum-ietf-monitor/1",
    "Accept": "application/vnd.github+json",
}

_STATE_PATH = Path(__file__).parent / "ietf_monitor_state.json"


def _load_state() -> dict[str, str]:
    if _STATE_PATH.exists():
        try:
            return dict(json.loads(_STATE_PATH.read_text()))
        except (ValueError, KeyError):
            pass
    return {}


def _save_state(state: dict[str, str]) -> None:
    _STATE_PATH.write_text(json.dumps(state, indent=2) + "\n")


def _fetch_draft_status(draft_name: str) -> str | None:
    url = f"{_DATATRACKER}/{draft_name}/"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "aevum-ietf-monitor/1"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            data: dict[str, object] = json.loads(resp.read())
        status = data.get("iesg_state_summary") or data.get("std_level_summary")
        if isinstance(status, str):
            return status
    except (URLError, ValueError, KeyError):
        print(f"WARNING: could not fetch status for {draft_name}")
    return None


def _issue_exists(title: str) -> bool:
    url = (
        f"{_GITHUB_API}/repos/{_REPO}/issues"
        f"?state=open&labels=standards-update&per_page=100"
    )
    req = urllib.request.Request(url, headers=_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            issues: list[dict[str, object]] = json.loads(resp.read())
        return any(i.get("title") == title for i in issues)
    except (URLError, ValueError):
        return False


def _open_issue(title: str, body: str) -> None:
    url = f"{_GITHUB_API}/repos/{_REPO}/issues"
    payload = json.dumps(
        {"title": title, "body": body, "labels": ["standards-update"]}
    ).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={**_HEADERS, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15):  # noqa: S310
        pass
    print(f"Opened issue: {title}")


def main() -> None:
    state = _load_state()
    for draft_name, info in WATCHED_DRAFTS.items():
        time.sleep(1)  # respect Datatracker rate limits
        new_status = _fetch_draft_status(draft_name)
        if new_status is None:
            continue
        old_status = state.get(draft_name)
        state[draft_name] = new_status
        watch_for = info.get("watch_for", [])
        if not isinstance(watch_for, list):
            watch_for = []
        if new_status == old_status:
            print(f"OK: {draft_name} unchanged ({new_status})")
            continue
        if new_status not in watch_for and old_status is not None:
            print(f"INFO: {draft_name} changed to {new_status} (not in watch list)")
            continue
        title = f"IETF: {draft_name} status changed to {new_status}"
        if _issue_exists(title):
            print(f"Issue already exists: {title}")
            continue
        note = info.get("note", "")
        body = (
            f"**Draft:** `{draft_name}`\n"
            f"**Previous status:** {old_status or '(unknown)'}\n"
            f"**New status:** {new_status}\n\n"
            f"**Note:** {note}\n\n"
            f"**Datatracker:** https://datatracker.ietf.org/doc/{draft_name}/"
        )
        _open_issue(title, body)
    _save_state(state)


if __name__ == "__main__":
    main()

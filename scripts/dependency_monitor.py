#!/usr/bin/env python3
"""Poll PyPI for new major versions of critical Aevum dependencies.

Opens a GitHub issue when a major version increment is detected.
Idempotent: skips if an open issue with the same title already exists.
"""

import json
import os
import urllib.request
from urllib.error import URLError

WATCHED_PACKAGES: dict[str, str] = {
    "cedarpy": "4",
    "openai-agents": "0",
    "langgraph-checkpoint": "4",
    "google-adk": "1",
    "agent-framework": "1",
    "mcp": "1",
    "fastmcp": "2",
    "liboqs-python": "0",
}

_GITHUB_API = "https://api.github.com"
_REPO = os.environ.get("GITHUB_REPOSITORY", "aevum-labs/aevum")
_TOKEN = os.environ.get("GITHUB_TOKEN", "")
_HEADERS = {
    "Authorization": f"Bearer {_TOKEN}",
    "User-Agent": "aevum-dep-monitor/1",
    "Accept": "application/vnd.github+json",
}


def _fetch_latest_pypi_version(package: str) -> str | None:
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310
            data: dict[str, object] = json.loads(resp.read())
        info = data.get("info")
        if isinstance(info, dict):
            version = info.get("version")
            if isinstance(version, str):
                return version
    except (URLError, ValueError, KeyError):
        print(f"WARNING: could not fetch {package} from PyPI")
    return None


def _get_major(version: str) -> str:
    return version.split(".")[0]


def _issue_exists(title: str) -> bool:
    url = (
        f"{_GITHUB_API}/repos/{_REPO}/issues"
        f"?state=open&labels=upstream-major-bump&per_page=100"
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
        {"title": title, "body": body, "labels": ["upstream-major-bump"]}
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
    for package, tracked_major in WATCHED_PACKAGES.items():
        version = _fetch_latest_pypi_version(package)
        if version is None:
            continue
        current_major = _get_major(version)
        if current_major == tracked_major:
            print(f"OK: {package} still at major {tracked_major}.x (latest: {version})")
            continue
        title = f"upstream major bump: {package} {tracked_major}.x → {current_major}.x"
        if _issue_exists(title):
            print(f"Issue already exists: {title}")
            continue
        body = (
            f"**Package:** `{package}`\n"
            f"**Previous tracked major:** {tracked_major}.x\n"
            f"**New major:** {current_major}.x (latest: {version})\n\n"
            f"**PyPI:** https://pypi.org/project/{package}/\n\n"
            "Review the changelog and assess impact on Aevum before upgrading."
        )
        _open_issue(title, body)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Fetch GitHub Releases for Aevum-integrated frameworks and post a weekly digest.

Posts a GitHub issue labeled "release-digest" each Monday.
Closes the previous week's digest issue to avoid accumulation.
"""

import json
import os
import urllib.request
from datetime import UTC, datetime, timedelta
from urllib.error import URLError

WATCHED_REPOS: list[tuple[str, str]] = [
    ("langchain-ai", "langgraph"),
    ("openai", "openai-agents-python"),
    ("microsoft", "agent-framework"),
    ("google", "adk-python"),
    ("modelcontextprotocol", "python-sdk"),
    ("anthropics", "anthropic-sdk-python"),
]

_GITHUB_API = "https://api.github.com"
_REPO = os.environ.get("GITHUB_REPOSITORY", "aevum-labs/aevum")
_TOKEN = os.environ.get("GITHUB_TOKEN", "")
_HEADERS = {
    "Authorization": f"Bearer {_TOKEN}",
    "User-Agent": "aevum-framework-digest/1",
    "Accept": "application/vnd.github+json",
}
_DIGEST_LABEL = "release-digest"
_DIGEST_TITLE_PREFIX = "Framework Release Digest —"


def _fetch_recent_releases(owner: str, repo: str, days: int = 7) -> list[dict[str, str]]:
    url = f"{_GITHUB_API}/repos/{owner}/{repo}/releases?per_page=5"
    req = urllib.request.Request(url, headers=_HEADERS)
    cutoff = datetime.now(tz=UTC) - timedelta(days=days)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            releases: list[dict[str, object]] = json.loads(resp.read())
        result = []
        for r in releases:
            published = r.get("published_at")
            if not isinstance(published, str):
                continue
            pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            if pub_dt < cutoff:
                continue
            name = r.get("name") or r.get("tag_name") or ""
            html_url = r.get("html_url") or ""
            if isinstance(name, str) and isinstance(html_url, str):
                result.append({"name": name, "url": html_url, "published_at": published})
        return result
    except (URLError, ValueError, KeyError):
        print(f"WARNING: could not fetch releases for {owner}/{repo}")
        return []


def _close_old_digest_issues() -> None:
    url = (
        f"{_GITHUB_API}/repos/{_REPO}/issues"
        f"?state=open&labels={_DIGEST_LABEL}&per_page=100"
    )
    req = urllib.request.Request(url, headers=_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            issues: list[dict[str, object]] = json.loads(resp.read())
    except (URLError, ValueError):
        return
    for issue in issues:
        title = issue.get("title")
        number = issue.get("number")
        if not isinstance(title, str) or not isinstance(number, int):
            continue
        if not title.startswith(_DIGEST_TITLE_PREFIX):
            continue
        close_url = f"{_GITHUB_API}/repos/{_REPO}/issues/{number}"
        payload = json.dumps({"state": "closed"}).encode()
        close_req = urllib.request.Request(
            close_url,
            data=payload,
            headers={**_HEADERS, "Content-Type": "application/json"},
            method="PATCH",
        )
        try:
            with urllib.request.urlopen(close_req, timeout=15):  # noqa: S310
                pass
            print(f"Closed old digest issue #{number}: {title}")
        except (URLError, ValueError):
            print(f"WARNING: could not close issue #{number}")


def _open_issue(title: str, body: str) -> None:
    url = f"{_GITHUB_API}/repos/{_REPO}/issues"
    payload = json.dumps(
        {"title": title, "body": body, "labels": [_DIGEST_LABEL]}
    ).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={**_HEADERS, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15):  # noqa: S310
        pass
    print(f"Opened digest issue: {title}")


def main() -> None:
    today = datetime.now(tz=UTC).strftime("%Y-%m-%d")
    title = f"{_DIGEST_TITLE_PREFIX} {today}"

    sections: list[str] = []
    for owner, repo in WATCHED_REPOS:
        releases = _fetch_recent_releases(owner, repo)
        if releases:
            lines = [f"### [{owner}/{repo}](https://github.com/{owner}/{repo})"]
            for r in releases:
                lines.append(f"- [{r['name']}]({r['url']}) — {r['published_at'][:10]}")
            sections.append("\n".join(lines))

    if sections:
        body = "## New releases in the last 7 days\n\n" + "\n\n".join(sections)
    else:
        body = "No new releases this week."

    _close_old_digest_issues()
    _open_issue(title, body)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Assert the branch ruleset's required status checks match reality.

Two independent failure modes this catches:

1. DEAD CONTEXT. A required check name that no workflow job produces. The check
   stays Pending forever and every merge must bypass the ruleset. Four such
   entries went unnoticed for months.

2. UNPINNED SOURCE. A required check with no `integration_id`. GitHub accepts a
   status for that context from any credential with `statuses: write`, not only
   from GitHub Actions. Matrix-generated contexts are typed by hand in the UI
   before they exist, and hand-typed contexts default to "Any source" -- so this
   regresses every time a matrix leg is added.

Reads GET /repos/{owner}/{repo}/rules/branches/{branch}, which returns active
rules regardless of the ruleset they live in. Public repos need no auth.
"""

from __future__ import annotations

import argparse
import itertools
import json
import pathlib
import re
import sys
import urllib.request

# The GitHub Actions app. Verify with: GET https://api.github.com/apps/github-actions
GITHUB_ACTIONS_APP_ID = 15368

MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")


def check_names_from_workflows(workflows: pathlib.Path) -> set[str]:
    """Every check-run name GitHub Actions can produce from this repo."""
    import yaml

    names: set[str] = set()
    for path in sorted(workflows.glob("*.yml")):
        doc = yaml.safe_load(path.read_text()) or {}
        for job_id, job in (doc.get("jobs") or {}).items():
            template = job.get("name", job_id)
            matrix = (job.get("strategy") or {}).get("matrix")
            keys = MATRIX_REF.findall(template)
            if not keys or not isinstance(matrix, dict):
                names.add(template)
                continue
            axes = [[str(v) for v in matrix.get(k, [])] for k in keys]
            if not all(axes):
                names.add(template)
                continue
            for combo in itertools.product(*axes):
                expanded = template
                for k, v in zip(keys, combo, strict=True):
                    expanded = MATRIX_REF.sub(
                        lambda m, k=k, v=v: v if m.group(1) == k else m.group(0),
                        expanded,
                    )
                names.add(expanded)
    return names


def fetch_rules(repo: str, branch: str, token: str | None) -> list[dict]:
    url = f"https://api.github.com/repos/{repo}/rules/branches/{branch}"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default="aevum-labs/aevum")
    ap.add_argument("--branch", default="main")
    ap.add_argument("--workflows", type=pathlib.Path, default=pathlib.Path(".github/workflows"))
    ap.add_argument("--token", default=None)
    ap.add_argument("--rules-json", type=pathlib.Path, default=None,
                    help="read the API response from a file instead of the network (for tests)")
    ap.add_argument("--report-only", action="store_true",
                    help="print findings, always exit 0")
    args = ap.parse_args(argv)

    rules = (
        json.loads(args.rules_json.read_text())
        if args.rules_json
        else fetch_rules(args.repo, args.branch, args.token)
    )

    rsc = [r for r in rules if r.get("type") == "required_status_checks"]
    if not rsc:
        print(f"no required_status_checks rule applies to {args.branch}", file=sys.stderr)
        return 0 if args.report_only else 1

    produced = check_names_from_workflows(args.workflows)
    errors: list[str] = []
    print(f"required_status_checks rules: {len(rsc)} "
          f"(rulesets {[r.get('ruleset_id') for r in rsc]})")

    for rule in rsc:
        for check in rule["parameters"]["required_status_checks"]:
            context = check["context"]
            integration = check.get("integration_id")
            status = []
            if context not in produced:
                errors.append(
                    f"dead context {context!r}: no job in {args.workflows} produces this name"
                )
                status.append("DEAD")
            if integration is None:
                errors.append(
                    f"unpinned source {context!r}: any credential with statuses:write "
                    f"can satisfy it"
                )
                status.append("ANY SOURCE")
            elif integration != GITHUB_ACTIONS_APP_ID:
                errors.append(
                    f"unexpected source {context!r}: integration_id {integration}, "
                    f"expected {GITHUB_ACTIONS_APP_ID}"
                )
                status.append(f"APP {integration}")
            print(f"  {'FAIL' if status else 'ok  '}  {context:<28} "
                  f"integration_id={integration}  {' '.join(status)}")

    if not errors:
        print("ruleset OK: every required check names a real job and is pinned to GitHub Actions")
        return 0

    print(f"\nruleset drift: {len(errors)} finding(s)", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    return 0 if args.report_only else 1


if __name__ == "__main__":
    raise SystemExit(main())

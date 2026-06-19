#!/usr/bin/env bash
set -euo pipefail

echo "== pip-audit =="
# Use JSON output and count real vulnerabilities explicitly. pip-audit prints
# "Dependency not found on PyPI and could not be audited" skip lines for
# unpublishable workspace packages (aevum-llm, aevum-maintainer) -- those are
# not vulnerabilities and must not fail this check.
audit_json="$(uv run pip-audit -f json)" || true
vuln_count="$(echo "$audit_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
vulns = [(dep["name"], v["id"]) for dep in data["dependencies"] for v in dep.get("vulns", [])]
for name, vuln_id in vulns:
    print(f"  {name}: {vuln_id}", file=sys.stderr)
print(len(vulns))
')"
if [ "$vuln_count" -gt 0 ]; then
  echo "VULN FOUND ($vuln_count)"
  exit 1
fi
echo "pip-audit clean"

echo "== weak primitives =="
if grep -rniE "md5|sha1[^_]|[^a-z]des |rc4|ecb|pickle\.load" packages --include=*.py | grep -v test; then
  echo "WEAK PRIMITIVE"; exit 1; fi
echo "security clean"

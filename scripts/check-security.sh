#!/usr/bin/env bash
set -euo pipefail
echo "== pip-audit =="; uv run pip-audit || { echo "VULN FOUND"; exit 1; }
echo "== weak primitives =="
if grep -rniE "md5|sha1[^_]|[^a-z]des |rc4|ecb|pickle\.load" packages --include=*.py | grep -v test; then
  echo "WEAK PRIMITIVE"; exit 1; fi
echo "security clean"

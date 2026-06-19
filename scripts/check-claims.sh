#!/usr/bin/env bash
set -euo pipefail
FORBIDDEN='tamper-?proof|guarantees? compliance|100% secure|court-admissible|impossible to (tamper|alter)|replay what the agent did|unhackable|cannot be (tampered|altered|changed)'
hits=$(grep -rniE "$FORBIDDEN" docs README.md packages --include=*.md --include=*.py --include=*.txt 2>/dev/null \
  | grep -viE "not |n't|does not|cannot be detected|never claim|rather than|instead of|CHANGELOG|check-claims|\bno\b[a-z, ]*\bguarantees?\b" || true)
if [ -n "$hits" ]; then echo "FORBIDDEN POSITIVE CLAIM(S) FOUND:"; echo "$hits"; exit 1; fi
echo "claims clean"

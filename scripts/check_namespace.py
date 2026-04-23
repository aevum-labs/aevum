#!/usr/bin/env python3
"""
check_namespace.py — Verify native namespace package discipline.

The `aevum` top-level directory and any sub-namespace directories
(aevum/store/, aevum/domain/) must NOT contain __init__.py.
If they do, the namespace package mechanism breaks for all other packages.

Run from the repository root:
    python scripts/check_namespace.py

Exit 0 = clean. Exit 1 = violations found.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
PACKAGES_DIR = REPO_ROOT / "packages"

# Namespace directories that must NEVER contain __init__.py.
# These are relative to each package's src/ directory.
FORBIDDEN_RELATIVE_DIRS = [
    "aevum",
    "aevum/store",
    "aevum/domain",
]

violations = []

if not PACKAGES_DIR.is_dir():
    print(f"ERROR: packages/ directory not found at {PACKAGES_DIR}")
    sys.exit(1)

for package_dir in sorted(PACKAGES_DIR.iterdir()):
    if not package_dir.is_dir():
        continue
    src = package_dir / "src"
    if not src.is_dir():
        continue
    for forbidden_rel in FORBIDDEN_RELATIVE_DIRS:
        target = src / forbidden_rel
        if target.is_dir():
            init_file = target / "__init__.py"
            if init_file.exists():
                violations.append(str(init_file.relative_to(REPO_ROOT)))

if violations:
    print("NAMESPACE VIOLATION — __init__.py found in shared namespace directory.")
    print("This breaks namespace package imports for all other packages.")
    print()
    for v in violations:
        print(f"  REMOVE: {v}")
    print()
    print("See CLAUDE.md 'Namespace Package Rule' for explanation.")
    sys.exit(1)

checked = sum(
    1 for p in PACKAGES_DIR.iterdir()
    if p.is_dir() and (p / "src").is_dir()
)
print(f"OK — namespace discipline verified across {checked} package(s).")
sys.exit(0)

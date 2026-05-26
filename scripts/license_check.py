# SPDX-License-Identifier: Apache-2.0
"""
Checks that every Python source file in packages/ has a SPDX-License-Identifier header.
Expected header: # SPDX-License-Identifier: Apache-2.0
Skips: __init__.py files (namespace packages may be empty), test files (optional),
       files in .git/, build/, dist/, __pycache__/.
"""

import pathlib
import sys

REQUIRED_SPDX = "SPDX-License-Identifier: Apache-2.0"
SKIP_DIRS = {".git", "build", "dist", "__pycache__", ".venv", "node_modules"}


def check_file(path: pathlib.Path) -> bool:
    """Return True if file has the required SPDX header."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        return REQUIRED_SPDX in content[:500]  # check first 500 chars only
    except Exception:
        return True  # skip unreadable files


def main() -> int:
    root = pathlib.Path("packages")
    violations = []

    for py_file in root.rglob("*.py"):
        # Skip known-exempt locations
        if any(skip in py_file.parts for skip in SKIP_DIRS):
            continue
        # Skip empty __init__.py (namespace packages)
        if py_file.name == "__init__.py" and py_file.stat().st_size == 0:
            continue
        if not check_file(py_file):
            violations.append(str(py_file))

    if violations:
        print(f"## License Compliance: {len(violations)} file(s) missing SPDX header")
        print(f"Required: `{REQUIRED_SPDX}`")
        print()
        for v in sorted(violations):
            print(f"  - {v}")
        print()
        print("Add this as the first line of each file:")
        print(f"  # {REQUIRED_SPDX}")
        return 1
    else:
        print("License compliance: OK — all Python source files have SPDX headers")
        return 0


if __name__ == "__main__":
    sys.exit(main())

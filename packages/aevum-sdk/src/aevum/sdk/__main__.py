"""
python -m aevum.sdk — SDK CLI.

Commands:
    aevum new <name>    Scaffold a new complication project
    aevum list          List installed complications
    aevum validate      Validate the manifest of the current package

This is the developer-facing CLI. Server management (aevum server start)
is aevum-cli (separate package, future phase).
"""

from __future__ import annotations

import sys


def cmd_new(name: str) -> None:
    """Scaffold a new complication project."""
    from aevum.sdk.scaffold import scaffold
    scaffold(name)


def cmd_list() -> None:
    """List all installed complications."""
    from aevum.sdk.discovery import discover_complications
    complications = discover_complications()
    if not complications:
        print("No complications installed.")
        print("Install a complication package that registers entry points under")
        print('  [project.entry-points."aevum.complications"]')
        return
    print(f"Installed complications ({len(complications)}):")
    for c in complications:
        health = "✓" if c.health() else "✗"
        print(f"  {health} {c.name} v{c.version} — {', '.join(c.capabilities)}")


def cmd_validate() -> None:
    """Validate the manifest of the current package."""
    from aevum.sdk.discovery import discover_complications
    complications = discover_complications()
    if not complications:
        print("No complications found in current environment.")
        sys.exit(1)
    all_ok = True
    for c in complications:
        manifest = c.manifest()
        missing = [k for k in ["name", "version", "capabilities", "schema_version"]
                   if not manifest.get(k)]
        if missing:
            print(f"✗ {c.name}: missing manifest fields: {missing}")
            all_ok = False
        else:
            print(f"✓ {c.name} v{c.version}: manifest valid")
    sys.exit(0 if all_ok else 1)


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print("Usage: aevum <command> [args]")
        print("Commands: new <name>, list, validate")
        sys.exit(1)

    command = args[0]
    if command == "new":
        if len(args) < 2:
            print("Usage: aevum new <name>")
            sys.exit(1)
        cmd_new(args[1])
    elif command == "list":
        cmd_list()
    elif command == "validate":
        cmd_validate()
    else:
        print(f"Unknown command: {command!r}")
        print("Commands: new <name>, list, validate")
        sys.exit(1)


if __name__ == "__main__":
    main()

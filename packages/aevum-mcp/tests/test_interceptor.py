# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Tests for the Aevum Docker MCP Gateway interceptor shim.

Runs the bin/ script as a subprocess to validate exit codes and behavior,
matching exactly how Docker MCP Gateway invokes it in production.

NO tests/__init__.py (standing rule).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

_SHIM = str(
    Path(__file__).parent.parent / "bin" / "aevum-mcp-intercept.py"
)


def _run(
    payload: dict[str, Any],
    env_extra: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any] | str]:
    env = os.environ.copy()
    env["AEVUM_DEV"] = "1"
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        [sys.executable, _SHIM],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    try:
        parsed: dict[str, Any] | str = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        parsed = result.stdout
    return result.returncode, parsed


_SAFE_CALL: dict[str, Any] = {
    "jsonrpc": "2.0", "id": 1,
    "method": "tools/call",
    "params": {"name": "query", "arguments": {"purpose": "test"}},
}

_CRISIS_CALL: dict[str, Any] = {
    "jsonrpc": "2.0", "id": 2,
    "method": "tools/call",
    "params": {
        "name": "ingest",
        "arguments": {"data": {"content": "I want to kill myself"}},
    },
}

_LIST_CALL: dict[str, Any] = {
    "jsonrpc": "2.0", "id": 3,
    "method": "tools/list",
    "params": {},
}


def test_safe_call_exits_0() -> None:
    code, _ = _run(_SAFE_CALL)
    assert code == 0, f"Expected 0, got {code}"


def test_safe_call_passes_original_json() -> None:
    code, parsed = _run(_SAFE_CALL)
    assert code == 0
    assert isinstance(parsed, dict)
    assert parsed.get("method") == "tools/call"
    assert parsed.get("id") == 1


def test_crisis_content_exits_1() -> None:
    code, _ = _run(_CRISIS_CALL)
    assert code == 1, f"Expected 1, got {code}"


def test_crisis_content_returns_jsonrpc_error() -> None:
    code, parsed = _run(_CRISIS_CALL)
    assert code == 1
    assert isinstance(parsed, dict)
    assert "error" in parsed
    assert parsed["error"]["code"] == -32001
    assert parsed.get("id") == 2


def test_tools_list_passes_through() -> None:
    code, parsed = _run(_LIST_CALL)
    assert code == 0
    assert isinstance(parsed, dict)
    assert parsed.get("method") == "tools/list"


def test_malformed_json_exits_0() -> None:
    """Malformed JSON must fail-open — never block a call silently."""
    env = os.environ.copy()
    env["AEVUM_DEV"] = "1"
    result = subprocess.run(
        [sys.executable, _SHIM],
        input="not valid json {{{",
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    assert result.returncode == 0, "Malformed JSON must fail-open (exit 0)"


def test_empty_stdin_exits_0() -> None:
    env = os.environ.copy()
    env["AEVUM_DEV"] = "1"
    result = subprocess.run(
        [sys.executable, _SHIM],
        input="",
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    assert result.returncode == 0


def test_deny_includes_aevum_marker() -> None:
    code, parsed = _run(_CRISIS_CALL)
    assert code == 1
    assert isinstance(parsed, dict)
    assert parsed["error"]["data"]["aevum"] is True


def test_shim_file_is_executable() -> None:
    shim_path = Path(_SHIM)
    assert shim_path.exists(), f"Shim not found: {shim_path}"
    assert os.access(shim_path, os.X_OK), f"Not executable: {shim_path}"

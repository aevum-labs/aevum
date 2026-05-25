# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Tests for aevum.mcp.interceptor — Docker MCP Gateway shim.

Tests run the interceptor as a subprocess to validate exit codes and behavior,
matching how Docker MCP Gateway invokes it.

NO tests/__init__.py (standing rule).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

INTERCEPTOR_CMD = [sys.executable, "-m", "aevum.mcp.interceptor"]


def _run(
    payload: dict[str, Any],
    env_extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "AEVUM_DEV": "1", **(env_extra or {})}
    return subprocess.run(
        INTERCEPTOR_CMD,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
    )


def _run_raw(
    raw_input: str,
    env_extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "AEVUM_DEV": "1", **(env_extra or {})}
    return subprocess.run(
        INTERCEPTOR_CMD,
        input=raw_input,
        capture_output=True,
        text=True,
        env=env,
    )


class TestInterceptorAllow:
    def test_safe_call_exits_0(self) -> None:
        result = _run({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "safe_tool"},
        })
        assert result.returncode == 0

    def test_safe_call_stdout_is_original_json(self) -> None:
        payload: dict[str, Any] = {
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "safe_tool"},
        }
        result = _run(payload)
        assert result.returncode == 0
        assert json.loads(result.stdout) == payload

    def test_reads_stdin_json_string_id(self) -> None:
        payload: dict[str, Any] = {
            "jsonrpc": "2.0", "id": "abc",
            "method": "tools/list", "params": {},
        }
        result = _run(payload)
        assert result.returncode == 0
        assert json.loads(result.stdout)["id"] == "abc"

    def test_empty_params_allowed(self) -> None:
        result = _run({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        assert result.returncode == 0

    def test_nested_params_with_safe_text_allowed(self) -> None:
        result = _run({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/data/config.json"}},
        })
        assert result.returncode == 0


class TestInterceptorDeny:
    def test_crisis_keyword_exits_1(self) -> None:
        result = _run({
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/call",
            "params": {"text": "I want to kill myself"},
        })
        assert result.returncode == 1

    def test_crisis_deny_response_is_valid_json(self) -> None:
        result = _run({
            "jsonrpc": "2.0", "id": 3,
            "method": "tools/call",
            "params": {"content": "I want to die"},
        })
        assert result.returncode == 1
        response = json.loads(result.stdout)
        assert "error" in response

    def test_crisis_deny_response_contains_barrier_label(self) -> None:
        result = _run({
            "jsonrpc": "2.0", "id": 4,
            "method": "tools/call",
            "params": {"message": "harm myself tonight"},
        })
        assert result.returncode == 1
        response = json.loads(result.stdout)
        assert "Barrier 1" in response["error"]["message"]

    def test_crisis_deny_preserves_call_id(self) -> None:
        result = _run({
            "jsonrpc": "2.0", "id": 99,
            "method": "tools/call",
            "params": {"text": "end my life"},
        })
        assert result.returncode == 1
        response = json.loads(result.stdout)
        assert response["id"] == 99

    def test_crisis_in_nested_params_exits_1(self) -> None:
        result = _run({
            "jsonrpc": "2.0", "id": 5,
            "method": "tools/call",
            "params": {"arguments": {"query": "commit suicide now"}},
        })
        assert result.returncode == 1


class TestInterceptorError:
    def test_malformed_json_exits_2(self) -> None:
        result = _run_raw("not valid json{{{")
        assert result.returncode == 2

    def test_empty_stdin_exits_2(self) -> None:
        result = _run_raw("")
        assert result.returncode == 2

    def test_truncated_json_exits_2(self) -> None:
        result = _run_raw('{"jsonrpc": "2.0", "id":')
        assert result.returncode == 2


class TestInterceptorNoServer:
    def test_does_not_require_aevum_http_server(self) -> None:
        """Interceptor must work standalone, with no Aevum HTTP server running."""
        env: dict[str, str] = {
            **{k: v for k, v in os.environ.items()},
            "AEVUM_DEV": "1",
        }
        env.pop("AEVUM_API_URL", None)
        env.pop("AEVUM_SERVER_URL", None)
        result = subprocess.run(
            INTERCEPTOR_CMD,
            input=json.dumps({
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/list", "params": {},
            }),
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0

    def test_works_without_receipt_db_in_dev_mode(self) -> None:
        """AEVUM_DEV=1 must not require AEVUM_RECEIPT_DB."""
        env: dict[str, str] = {
            **{k: v for k, v in os.environ.items()},
            "AEVUM_DEV": "1",
        }
        env.pop("AEVUM_RECEIPT_DB", None)
        result = subprocess.run(
            INTERCEPTOR_CMD,
            input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0


class TestInterceptorExitCodeContract:
    def test_exit_0_is_allow(self) -> None:
        """Exit 0 is the allow signal — stdout must contain original JSON."""
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}
        result = _run(payload)
        assert result.returncode == 0
        assert json.loads(result.stdout) == payload

    def test_exit_1_is_deny(self) -> None:
        """Exit 1 is the deny signal — stdout must contain error response."""
        result = _run({
            "jsonrpc": "2.0", "id": 8,
            "method": "tools/call",
            "params": {"text": "I want to die"},
        })
        assert result.returncode == 1
        err = json.loads(result.stdout)
        assert err.get("error") is not None

    def test_exit_2_is_error(self) -> None:
        """Exit 2 signals an interceptor error."""
        result = _run_raw("bad-json")
        assert result.returncode == 2

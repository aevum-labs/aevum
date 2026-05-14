# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Tests for AevumCrewHooks and AevumTaskCallback.
Uses mocked Cedar to avoid live policy evaluation.
"""
from unittest.mock import MagicMock, patch

import pytest

from aevum.core.adapters.crewai import AevumCrewHooks, AevumTaskCallback


def _permit_patch() -> object:
    """Patch Cedar to allow everything."""
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = True
    return patch("aevum.core.adapters.crewai.CedarPolicyEngine", **{"default.return_value": mock_engine})


def _deny_patch() -> object:
    """Patch Cedar to deny everything."""
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = False
    return patch("aevum.core.adapters.crewai.CedarPolicyEngine", **{"default.return_value": mock_engine})


class TestAevumCrewHooksInit:
    def test_init_without_kernel(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        assert hooks._kernel is None

    def test_init_with_kernel(self) -> None:
        kernel = MagicMock()
        hooks = AevumCrewHooks(kernel=kernel)
        assert hooks._kernel is kernel


class TestBeforeTask:
    def test_before_task_returns_ctx(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        with _permit_patch():
            ctx = hooks.before_task("summarize document", "researcher")
        assert ctx["cedar_permitted"] is True
        assert ctx["agent_role"] == "researcher"
        assert ctx["task_description"] == "summarize document"

    def test_before_task_raises_on_cedar_deny(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        with _deny_patch(), pytest.raises(PermissionError, match="Cedar denied"):
            hooks.before_task("malicious task", "agent")

    def test_before_task_ctx_has_started_at(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        with _permit_patch():
            ctx = hooks.before_task("do something", "worker")
        assert "started_at" in ctx

    def test_before_task_ctx_has_consequential(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        with _permit_patch():
            ctx = hooks.before_task("task", "agent", consequential=True)
        assert ctx["consequential"] is True

    def test_before_task_non_consequential_no_govern(self) -> None:
        kernel = MagicMock()
        hooks = AevumCrewHooks(kernel=kernel)
        with _permit_patch():
            ctx = hooks.before_task("safe task", "agent", consequential=False)
        assert "govern_outcome" not in ctx

    def test_before_task_consequential_reversible_no_govern(self) -> None:
        kernel = MagicMock()
        hooks = AevumCrewHooks(kernel=kernel)
        with _permit_patch():
            ctx = hooks.before_task("task", "agent", consequential=True, reversible=True)
        assert "govern_outcome" not in ctx

    def test_before_task_long_description_truncated_in_error(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        with _deny_patch(), pytest.raises(PermissionError) as exc_info:
            hooks.before_task("a" * 200, "agent")
        assert len(str(exc_info.value)) < 300  # truncated to 50 chars

    def test_before_task_cedar_called_with_correct_params(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        mock_engine = MagicMock()
        mock_engine.is_permitted.return_value = True
        with patch("aevum.core.adapters.crewai.CedarPolicyEngine", **{"default.return_value": mock_engine}):
            hooks.before_task("my task", "researcher")
        call_kwargs = mock_engine.is_permitted.call_args[1]
        assert call_kwargs["principal_type"] == "AevumAgent"
        assert call_kwargs["principal_id"] == "researcher"
        assert call_kwargs["action"] == "tool_call"


class TestAfterTask:
    def test_after_task_does_not_raise(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        ctx = {"agent_role": "researcher", "task_description": "test", "started_at": "now"}
        hooks.after_task(ctx, "output", success=True)  # must not raise

    def test_after_task_failure_does_not_raise(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        ctx = {"agent_role": "agent", "task_description": "task", "started_at": "now"}
        hooks.after_task(ctx, "error output", success=False)

    def test_after_task_with_kernel(self) -> None:
        kernel = MagicMock()
        hooks = AevumCrewHooks(kernel=kernel)
        ctx = {"agent_role": "agent"}
        hooks.after_task(ctx, "output", success=True)

    def test_after_task_with_none_output(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        ctx = {"agent_role": "agent"}
        hooks.after_task(ctx, None, success=True)  # must not raise

    def test_after_task_with_complex_output(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        ctx = {"agent_role": "agent"}
        hooks.after_task(ctx, {"nested": {"data": [1, 2, 3]}}, success=True)


class TestAevumTaskCallback:
    def test_callback_returns_output(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        callback = AevumTaskCallback(hooks=hooks)
        result = callback("task output")
        assert result == "task output"

    def test_callback_passes_output_to_after_task(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        called_with = []

        def patched(ctx, output, success):  # type: ignore[no-untyped-def]
            called_with.append(output)

        hooks.after_task = patched  # type: ignore[method-assign]
        callback = AevumTaskCallback(hooks=hooks)
        callback("my output")
        assert "my output" in called_with

    def test_callback_with_none_output(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        callback = AevumTaskCallback(hooks=hooks)
        result = callback(None)
        assert result is None

    def test_callback_with_dict_output(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        callback = AevumTaskCallback(hooks=hooks)
        data = {"result": "success", "count": 42}
        result = callback(data)
        assert result == data

    def test_callback_with_consequential_flag(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        callback = AevumTaskCallback(hooks=hooks, consequential=True, reversible=False)
        assert callback._consequential is True
        assert callback._reversible is False

    def test_callback_default_flags(self) -> None:
        hooks = AevumCrewHooks(kernel=None)
        callback = AevumTaskCallback(hooks=hooks)
        assert callback._consequential is False
        assert callback._reversible is True

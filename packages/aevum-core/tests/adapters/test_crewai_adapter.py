# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Semantic drift snapshot tests for the CrewAI AevumCrewHooks adapter.

These tests detect when crewai changes the callback/hook interface in a way
that silently breaks Aevum's governance envelope.  If this file fails after
a crewai upgrade, compare the diff carefully before updating.

To update snapshots after an intentional change:
    pytest --inline-snapshot=fix packages/aevum-core/tests/adapters/

CI uses --inline-snapshot=disable so snapshots are never auto-updated in CI.

Upstream change that would break this adapter:
  - crewai renames task/crew callback arguments
  - AevumTaskCallback.__call__ signature no longer matches crewai's expected callback shape
  - crewai adds required fields to task output objects
Re-evaluate when: crewai releases a major version bump or changes callback protocol.
"""
from __future__ import annotations

import pytest

try:
    import crewai  # noqa: F401
except ModuleNotFoundError as exc:
    # Only skip when crewai itself is absent. Any other ImportError/ModuleNotFoundError
    # (e.g. a transitive dependency version conflict, such as crewai pulling an
    # opentelemetry-sdk that's missing a symbol it expects) is a real regression and
    # must fail loudly here, not be silently reclassified as "not installed".
    if exc.name != "crewai":
        raise
    pytest.skip("crewai not installed", allow_module_level=True)

from unittest.mock import MagicMock, patch  # noqa: E402

from inline_snapshot import snapshot  # noqa: E402

from aevum.core.adapters.crewai import AevumCrewHooks, AevumTaskCallback  # noqa: E402


def _permit_patch() -> object:
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = True
    return patch("aevum.core.adapters.crewai.CedarPolicyEngine", **{"default.return_value": mock_engine})


def _deny_patch() -> object:
    mock_engine = MagicMock()
    mock_engine.is_permitted.return_value = False
    return patch("aevum.core.adapters.crewai.CedarPolicyEngine", **{"default.return_value": mock_engine})


def test_before_task_return_shape() -> None:
    """
    before_task must return a dict with exactly these keys.
    If the adapter adds, removes, or renames a key this snapshot fails.
    Run pytest --inline-snapshot=fix to update after intentional changes.
    """
    hooks = AevumCrewHooks(kernel=None)
    with _permit_patch():
        result = hooks.before_task("summarize report", "researcher")

    assert result == snapshot(
        {
            "task_description": "summarize report",
            "agent_role": "researcher",
            "started_at": result["started_at"],
            "cedar_permitted": True,
            "consequential": False,
        }
    )


def test_before_task_cedar_permitted_is_bool() -> None:
    """cedar_permitted must be exactly True — consumers type-check it."""
    hooks = AevumCrewHooks(kernel=None)
    with _permit_patch():
        result = hooks.before_task("task", "agent")
    assert result["cedar_permitted"] is True


def test_before_task_cedar_deny_raises_permission_error() -> None:
    """Cedar deny must raise PermissionError — not return a falsy value."""
    hooks = AevumCrewHooks(kernel=None)
    with _deny_patch(), pytest.raises(PermissionError, match="Cedar denied"):
        hooks.before_task("blocked task", "attacker")


def test_before_task_consequential_flag_in_ctx() -> None:
    """consequential=True must be present in the context dict."""
    hooks = AevumCrewHooks(kernel=None)
    with _permit_patch():
        result = hooks.before_task("send email", "writer", consequential=True)

    assert result == snapshot(
        {
            "task_description": "send email",
            "agent_role": "writer",
            "started_at": result["started_at"],
            "cedar_permitted": True,
            "consequential": True,
        }
    )


def test_task_callback_return_shape() -> None:
    """
    AevumTaskCallback.__call__ must return the output unchanged.
    CrewAI passes the return value along the task chain.
    """
    hooks = AevumCrewHooks(kernel=None)
    callback = AevumTaskCallback(hooks=hooks)
    output = {"result": "done", "confidence": 0.97}
    returned = callback(output)

    assert returned == snapshot({"result": "done", "confidence": 0.97})


def test_task_callback_string_output_passthrough() -> None:
    """String outputs must pass through unmodified."""
    hooks = AevumCrewHooks(kernel=None)
    callback = AevumTaskCallback(hooks=hooks)
    result = callback("task complete")

    assert result == snapshot("task complete")

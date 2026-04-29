"""
Tests for A2A task format and MCP tools.
Uses direct tool invocation -- no real MCP protocol.

NO tests/__init__.py (standing rule).
"""

from __future__ import annotations

import json

from aevum.core.engine import Engine

from aevum.mcp.a2a import A2ATask
from aevum.mcp.server import create_server


class TestA2AModels:
    def test_created_task(self) -> None:
        task = A2ATask.created("urn:aevum:audit:abc", "Test Task", "desc")
        assert task.task_id == "urn:aevum:audit:abc"
        assert task.state == "created"
        assert task.name == "Test Task"

    def test_completed_task(self) -> None:
        task = A2ATask.completed("urn:aevum:audit:abc", "Test", "Done successfully")
        assert task.state == "completed"
        assert len(task.messages) == 1
        assert task.messages[0].role == "agent"

    def test_failed_task(self) -> None:
        task = A2ATask.failed("urn:aevum:audit:abc", "Test", "Something went wrong")
        assert task.state == "failed"

    def test_input_required_task(self) -> None:
        task = A2ATask.input_required("urn:aevum:audit:abc", "Test", "Need approval")
        assert task.state == "input_required"

    def test_task_serializable(self) -> None:
        task = A2ATask.created("urn:aevum:audit:abc", "Test")
        # Must be JSON-serializable (MCP protocol requirement)
        json.dumps(task.model_dump(mode="json"))

    def test_valid_states(self) -> None:
        valid = ["created", "working", "input_required", "completed", "failed", "cancelled"]
        for state in valid:
            task = A2ATask(task_id="urn:aevum:audit:abc", name="t", state=state)  # type: ignore[arg-type]
            assert task.state == state


class TestA2AMcpTools:
    def test_create_task_tool(self) -> None:
        mcp = create_server(Engine())
        tool_fn = mcp._tool_manager._tools["create_task"].fn  # type: ignore[attr-defined]
        result = tool_fn(name="Test Task", description="A test", payload={"x": 1})
        assert result["state"] == "created"
        assert result["task_id"].startswith("urn:aevum:audit:")
        assert result["name"] == "Test Task"

    def test_get_task_tool(self) -> None:
        mcp = create_server(Engine())
        create_fn = mcp._tool_manager._tools["create_task"].fn  # type: ignore[attr-defined]
        get_fn = mcp._tool_manager._tools["get_task"].fn  # type: ignore[attr-defined]

        created = create_fn(name="Fetch Me", description="test")
        task_id = created["task_id"]

        fetched = get_fn(task_id=task_id)
        assert fetched["task_id"] == task_id

    def test_get_task_not_found(self) -> None:
        mcp = create_server(Engine())
        get_fn = mcp._tool_manager._tools["get_task"].fn  # type: ignore[attr-defined]
        result = get_fn(task_id="urn:aevum:audit:00000000-0000-7000-8000-000000000999")
        assert result["state"] == "failed"

    def test_seven_tools_registered(self) -> None:
        mcp = create_server(Engine())
        tools = set(mcp._tool_manager._tools.keys())  # type: ignore[attr-defined]
        for expected in ["ingest", "query", "review", "commit", "replay",
                         "create_task", "get_task"]:
            assert expected in tools, f"Missing tool: {expected}"

    def test_create_task_result_json_serializable(self) -> None:
        mcp = create_server(Engine())
        tool_fn = mcp._tool_manager._tools["create_task"].fn  # type: ignore[attr-defined]
        result = tool_fn(name="Test", payload={})
        json.dumps(result)  # Must not raise

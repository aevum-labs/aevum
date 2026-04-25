"""Tests for Complication base class and Context."""

from __future__ import annotations

import pytest
from hello_complication import HelloComplication

from aevum.sdk import Complication, Context
from aevum.sdk.base import Complication as ComplicationBase


def test_hello_complication_is_subclass() -> None:
    assert issubclass(HelloComplication, ComplicationBase)


@pytest.mark.asyncio
async def test_run_returns_dict() -> None:
    comp = HelloComplication()
    ctx = Context(subject_ids=["s1"], purpose="test", actor="actor")
    result = await comp.run(ctx, {"who": "tester"})
    assert result == {"result": "hello, tester"}


@pytest.mark.asyncio
async def test_run_default_payload() -> None:
    comp = HelloComplication()
    ctx = Context(subject_ids=[], purpose="test", actor="actor")
    result = await comp.run(ctx, {})
    assert result == {"result": "hello, world"}


def test_run_sync() -> None:
    comp = HelloComplication()
    ctx = Context(subject_ids=["s1"], purpose="test", actor="actor")
    result = comp.run_sync(ctx, {"who": "sync"})
    assert result["result"] == "hello, sync"


def test_health_default_true() -> None:
    assert HelloComplication().health() is True


def test_context_is_frozen() -> None:
    ctx = Context(subject_ids=["s1"], purpose="test", actor="actor")
    with pytest.raises((AttributeError, TypeError)):
        ctx.purpose = "modified"  # type: ignore[misc]


def test_missing_name_raises() -> None:
    with pytest.raises(TypeError, match="name"):
        class BadComp(Complication):
            name = ""
            version = "0.1.0"
            capabilities = ["x"]

            async def run(self, ctx: Context, payload: dict) -> dict:  # type: ignore[type-arg]
                return {}


def test_missing_capabilities_raises() -> None:
    with pytest.raises(TypeError, match="capabilities"):
        class BadComp(Complication):
            name = "bad"
            version = "0.1.0"
            capabilities = []

            async def run(self, ctx: Context, payload: dict) -> dict:  # type: ignore[type-arg]
                return {}


def test_class_attributes_accessible() -> None:
    assert HelloComplication.name == "hello"
    assert HelloComplication.version == "0.1.0"
    assert "echo" in HelloComplication.capabilities

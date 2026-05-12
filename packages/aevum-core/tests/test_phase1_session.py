# SPDX-License-Identifier: Apache-2.0
"""Tests for Phase 1 session async context manager."""
import pytest

from aevum.core.session import Session


class TestSessionContextManager:
    @pytest.mark.asyncio
    async def test_aenter_returns_session(self):
        session = Session(actor="test-actor")
        result = await session.__aenter__()
        assert result is session

    @pytest.mark.asyncio
    async def test_aexit_completes_without_error(self):
        session = Session(actor="test-actor")
        await session.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_async_with_block_works(self):
        async with Session(actor="test-actor") as session:
            assert session.actor == "test-actor"

    @pytest.mark.asyncio
    async def test_aexit_on_exception_does_not_raise(self):
        session = Session(actor="test-actor")
        # Should not raise even with exception info passed
        await session.__aexit__(ValueError, ValueError("test"), None)

    @pytest.mark.asyncio
    async def test_session_preserves_fields_through_context(self):
        async with Session(
            actor="alice",
            correlation_id="corr-1",
            episode_id="ep-1",
        ) as s:
            assert s.actor == "alice"
            assert s.correlation_id == "corr-1"
            assert s.episode_id == "ep-1"

    def test_session_has_aenter(self):
        assert hasattr(Session, "__aenter__")

    def test_session_has_aexit(self):
        assert hasattr(Session, "__aexit__")

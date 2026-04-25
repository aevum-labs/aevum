"""
Tests for LlmComplication.
Uses litellm mock mode — no real LLM API keys needed.

NO tests/__init__.py (standing rule).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aevum.llm.complication import LlmComplication, _sha3


class TestLlmComplication:
    def test_manifest_valid(self) -> None:
        comp = LlmComplication()
        m = comp.manifest()
        assert m["name"] == "llm"
        assert "llm-completion" in m["capabilities"]
        assert m["schema_version"] == "1.0"

    def test_health_always_true(self) -> None:
        comp = LlmComplication()
        assert comp.health() is True

    def test_sha3_deterministic(self) -> None:
        assert _sha3("hello") == _sha3("hello")
        assert _sha3("hello") != _sha3("world")
        assert len(_sha3("test")) == 64  # SHA3-256 hex

    @pytest.mark.asyncio
    async def test_run_returns_model_id_and_hashes(self) -> None:
        comp = LlmComplication(model="gpt-4.1-mini")

        mock_message = MagicMock()
        mock_message.content = "This is a test response."
        mock_choice = MagicMock()
        mock_choice.message = mock_message
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        with patch("litellm.acompletion", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = mock_response
            ctx = {"purpose": "test-query", "metadata": {}}
            result = await comp.run(ctx, {"entity-1": {"content": "data"}})

        assert result["model_id"] == "gpt-4.1-mini"
        assert "prompt_hash" in result
        assert "response_hash" in result
        assert "response" in result
        assert len(result["prompt_hash"]) == 64   # SHA3-256
        assert len(result["response_hash"]) == 64

    @pytest.mark.asyncio
    async def test_raw_prompt_not_in_result(self) -> None:
        """The actual prompt must never appear in the result."""
        comp = LlmComplication(model="gpt-4.1-mini")

        mock_message = MagicMock()
        mock_message.content = "Response."
        mock_choice = MagicMock()
        mock_choice.message = mock_message
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        with patch("litellm.acompletion", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = mock_response
            ctx = {"purpose": "sensitive-purpose", "metadata": {}}
            result = await comp.run(ctx, {"key": "sensitive data"})

        result_str = str(result)
        assert "sensitive data" not in result_str, "Raw data must not be in result"
        assert "Purpose:" not in result_str, "Raw prompt must not be in result"

    @pytest.mark.asyncio
    async def test_fallback_model_tried_on_failure(self) -> None:
        comp = LlmComplication(
            model="primary-model",
            fallback_models=["fallback-model"],
        )

        mock_message = MagicMock()
        mock_message.content = "Fallback response."
        mock_choice = MagicMock()
        mock_choice.message = mock_message
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        call_count = 0

        async def side_effect(**kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            if kwargs.get("model") == "primary-model":
                raise Exception("Primary model unavailable")
            return mock_response

        with patch("litellm.acompletion", side_effect=side_effect):
            ctx = {"purpose": "test", "metadata": {}}
            result = await comp.run(ctx, {})

        assert result["model_id"] == "fallback-model"
        assert call_count == 2  # Tried primary, then fallback

    @pytest.mark.asyncio
    async def test_all_models_fail_returns_error(self) -> None:
        comp = LlmComplication(model="bad-model")

        with patch("litellm.acompletion", new_callable=AsyncMock) as mock_llm:
            mock_llm.side_effect = Exception("All models failed")
            ctx = {"purpose": "test", "metadata": {}}
            result = await comp.run(ctx, {})

        assert "llm_error" in result
        assert "prompt_hash" in result  # Still logged for audit

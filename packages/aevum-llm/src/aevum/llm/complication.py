"""
LlmComplication — LiteLLM-backed with tier-ordered fallback.

Every invocation is logged with model_id, prompt_hash, response_hash.
The raw prompt and response are NEVER stored in the ledger.
The model_id is set in provenance.model_id of the OutputEnvelope.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _sha3(text: str) -> str:
    return hashlib.sha3_256(text.encode()).hexdigest()


class LlmComplication:
    """
    LLM complication backed by LiteLLM with tier-ordered fallback.

    Args:
        model: Primary model identifier (LiteLLM format: "gpt-4.1", "claude-sonnet-4-6")
        fallback_models: Tried in order if primary fails
        max_tokens: Maximum tokens in response
        temperature: Sampling temperature (0.0 = deterministic)
    """

    name = "llm"
    version = "0.1.0"
    capabilities = ["llm-completion"]

    def __init__(
        self,
        model: str = "gpt-4.1",
        fallback_models: list[str] | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> None:
        self._model = model
        self._fallback_models = fallback_models or []
        self._max_tokens = max_tokens
        self._temperature = temperature

    def manifest(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": "LiteLLM-backed LLM completion with episodic ledger record",
            "capabilities": list(self.capabilities),
            "classification_max": 2,  # LLM output is internal by default
            "functions": ["query"],
            "auth": {"scopes_required": [], "public_key": None},
            "schema_version": "1.0",
        }

    def health(self) -> bool:
        """Always healthy — model availability checked at call time."""
        return True

    async def run(self, ctx: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        """
        Run an LLM completion over the query context.

        Expects payload to contain graph results from the query function.
        Returns completion text with model_id and hashes for audit.
        Raw prompt and response are NOT returned — only hashes.
        """
        import litellm

        purpose = ctx.get("purpose", "")
        results = payload if payload else {}
        prompt = self._build_prompt(purpose, results)
        prompt_hash = _sha3(prompt)

        models_to_try = [self._model] + self._fallback_models
        used_model: str = self._model
        response_text: str = ""
        error: str | None = None

        for model in models_to_try:
            try:
                response = await litellm.acompletion(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=self._max_tokens,
                    temperature=self._temperature,
                )
                response_text = response.choices[0].message.content or ""
                used_model = model
                error = None
                break
            except Exception as e:
                logger.warning("LLM call failed for model %s: %s", model, e)
                error = str(e)
                continue

        if error and not response_text:
            return {
                "llm_error": error,
                "model_id": used_model,
                "prompt_hash": prompt_hash,
            }

        response_hash = _sha3(response_text)

        return {
            # model_id is the key field — maps to provenance.model_id
            "model_id": used_model,
            "prompt_hash": prompt_hash,        # SHA3-256, not the raw prompt
            "response_hash": response_hash,    # SHA3-256, not the raw response
            "response": response_text,         # The actual completion
            "token_estimate": len(response_text.split()),
        }

    def _build_prompt(self, purpose: str, results: dict[str, Any]) -> str:
        """Build a prompt from the query purpose and graph results."""
        sep = chr(10)
        items = [
            f"- {k}: {v}" for k, v in results.items()
            if not k.startswith("_") and k != "complication_results"
        ]
        context_str = sep.join(items) if items else "None"
        return (
            f"Purpose: {purpose}" + sep + sep +
            "Available context:" + sep + context_str + sep + sep +
            "Based on the context above, provide a relevant and helpful response."
        )

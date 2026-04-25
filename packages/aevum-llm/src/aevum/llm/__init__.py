"""
aevum.llm — LiteLLM-backed LLM complication.

Every LLM call is logged to the Aevum ledger with:
  - model_id (set in provenance.model_id)
  - prompt_hash (SHA3-256 of the prompt — not the prompt itself)
  - response_hash (SHA3-256 of the response content)

Usage:
    from aevum.llm import LlmComplication

    comp = LlmComplication(
        model="gpt-4.1",
        fallback_models=["gpt-4o", "claude-sonnet-4-6"],
    )
    engine.install_complication(comp, auto_approve=True)
"""

from aevum.llm.complication import LlmComplication

__version__ = "0.1.0"

__all__ = ["LlmComplication"]

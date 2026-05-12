# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
CedarPolicyEngine — wrapper around cedarpy for Aevum policy evaluation.

All Cedar policy evaluation in Aevum goes through this module.
Direct calls to cedarpy.is_authorized are forbidden in application code.

Policy files live in: aevum/core/policies/
  barriers.cedar        — five absolute barrier forbid policies
  trifecta.cedar        — TaintLabel trifecta enforcement
  autonomy.cedar        — L1-L5 autonomy enforcement

Entity type conventions:
  AevumAgent::"<session-id>"      principal (an agent session)
  DataGraph::"knowledge"          knowledge named graph
  DataGraph::"provenance"         provenance named graph (append-only)
  DataGraph::"consent"            consent named graph
  ToolAction::"<tool-name>"       any tool or API call
  TaintLabel::"<label>"           READS_UNTRUSTED, READS_PRIVATE, CAN_EXFILTRATE

Decision: Decision.Allow = permitted; Decision.Deny = denied (barrier fires)
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from cedarpy import AuthzResult, Decision, is_authorized

logger = logging.getLogger(__name__)

# Policy directory (relative to this file)
_POLICY_DIR = Path(__file__).parent / "policies"


class PolicyError(Exception):
    """Raised when policy evaluation itself fails (not a deny — an engine error)."""


class CedarPolicyEngine:
    """
    Evaluates Cedar policies for Aevum authorization decisions.

    Usage:
      engine = CedarPolicyEngine.default()
      result = engine.is_permitted(
          principal_type="AevumAgent",
          principal_id="session-abc",
          action="relate_graph_write",
          resource_type="DataGraph",
          resource_id="knowledge",
          context={"has_crisis_content": False, ...},
          entities=[...],
      )
      if not result:
          raise BarrierError("...")
    """

    def __init__(self, policy_text: str) -> None:
        self._policy_text = policy_text

    @classmethod
    def default(cls) -> CedarPolicyEngine:
        """Load all policies from the policies/ directory."""
        policy_text = cls._load_all_policies()
        return cls(policy_text)

    @classmethod
    def _load_all_policies(cls) -> str:
        """Load and concatenate all .cedar files from the policies directory."""
        if not _POLICY_DIR.exists():
            raise PolicyError(
                f"Policy directory not found: {_POLICY_DIR}. "
                "Create packages/aevum-core/src/aevum/core/policies/"
            )
        cedar_files = sorted(_POLICY_DIR.glob("*.cedar"))
        if not cedar_files:
            raise PolicyError(
                f"No .cedar files found in {_POLICY_DIR}. "
                "Phase 2 requires barrier policies to be present."
            )
        parts: list[str] = []
        for f in cedar_files:
            parts.append(f"// === {f.name} ===\n")
            parts.append(f.read_text(encoding="utf-8"))
            parts.append("\n\n")
        combined = "".join(parts)
        logger.debug(
            "Loaded %d Cedar policy files (%d chars)",
            len(cedar_files), len(combined),
        )
        return combined

    def is_permitted(
        self,
        principal_type: str,
        principal_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        context: dict[str, Any],
        entities: list[dict[str, Any]] | None = None,
    ) -> bool:
        """
        Evaluate Cedar policies for a request.

        Returns True if permitted, False if denied.
        Raises PolicyError only if the engine itself fails (not for denials).

        Cedar semantics:
          - If any forbid applies → False (denied)
          - If at least one permit applies AND no forbid → True (allowed)
          - Otherwise → False (implicit deny)
        """
        request = {
            "principal": f'{principal_type}::"{principal_id}"',
            "action": f'Action::"{action}"',
            "resource": f'{resource_type}::"{resource_id}"',
            "context": context,
        }
        _entities = entities or []

        try:
            result: AuthzResult = is_authorized(
                request,
                self._policy_text,
                _entities,
            )
        except Exception as exc:
            raise PolicyError(
                f"Cedar policy engine error on action={action!r}: {exc}"
            ) from exc

        decision = result.decision
        permitted: bool = (decision == Decision.Allow)

        if not permitted:
            logger.debug(
                "Cedar DENY: principal=%s action=%s resource=%s",
                principal_id, action, resource_id,
            )

        return permitted

    def validate(self) -> list[str]:
        """
        Validate loaded policies syntactically via a no-op authorization request.
        Returns list of error strings (empty = valid).
        Full schema validation requires a Cedar schema file (Phase 4+).
        """
        try:
            # Use a benign request to surface any syntax errors in the policy text
            request = {
                "principal": 'AevumAgent::"validate-probe"',
                "action": 'Action::"__validate_probe__"',
                "resource": 'DataGraph::"knowledge"',
                "context": {},
            }
            is_authorized(request, self._policy_text, [])
            return []
        except Exception as exc:
            return [str(exc)]

    @property
    def policy_text(self) -> str:
        """The combined Cedar policy text. Useful for debugging."""
        return self._policy_text

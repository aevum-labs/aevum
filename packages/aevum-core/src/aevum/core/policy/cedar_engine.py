# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""CedarPolicyEngine — Cedar ABAC engine. Requires aevum-core[cedar]."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

try:
    import cedarpy  # noqa: F401
    _CEDAR_AVAILABLE = True
except ImportError:
    _CEDAR_AVAILABLE = False

logger = logging.getLogger(__name__)

_POLICY_DIR = Path(__file__).parent.parent / "policies"


class PolicyError(Exception):
    """Raised when policy evaluation itself fails (not a deny — an engine error)."""


class CedarPolicyEngine:
    """Cedar ABAC engine. Requires aevum-core[cedar]."""

    def __init__(self, policy_text: str) -> None:
        if not _CEDAR_AVAILABLE:
            raise RuntimeError(
                "cedarpy is not installed. "
                "Run: pip install 'aevum-core[cedar]'"
            )
        self._policy_text = policy_text

    @classmethod
    def default(cls) -> CedarPolicyEngine:
        """Load the default shipped policy bundle."""
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
        *,
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
        """
        from cedarpy import AuthzResult, Decision, is_authorized

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
        """Validate loaded policies syntactically. Returns error strings (empty = valid)."""
        try:
            from cedarpy import is_authorized
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
        """The combined Cedar policy text."""
        return self._policy_text

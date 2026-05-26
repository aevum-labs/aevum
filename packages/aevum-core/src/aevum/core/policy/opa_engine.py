# SPDX-License-Identifier: Apache-2.0
"""OPA HTTP sidecar adapter. Implements PolicyEngine via the OPA REST API."""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("aevum.policy.opa")


class OPAPolicyEngine:
    """
    OPA policy engine implementing the PolicyEngine Protocol.
    Evaluates all three policy-governed barriers via OPA HTTP sidecar.
    Barriers 1 (Crisis) and 4 (AuditImmutability) are hardcoded —
    OPA does not govern them regardless of configuration.

    Requires OPA server running at opa_url (default: AEVUM_OPA_URL env var).
    Fails OPEN on timeout/unavailable (logs WARNING).
    Fails CLOSED on explicit OPA deny (returns False).

    Fail-open semantics are intentional per ADR-005: OPA is a sidecar, not a
    hard gate. If it goes down, the hardcoded barriers (Crisis, AuditImmutability)
    still hold. Cedar evaluation (if available) also runs independently.

    Usage:
        engine = OPAPolicyEngine(opa_url="http://localhost:8181")
        permitted = engine.is_permitted(
            principal_type="AevumAgent",
            principal_id="agent-1",
            action="consent::grant",
            resource_type="Subject",
            resource_id="subject-1",
            context={...},
        )
    """

    def __init__(self, opa_url: str | None = None) -> None:
        self._opa_url = (opa_url or os.environ.get("AEVUM_OPA_URL", "")).rstrip("/")
        if not self._opa_url:
            raise RuntimeError(
                "OPAPolicyEngine requires AEVUM_OPA_URL environment variable "
                "or opa_url constructor argument. "
                "Example: OPAPolicyEngine(opa_url='http://localhost:8181')"
            )
        self._client = httpx.Client(timeout=2.0)

    def is_permitted(
        self,
        *,
        principal_type: str,
        principal_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        context: dict[str, Any],
    ) -> bool:
        """
        Evaluate via OPA. Routes to the correct Rego package based on action prefix.
        Fails open on network error (OPA unavailable = permissive).
        Fails closed on explicit OPA deny.
        """
        rego_package = self._route_action(action)
        opa_input = {
            "principal": {"type": principal_type, "id": principal_id},
            "action": action,
            "resource": {"type": resource_type, "id": resource_id},
            "context": context,
        }
        return self._query_opa(rego_package, opa_input)

    def _route_action(self, action: str) -> str:
        """Route action to the correct OPA Rego package path."""
        if action.startswith("consent::"):
            return "aevum/consent/allow"
        if action.startswith("classification::"):
            return "aevum/classification_ceiling/allow"
        if action.startswith("provenance::"):
            return "aevum/provenance/allow"
        return "aevum/authz/allow"

    def _query_opa(self, path: str, input_data: dict[str, Any]) -> bool:
        """POST to OPA and return the boolean decision. Fails open on any error."""
        try:
            response = self._client.post(
                f"{self._opa_url}/v1/data/{path}",
                json={"input": input_data},
            )
            if response.status_code != 200:
                logger.warning(
                    "OPA returned %d for %s — failing open",
                    response.status_code, path,
                )
                return True
            result = response.json()
            return bool(result.get("result", True))
        except Exception as exc:  # noqa: BLE001
            logger.warning("OPA query failed for %s — failing open: %s", path, exc)
            return True

    def close(self) -> None:
        self._client.close()

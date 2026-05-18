"""OPA HTTP sidecar adapter. Implements PolicyEngine via the OPA REST API."""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("aevum.policy.opa")


class OPAPolicyEngine:
    """
    OPA sidecar policy engine (http://opa:8181).
    Used for content-based rules (HIPAA minimum-necessary, PCI scope, etc.).
    Cedar handles entity ABAC; OPA handles payload/content policy.
    Fails OPEN for policy-layer decisions per ADR-005.
    Absolute barriers are never delegated to OPA.
    """

    def __init__(self, url: str, *, timeout: float = 2.0) -> None:
        self._url = url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)

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
        """Query OPA. Returns True on network error (fail-open per ADR-005)."""
        try:
            resp = self._client.post(
                f"{self._url}/v1/data/aevum/allow",
                json={
                    "input": {
                        "principal": {"type": principal_type, "id": principal_id},
                        "action": action,
                        "resource": {"type": resource_type, "id": resource_id},
                        "context": context,
                    }
                },
            )
            resp.raise_for_status()
            return bool(resp.json().get("result", True))
        except Exception:  # noqa: BLE001
            logger.warning(
                "OPA unreachable — failing open for policy-layer decision"
            )
            return True

    def close(self) -> None:
        self._client.close()

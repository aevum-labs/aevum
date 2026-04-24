"""
PolicyBridge — routes to OPA and Cedar.
Phase 3: permissive stub. Real engines arrive Phase 6.
Every decision logged for auditability even in stub mode.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class PolicyBridge:
    """Hybrid OPA + Cedar policy bridge. Phase 3 = permissive stub."""

    def __init__(self, opa_url: str | None = None) -> None:
        self._opa_url = opa_url
        if not opa_url:
            logger.debug("PolicyBridge in permissive stub mode (Phase 3)")

    def evaluate_consent(self, *, subject_id: str, operation: str,
                         grantee_id: str, purpose: str, classification: int) -> bool:
        """Cedar consent. Phase 3: always permit (ConsentLedger handles this)."""
        return True

    def evaluate_infrastructure(self, *, actor: str, operation: str,
                                resource: dict[str, Any]) -> bool:
        """OPA infra policy. Phase 3: always permit."""
        return True

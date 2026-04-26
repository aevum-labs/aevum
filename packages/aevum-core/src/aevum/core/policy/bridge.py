"""
PolicyBridge -- OPA + Cedar hybrid policy engine.

Phase 9: Cedar consent decisions are real (cedarpy in-process).
OPA infrastructure policy is still permissive stub (requires k8s/Docker sidecar).

Cedar handles:
  - Consent grant validation (subject, grantee, operation, purpose, expiry)
  - Purpose specificity checks
  - Classification ceiling cross-check

cedarpy docs: https://pypi.org/project/cedarpy/
Cedar schema: a simple RBAC-style policy for Aevum grants.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Cedar policy for Aevum consent decisions.
# A request is ALLOWED if an active, non-expired grant covers the operation.
# Purpose must not be a generic placeholder.
# Classification must not exceed grant's classification_max.
_CEDAR_POLICY = """
permit(
    principal == User::"?principal",
    action == Action::"?operation",
    resource == Subject::"?subject"
)
when {
    context.grant_active == true &&
    context.purpose_specific == true &&
    context.classification_ok == true
};
"""


def _is_purpose_specific(purpose: str) -> bool:
    generic = {"any", "all", "all purposes", "any purpose", "analytics", ""}
    return purpose.lower().strip() not in generic


class PolicyBridge:
    """
    Hybrid OPA + Cedar policy bridge.

    Cedar: real in-process consent decisions (cedarpy).
    OPA: still permissive stub -- Phase 10+ adds sidecar.
    """

    def __init__(self, opa_url: str | None = None) -> None:
        self._opa_url = opa_url
        self._cedar_available = self._check_cedar()
        if not self._cedar_available:
            logger.warning(
                "cedarpy not installed -- PolicyBridge falling back to permissive mode. "
                "Install cedarpy for real Cedar consent enforcement."
            )
        elif opa_url:
            logger.info("OPA sidecar configured at %s (still permissive in Phase 9)", opa_url)

    @staticmethod
    def _check_cedar() -> bool:
        try:
            from cedarpy import is_authorized  # noqa: F401
            return True
        except ImportError:
            return False

    def evaluate_consent(
        self,
        *,
        subject_id: str,
        operation: str,
        grantee_id: str,
        purpose: str,
        classification: int,
        grant_active: bool = True,
        classification_max: int = 3,
    ) -> bool:
        """
        Cedar consent decision.

        If cedarpy is installed: real Cedar evaluation.
        If cedarpy is not installed: falls back to permissive (logs warning).

        Args:
            grant_active: Whether an active, unexpired grant exists
                          (checked by ConsentLedger before calling here)
            classification_max: Maximum classification this grant covers
        """
        # Fast-path checks -- always applied regardless of cedarpy availability
        if not grant_active:
            return False
        if classification > classification_max:
            return False
        if not _is_purpose_specific(purpose):
            return False

        if not self._cedar_available:
            return True  # Permissive fallback -- cedarpy not installed

        # Cedar evaluation (cedarpy 4.x API -- request is a plain dict)
        try:
            from cedarpy import Decision, is_authorized
            context = {
                "grant_active": grant_active,
                "purpose_specific": _is_purpose_specific(purpose),
                "classification_ok": classification <= classification_max,
            }
            request = {
                "principal": f'User::"{grantee_id}"',
                "action": f'Action::"{operation}"',
                "resource": f'Subject::"{subject_id}"',
                "context": context,
            }
            # entities list is empty -- decisions are context-driven, not entity-driven
            authz_result = is_authorized(request, _CEDAR_POLICY, [])
            return bool(authz_result.decision == Decision.Allow)
        except Exception as e:
            logger.warning("Cedar evaluation error: %s -- denying (fail-closed)", e)
            return False

    def evaluate_infrastructure(
        self,
        *,
        actor: str,
        operation: str,
        resource: dict[str, Any],
    ) -> bool:
        """
        OPA infrastructure policy.
        Phase 9: still permissive. Phase 10: HTTP call to OPA sidecar.
        """
        return True

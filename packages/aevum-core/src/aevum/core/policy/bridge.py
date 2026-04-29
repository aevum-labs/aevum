"""
PolicyBridge -- hybrid Cedar + OPA policy enforcement.

Cedar (in-process via cedarpy) handles consent decisions:
  - Grant validation, purpose specificity, classification ceiling
  - Fails gracefully to permissive if cedarpy is not installed

OPA (external sidecar via HTTP) handles infrastructure policy:
  - Actor-level access control, rate limiting, environment-aware rules
  - Configured via AEVUM_OPA_URL or Engine(opa_url=...)
  - Fails closed on any error: timeout, parse failure, non-200 response
  - Disabled (permissive) when opa_url is None or empty

Both engines are optional. Without either, Aevum runs with built-in
barrier enforcement only -- the five absolute barriers remain unconditional.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_GENERIC_PURPOSES = frozenset({
    "any", "all", "all purposes", "any purpose", "analytics", ""
})

# Cedar policy for consent decisions.
# Requests are permitted when: grant is active, purpose is specific,
# and the data classification does not exceed the grant ceiling.
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
    """Return True if the purpose is specific enough to be auditable."""
    return purpose.lower().strip() not in _GENERIC_PURPOSES


class PolicyBridge:
    """
    Hybrid Cedar + OPA policy bridge.

    Cedar evaluates consent decisions in-process (fast, no network).
    OPA evaluates infrastructure policy via HTTP sidecar (optional).
    Either engine may be absent; the other continues to function.
    """

    def __init__(self, opa_url: str | None = None) -> None:
        self._opa_url = opa_url.rstrip("/") if opa_url else None
        self._cedar_available = self._probe_cedar()
        self._http: httpx.Client | None = None

        if not self._cedar_available:
            logger.warning(
                "cedarpy not installed -- consent decisions are permissive. "
                "Install with: pip install 'aevum-core[cedar]'"
            )
        if self._opa_url:
            logger.info("OPA sidecar configured at %s", self._opa_url)
        else:
            logger.debug(
                "No OPA sidecar configured -- infrastructure policy is permissive. "
                "Set AEVUM_OPA_URL or pass opa_url= to Engine() to enable."
            )

    @staticmethod
    def _probe_cedar() -> bool:
        try:
            from cedarpy import is_authorized  # noqa: F401
            return True
        except ImportError:
            return False

    def _http_client(self) -> httpx.Client:
        """Lazy-initialise a shared httpx client for OPA calls."""
        if self._http is None:
            self._http = httpx.Client(timeout=5.0)
        return self._http

    # ── Cedar: consent decisions ──────────────────────────────────────────────

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
        Evaluate a consent request via Cedar.

        Fast-path denials skip the Cedar call entirely:
          - grant_active is False
          - classification exceeds classification_max
          - purpose is a generic placeholder

        Falls back to permissive when cedarpy is not installed.
        Fails closed (returns False) on any Cedar error.
        """
        if not grant_active:
            return False
        if classification > classification_max:
            return False
        if not _is_purpose_specific(purpose):
            return False

        if not self._cedar_available:
            return True  # Permissive fallback -- cedarpy not installed

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
            result = is_authorized(request, _CEDAR_POLICY, [])
            return bool(result.decision == Decision.Allow)
        except Exception as exc:
            logger.warning(
                "Cedar evaluation failed for %s/%s -- denying (fail-closed): %s",
                grantee_id, operation, exc,
            )
            return False

    # ── OPA: infrastructure policy ────────────────────────────────────────────

    def evaluate_infrastructure(
        self,
        *,
        actor: str,
        operation: str,
        resource: dict[str, Any],
    ) -> bool:
        """
        Evaluate infrastructure-level policy via OPA sidecar.

        Sends a POST to {opa_url}/v1/data/aevum/authz/allow with the
        request as the input bundle and returns the boolean result.

        Fails closed on any error: network timeout, parse failure, or
        non-200 response all return False. This prevents a misconfigured
        sidecar from silently permitting all traffic.

        Returns True (permissive) when no OPA URL is configured.
        """
        if not self._opa_url:
            return True

        input_bundle: dict[str, Any] = {
            "principal": actor,
            "action": operation,
            "resource": resource,
        }

        try:
            response = self._http_client().post(
                f"{self._opa_url}/v1/data/aevum/authz/allow",
                json={"input": input_bundle},
            )
            response.raise_for_status()
            return bool(response.json().get("result", False))
        except httpx.TimeoutException:
            logger.warning(
                "OPA sidecar timed out for %s/%s -- denying (fail-closed)",
                actor, operation,
            )
            return False
        except Exception as exc:
            logger.warning(
                "OPA sidecar error for %s/%s -- denying (fail-closed): %s",
                actor, operation, exc,
            )
            return False

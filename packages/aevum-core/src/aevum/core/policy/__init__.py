"""
Policy engine protocol for aevum-core.
The kernel accepts any object conforming to PolicyEngine.
Cedar is the default implementation. OPA is the secondary.
Neither is required — NullPolicyEngine is the permissive fallback.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

try:
    import cedarpy  # noqa: F401
    _CEDAR_AVAILABLE = True
except ImportError:
    _CEDAR_AVAILABLE = False


@runtime_checkable
class PolicyEngine(Protocol):
    """
    Vendor-agnostic policy evaluation interface.
    Machine test: swappable without touching any of the five functions.
    Brain test: every evaluation is logged to the sigchain before return.
    """

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
        """Return True if the action is permitted, False to deny."""
        ...


class NullPolicyEngine:
    """
    Permissive fallback. Permits everything above the absolute barriers.
    Used when no policy engine is configured or Cedar is not installed.
    Logs a WARNING at first use so operators know they are running without ABAC.
    """

    _warned: bool = False

    def is_permitted(self, **_: Any) -> bool:  # noqa: ANN401
        if not NullPolicyEngine._warned:
            import logging
            logging.getLogger("aevum.policy").warning(
                "No policy engine configured — all ABAC decisions are PERMIT. "
                "Install aevum-core[cedar] and configure CedarPolicyEngine "
                "for production deployments."
            )
            NullPolicyEngine._warned = True
        return True

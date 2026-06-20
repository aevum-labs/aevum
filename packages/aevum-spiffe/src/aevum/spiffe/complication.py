# SPDX-License-Identifier: Apache-2.0
"""
SpiffeComplication — SPIFFE agent identity via JWT-SVIDs.

ADR-006 implementation. See docs/adrs/adr-006-spiffe-integration.md.

Lifecycle note: the Engine has no on_approved callback mechanism. Callers
must invoke comp.on_approved(engine) explicitly after
engine.approve_complication("aevum-spiffe") to trigger attestation.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

log = logging.getLogger(__name__)

_DEFAULT_SOCKET = "unix:///tmp/spire-agent/public/api.sock"
_DEFAULT_AUDIENCE = ["aevum"]

# Module-level sentinel. Not a top-level import — py-spiffe is imported lazily
# inside _fetch_svid(). This name exists so tests can patch
# aevum.spiffe.complication.WorkloadApiClient without triggering a real import.
WorkloadApiClient: Any = None


class SpiffeComplication:
    """
    SPIFFE/SPIRE agent identity complication.

    When on_approved() is called, fetches a JWT-SVID from the SPIFFE Workload
    API and commits a spiffe.attested AuditEvent. When `commitment_key_id` is
    configured, the SPIFFE ID is bound via a v2 principal_identity commitment
    (HMAC, never stored raw — P2-IDENTITY-V2) rather than recorded directly in
    the payload; trust domain and other metadata are always recorded
    operationally. The JWT token itself is never stored.

    Failure modes (all non-fatal):
    - py-spiffe not installed: warn and skip
    - SPIFFE socket unavailable: warn and skip
    - Invalid SVID: warn and skip

    The complication never prevents Engine startup or operation.

    Engine integration (no automatic lifecycle hook):
        engine.install_complication(comp)
        engine.approve_complication("aevum-spiffe")
        comp.on_approved(engine)  # caller must invoke this explicitly
    """

    name: str = "aevum-spiffe"
    version: str = "0.4.0"
    capabilities: list[str] = ["spiffe-identity"]

    def __init__(
        self,
        socket_path: str | None = None,
        audience: list[str] | None = None,
        commitment_key_id: str | None = None,
    ) -> None:
        self._socket = socket_path or os.environ.get(
            "AEVUM_SPIFFE_SOCKET", _DEFAULT_SOCKET
        )
        self._audience = audience or list(_DEFAULT_AUDIENCE)
        self._commitment_key_id = commitment_key_id or os.environ.get(
            "AEVUM_SPIFFE_COMMITMENT_KEY_ID"
        )
        self._spiffe_id: str | None = None
        self._trust_domain: str | None = None
        self._attested: bool = False

    def manifest(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": "SPIFFE/SPIRE cryptographic agent identity via JWT-SVIDs",
            "capabilities": list(self.capabilities),
            "classification_max": 0,
            "functions": ["commit"],
            "auth": {"scopes_required": [], "public_key": None},
            "schema_version": "1.0",
        }

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def on_approved(self, engine: Any) -> None:
        """
        Call after engine.approve_complication("aevum-spiffe") to trigger
        SPIFFE attestation and emit the spiffe.attested event.

        The Engine does not call this automatically; callers must invoke it.
        """
        self._attest_and_emit(engine)

    def _attest_and_emit(self, engine: Any) -> None:
        try:
            spiffe_id, trust_domain, expiry = self._fetch_svid()
        except ImportError:
            log.warning(
                "aevum-spiffe: py-spiffe not installed. "
                "Install with: pip install aevum-spiffe[spiffe]. "
                "Continuing without agent identity attestation."
            )
            return
        except Exception as exc:
            log.warning(
                "aevum-spiffe: SPIFFE attestation failed (%s). "
                "Is SPIRE running at %s? "
                "Continuing without agent identity attestation.",
                exc,
                self._socket,
            )
            return

        self._spiffe_id = spiffe_id
        self._trust_domain = trust_domain
        self._attested = True

        self._commit_attested_event(engine, spiffe_id, trust_domain, expiry)
        log.info("aevum-spiffe: attested (trust_domain=%s)", trust_domain)

    def _fetch_svid(self) -> tuple[str, str, str]:
        """
        Fetch a JWT-SVID from the SPIFFE Workload API.
        Returns (spiffe_id, trust_domain, expiry_iso8601).
        Raises ImportError if py-spiffe is not installed.
        Raises Exception if attestation fails.
        """
        import datetime

        # Honour the module-level name so tests can patch it; fall back to lazy import.
        _module = sys.modules.get(__name__)
        wac = getattr(_module, "WorkloadApiClient", None) if _module else None
        if wac is None:
            from spiffe import WorkloadApiClient as _wac  # noqa: PLC0415
            wac = _wac

        with wac(workload_api_address=self._socket) as client:
            svid = client.fetch_jwt_svid(audiences=self._audience)

        spiffe_id = str(svid.spiffe_id)
        trust_domain = svid.spiffe_id.trust_domain.name
        expiry_dt = datetime.datetime.fromtimestamp(
            svid.expiry, tz=datetime.UTC
        )
        expiry = expiry_dt.isoformat()
        return spiffe_id, trust_domain, expiry

    def _commit_attested_event(
        self,
        engine: Any,
        spiffe_id: str,
        trust_domain: str,
        expiry: str,
    ) -> None:
        # spiffe_id goes to principal_identity (→ HMAC commitment), never the
        # payload — putting it in both would defeat the commitment. No iat: py-spiffe's
        # JwtSvid exposes only spiffe_id/audience/expiry, not an issued-at claim.
        payload = {
            "trust_domain": trust_domain,
            "audience": self._audience,
            "svid_type": "jwt",
            "source": "workload-api",
            "socket": self._socket,
            "expiry": expiry,
        }
        binding_kwargs: dict[str, Any] = {}
        if self._commitment_key_id is not None:
            from datetime import datetime as _datetime

            exp_epoch = int(_datetime.fromisoformat(expiry).timestamp())
            binding_kwargs = {
                "principal_identity": spiffe_id,
                "principal_claims": {
                    "iss": f"spiffe://{trust_domain}",
                    "aud": list(self._audience),
                    "exp": exp_epoch,
                },
                "commitment_key_id": self._commitment_key_id,
            }
        try:
            engine.commit(
                event_type="spiffe.attested",
                payload=payload,
                actor="aevum-spiffe",
                **binding_kwargs,
            )
        except Exception as exc:
            log.error("aevum-spiffe: failed to commit spiffe.attested event: %s", exc)

    # ── Public API for downstream complications ───────────────────────────────

    def get_actor_spiffe_id(self) -> str | None:
        """
        Return the attested SPIFFE ID, or None if not yet attested.

        Downstream complications can call this to add actor_spiffe_id to
        their event payloads:
            spiffe_comp = engine.get_active_complication_by_capability("spiffe-identity")
            spiffe_id = spiffe_comp.get_actor_spiffe_id() if spiffe_comp else None
        """
        return self._spiffe_id

    @property
    def is_attested(self) -> bool:
        """True if SPIFFE attestation succeeded."""
        return self._attested

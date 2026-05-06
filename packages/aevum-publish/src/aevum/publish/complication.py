"""
PublishComplication — Rekor v2 transparency log integration.

ADR-007 implementation. See docs/adrs/adr-007-transparency-log.md.

Lifecycle note: the Engine has no automatic on_approved callback mechanism.
Callers must invoke comp.on_approved(engine) explicitly after
engine.approve_complication("aevum-publish") to trigger checkpoint submission.
This matches the pattern established by aevum-spiffe.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from typing import Any

log = logging.getLogger(__name__)

_DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
_DEFAULT_EVERY_N = int(os.environ.get("AEVUM_PUBLISH_EVERY_N_EVENTS", "100"))
_DEFAULT_EVERY_S = int(os.environ.get("AEVUM_PUBLISH_EVERY_SECONDS", "300"))


def _compute_checkpoint_digest(
    sequence: int,
    prior_hash: str,
    signer_key_id: str,
    system_time: int,
) -> bytes:
    """
    SHA-256 digest of the canonical checkpoint record.

    Using SHA-256 (not SHA3-256) because Rekor's hashedrekord spec requires SHA-256.
    The chain's internal integrity uses SHA3-256; the external witness uses SHA-256.
    These are separate trust layers with different hash requirements.
    """
    record = json.dumps(
        {
            "sequence": sequence,
            "prior_hash": prior_hash,
            "signer_key_id": signer_key_id,
            "system_time": system_time,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(record).digest()


class PublishComplication:
    """
    Transparency log complication. Submits chain checkpoints to Rekor v2.

    Threshold triggers (whichever comes first):
    - every_n_events: submit after N events are written to the chain
    - every_seconds: submit after M seconds since last submission

    Failure modes:
    - httpx not installed: warn, skip
    - Rekor unreachable: warn, buffer for next threshold
    - Submission rejected: warn, log details

    NEVER blocks the Engine write path. NEVER raises in lifecycle hooks.

    Engine integration (no automatic lifecycle hook):
        engine.install_complication(comp)
        engine.approve_complication("aevum-publish")
        comp.on_approved(engine)  # caller must invoke this explicitly
    """

    name: str = "aevum-publish"
    version: str = "0.1.0"

    def __init__(
        self,
        rekor_url: str | None = None,
        every_n_events: int | None = None,
        every_seconds: int | None = None,
    ) -> None:
        self._rekor_url = (rekor_url or _DEFAULT_REKOR_URL).rstrip("/")
        self._every_n = every_n_events or _DEFAULT_EVERY_N
        self._every_s = every_seconds or _DEFAULT_EVERY_S
        self._engine: Any = None
        self._events_since_checkpoint: int = 0
        self._last_checkpoint_time: float = time.monotonic()
        self._lock = threading.Lock()
        self._enabled: bool = False

    def manifest(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": "Sigstore Rekor v2 transparency log checkpoints for chain verification",
            "capabilities": ["transparency-log"],
            "classification_max": 0,
            "functions": ["commit"],
            "auth": {"scopes_required": [], "public_key": None},
            "schema_version": "1.0",
        }

    # ── Lifecycle hook ────────────────────────────────────────────────────────
    # Mirrors aevum-spiffe pattern: Engine does not call this automatically.
    # Callers must invoke comp.on_approved(engine) explicitly after
    # engine.approve_complication("aevum-publish").

    def on_approved(self, engine: Any) -> None:
        """
        Call after engine.approve_complication("aevum-publish") to trigger
        initial checkpoint submission and enable event counting.

        The Engine does not call this automatically; callers must invoke it.
        """
        self._engine = engine
        self._enabled = True
        self._try_submit_checkpoint(reason="complication.approved")

    # ── Event counting hook ───────────────────────────────────────────────────

    def on_event_written(self) -> None:
        """
        Call after each successful event write to the chain. Checks both
        thresholds and submits a checkpoint if either is met.
        """
        if not self._enabled:
            return

        with self._lock:
            self._events_since_checkpoint += 1
            n_trigger = self._events_since_checkpoint >= self._every_n
            t_trigger = (time.monotonic() - self._last_checkpoint_time) >= self._every_s

        if n_trigger or t_trigger:
            reason = "n_events" if n_trigger else "interval"
            self._try_submit_checkpoint(reason=reason)

    # ── Checkpoint submission ─────────────────────────────────────────────────

    def _try_submit_checkpoint(self, reason: str = "threshold") -> None:
        """
        Attempt to submit a checkpoint to Rekor. Silently degrades on failure.
        Resets event counter and timer on success.
        """
        if self._engine is None:
            return

        try:
            entries = self._engine.get_ledger_entries()
        except Exception as exc:
            log.warning("aevum-publish: could not read ledger: %s", exc)
            return

        if not entries:
            return

        last = entries[-1]
        sequence = last.get("sequence", 0)
        prior_hash = last.get("prior_hash", "")
        signer_key_id = last.get("signer_key_id", "")
        system_time = last.get("system_time", 0)

        digest = _compute_checkpoint_digest(
            sequence, prior_hash, signer_key_id, system_time
        )

        try:
            log_index, entry_hash = self._submit_to_rekor(digest)
        except Exception as exc:
            log.warning(
                "aevum-publish: checkpoint submission failed (%s). "
                "Will retry at next threshold.",
                exc,
            )
            return

        self._write_checkpoint_event(
            log_index=log_index,
            entry_hash=entry_hash,
            chain_sequence=sequence,
            chain_prior_hash=prior_hash,
            reason=reason,
        )

        with self._lock:
            self._events_since_checkpoint = 0
            self._last_checkpoint_time = time.monotonic()

        log.info(
            "aevum-publish: checkpoint submitted — sequence=%d rekor_index=%d",
            sequence,
            log_index,
        )

    def _submit_to_rekor(self, digest: bytes) -> tuple[int, str]:
        """
        Submit a SHA-256 digest to Rekor v2 as a hashedrekord entry.
        Returns (log_index, entry_hash).
        Raises ImportError if httpx not installed.
        Raises httpx.HTTPError on submission failure.

        NOTE: The format below matches the Rekor v1 hashedrekord spec. Rekor v2
        (rekor-tiles) uses a different tile-based API; verify against
        https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md before
        production use.
        """
        try:
            import httpx  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "aevum-publish requires httpx. "
                "Install with: pip install aevum-publish[rekor]"
            ) from exc

        digest_hex = digest.hex()

        body = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": digest_hex,
                    }
                },
            },
        }

        resp = httpx.post(
            f"{self._rekor_url}/api/v1/log/entries",
            json=body,
            timeout=30.0,
        )
        resp.raise_for_status()

        data = resp.json()
        uuid_key = next(iter(data))
        entry = data[uuid_key]
        log_index = int(entry.get("logIndex", entry.get("log_index", -1)))
        return log_index, uuid_key

    def _write_checkpoint_event(
        self,
        log_index: int,
        entry_hash: str,
        chain_sequence: int,
        chain_prior_hash: str,
        reason: str,
    ) -> None:
        """Write transparency.checkpoint AuditEvent to the local sigchain."""
        try:
            self._engine._ledger.append(
                event_type="transparency.checkpoint",
                payload={
                    "rekor_log_index": log_index,
                    "rekor_entry_hash": entry_hash,
                    "rekor_server": self._rekor_url,
                    "chain_sequence": chain_sequence,
                    "chain_prior_hash": chain_prior_hash,
                    "checkpoint_reason": reason,
                },
                actor="aevum-publish",
            )
        except Exception as exc:
            log.error(
                "aevum-publish: failed to write transparency.checkpoint: %s", exc
            )

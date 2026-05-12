"""Session — per-request context carrier with async context manager."""

from __future__ import annotations

import dataclasses
import logging
from typing import Any

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Session:
    actor: str
    correlation_id: str | None = None
    episode_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    async def __aenter__(self) -> Session:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        # REMEMBER fires here regardless of how the session closes
        commit_type = "complete" if exc_type is None else "emergency"
        await self._remember(commit_type=commit_type)

    async def _remember(self, commit_type: str) -> None:
        """
        Mandatory COMMIT on session close. Called by __aexit__.
        Must not raise — if it fails, log and continue.
        Session close must not be blocked by a REMEMBER failure.

        Phase 1: structural stub. Full REMEMBER binding in Phase 2
        when the Session is wired to a Kernel and ledger.
        """
        try:
            await self._do_commit(commit_type=commit_type)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "REMEMBER failed for session %s (commit_type=%s): %s. "
                "This is a principle violation and must be investigated.",
                getattr(self, "episode_id", "unknown"), commit_type, exc,
            )

    async def _do_commit(self, commit_type: str) -> None:
        """
        Execute the REMEMBER commit. Override or replace in Phase 2
        when Session is bound to a Kernel/ledger.
        Phase 1: no-op (no ledger reference available on the data carrier).
        """

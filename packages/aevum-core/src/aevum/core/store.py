# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
ReceiptStore — protocol and null/stub implementations for the three-tier receipt store.

Three tiers (all in one SQLite file — see SqliteReceiptStore):
  crash_protected  locked=1; never rotated; survives operational rotation
  operational      default; 48-hour rolling window
  long_term        EU AI Act Art. 26(6) minimum; promoted from operational

See also: adr-010-three-tier-receipt-storage.md
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class ReceiptNotFoundError(Exception):
    """Raised when lock() is called for a receipt_hash that does not exist."""


@runtime_checkable
class ReceiptStore(Protocol):

    def put(
        self,
        receipt_hash: str,          # SHA3-256 hex of COSE_Sign1 bytes
        blob: bytes,                # raw COSE_Sign1 bytes
        entry_hash: str = "",       # sigchain_entry_hash for cross-reference
        rekor_entry_ref: str = "",  # Rekor entry UUID/URL (empty if not submitted)
        tier: str = "operational",  # 'crash_protected' | 'operational' | 'long_term'
    ) -> None: ...

    def get(self, receipt_hash: str) -> bytes | None: ...

    def lock(self, receipt_hash: str) -> None:
        """
        Escalate a receipt to crash_protected tier.
        Sets locked=1 and tier='crash_protected'.
        Idempotent — locking an already-locked receipt is safe.
        Raises ReceiptNotFoundError if receipt_hash does not exist.
        """
        ...

    def list_hashes(
        self,
        after: str | None = None,  # pagination cursor (receipt_hash)
        limit: int = 100,
        tier: str | None = None,   # filter by tier; None = all tiers
    ) -> list[str]: ...

    def put_ambient(
        self,
        snapshot_id: str,  # AmbientContextReceipt.snapshot_id
        blob: bytes,       # raw COSE_Sign1 bytes of ambient receipt
        session_id: str,
        trigger: str,      # SESSION_START | STATE_CHANGE | PERIODIC | INCIDENT_LOCK
    ) -> None: ...

    def get_ambient(self, snapshot_id: str) -> bytes | None: ...


class NullReceiptStore:
    """
    Discards all receipts. Used in tests that do not exercise storage.
    Does NOT satisfy I6-CRASH_PROTECTED. Never use in production.
    """

    def put(
        self,
        receipt_hash: str,
        blob: bytes,
        entry_hash: str = "",
        rekor_entry_ref: str = "",
        tier: str = "operational",
    ) -> None:
        pass

    def get(self, receipt_hash: str) -> bytes | None:
        return None

    def lock(self, receipt_hash: str) -> None:
        # silently no-ops
        pass

    def list_hashes(
        self,
        after: str | None = None,
        limit: int = 100,
        tier: str | None = None,
    ) -> list[str]:
        return []

    def put_ambient(
        self,
        snapshot_id: str,
        blob: bytes,
        session_id: str,
        trigger: str,
    ) -> None:
        pass

    def get_ambient(self, snapshot_id: str) -> bytes | None:
        return None


class PostgresReceiptStore:
    """
    Stub for multi-process deployments using PostgreSQL.
    SQLite WAL does NOT support concurrent writers across processes.
    For multi-process agent deployments, use this backend.
    Requires: pip install aevum-core[postgres] (adds asyncpg or psycopg2)
    """

    def __init__(self, dsn: str) -> None:
        raise NotImplementedError(
            "PostgresReceiptStore is not yet implemented. "
            "Use SqliteReceiptStore for single-process deployments. "
            "Track: github.com/aevum-labs/aevum/issues (postgres-store label)"
        )

    def put(self, *args: object, **kwargs: object) -> None:
        raise NotImplementedError()

    def get(self, *args: object, **kwargs: object) -> bytes | None:
        raise NotImplementedError()

    def lock(self, *args: object, **kwargs: object) -> None:
        raise NotImplementedError()

    def list_hashes(self, *args: object, **kwargs: object) -> list[str]:
        raise NotImplementedError()

    def put_ambient(self, *args: object, **kwargs: object) -> None:
        raise NotImplementedError()

    def get_ambient(self, *args: object, **kwargs: object) -> bytes | None:
        raise NotImplementedError()

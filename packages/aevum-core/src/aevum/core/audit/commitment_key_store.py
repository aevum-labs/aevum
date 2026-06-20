# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
CommitmentKeyStore — secure-erasable key material for principal-commitment binding.

P2-IDENTITY-V2 (DD1, DD5, DD6, DD8, spec aevum-signing-v2.md). A commitment key is
the HMAC-SHA256 secret used to compute AuditEvent.principal_commitment (see
aevum.core.audit.event.compute_principal_commitment): it lets an investigator who
holds the key confirm that a given external credential identity (OIDC sub / SPIFFE
ID / DID) produced a given signed event, without that identity ever being stored in
the clear on the chain.

Modeled structurally on aevum.core.consent.ledger.ConsentLedger (SQLite-backed,
PRAGMA secure_delete=ON, crypto-shred on destroy) but DELIBERATELY uses a disjoint
vocabulary (DD8): `scope` / `principal` / `commitment_key_id`, never "subject" —
ConsentLedger's "subject" means the GDPR data subject; this store's "principal"
means the bound CREDENTIAL identity of an actor. Conflating the two vocabularies
would make it easy to mix up two genuinely different concepts that happen to share
a shape. See KNOWN_UNKNOWNS.md for the two-"subject" distinction.

DD5 (deployment-scope granularity): one commitment key typically covers an entire
deployment scope. Destroying it erases the ability to re-derive or confirm ANY
principal_commitment computed under that key — a coarse, all-or-nothing erasure.
Per-principal key granularity is a future refinement that needs no signed-format
change (principal_commitment_key_id already identifies which key was used).

DD6: chain verification never calls into this store — principal_commitment is
opaque signed bytes to the verifier. Only identity-matching (confirming a specific
external credential produced a given commitment) needs the key.
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from aevum.core.audit.event import AuditEvent, compute_principal_commitment

if TYPE_CHECKING:
    from aevum.core.protocols.audit_ledger import AuditLedgerProtocol


class CommitmentKeyStore:
    """Secure-erasable store of HMAC-SHA256 commitment keys, keyed by commitment_key_id.

    db_path=":memory:" for in-process or test usage (data lost on close).
    Pass a Path for persistent storage in production deployments.
    """

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        # secure_delete: deleted key bytes are overwritten with zeros on disk
        # (including the rollback journal) rather than merely unlinked from the
        # page index. Required so that destroy() actually makes the commitment
        # key unrecoverable, not just unindexed — the same guarantee ConsentLedger
        # makes for its DEK vault.
        self._conn.execute("PRAGMA secure_delete=ON;")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS commitment_keys (
                commitment_key_id  TEXT PRIMARY KEY,
                scope               TEXT NOT NULL,
                key_bytes           BLOB NOT NULL,
                created_at          TEXT NOT NULL
            );
        """)
        self._conn.commit()

    def create_key(
        self,
        scope: str,
        commitment_key_id: str | None = None,
        key_bytes: bytes | None = None,
    ) -> str:
        """Create and store a new commitment key for `scope`. Returns its commitment_key_id.

        Key material resolution (constructor-arg overrides env var overrides
        autogen — the same priority InProcessSigner/SigningConfig use elsewhere):
          1. `key_bytes` argument, if provided (must be 32 bytes).
          2. AEVUM_COMMITMENT_KEY env var (hex-encoded 32 bytes), if set.
          3. os.urandom(32) — a fresh, ephemeral key.
        """
        key_id = commitment_key_id or str(uuid.uuid4())
        if key_bytes is not None:
            resolved_key = key_bytes
        else:
            env_hex = os.environ.get("AEVUM_COMMITMENT_KEY")
            resolved_key = bytes.fromhex(env_hex) if env_hex else os.urandom(32)
        if len(resolved_key) != 32:
            raise ValueError(f"commitment key must be 32 bytes, got {len(resolved_key)}")

        self._conn.execute(
            "INSERT INTO commitment_keys VALUES (?, ?, ?, ?)",
            (key_id, scope, resolved_key, datetime.now(UTC).isoformat()),
        )
        self._conn.commit()
        return key_id

    def get_key(self, commitment_key_id: str) -> bytes | None:
        """Retrieve the raw key bytes for commitment_key_id. Returns None if destroyed/absent."""
        row = self._conn.execute(
            "SELECT key_bytes FROM commitment_keys WHERE commitment_key_id = ?",
            (commitment_key_id,),
        ).fetchone()
        result: bytes | None = row[0] if row else None
        return result

    def scope_for(self, commitment_key_id: str) -> str | None:
        """Retrieve the scope a commitment_key_id was created for. None if destroyed/absent."""
        row = self._conn.execute(
            "SELECT scope FROM commitment_keys WHERE commitment_key_id = ?",
            (commitment_key_id,),
        ).fetchone()
        result: str | None = row[0] if row else None
        return result

    def commitment_for(self, commitment_key_id: str, principal: str) -> str | None:
        """Compute the principal_commitment for `principal` under commitment_key_id.

        Returns None if the key has been destroyed (or never existed) — callers
        cannot distinguish "destroyed" from "never existed" by design; both mean
        the commitment can no longer be confirmed (DD5, GDPR Art. 17 parity with
        ConsentLedger.shred()).
        """
        key = self.get_key(commitment_key_id)
        if key is None:
            return None
        return compute_principal_commitment(key, principal)

    def destroy(
        self,
        commitment_key_id: str,
        *,
        ledger: AuditLedgerProtocol,
        actor: str,
        episode_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        """Erase commitment_key_id, then append an auditable commitment_key.destroyed
        event to `ledger` recording that the erasure occurred.

        Uses the EXISTING ledger-append mechanism (ledger.append) directly — no new
        persistence path. The event records `scope` (captured before deletion) and
        `commitment_key_id` so that an investigator can see WHICH deployment scope
        lost the ability to confirm its commitments, and WHEN, without the audit
        chain ever holding the key material itself.

        Erasure is coarse (DD5): destroying a key erases the ability to confirm or
        re-derive EVERY principal_commitment computed under it, not just one
        principal's. The signed chain entries that reference commitment_key_id are
        untouched (append-only) — only the ability to interpret their
        principal_commitment field via this key is lost.

        Authorization is the caller's responsibility: this method does not check
        whether the caller may destroy commitment_key_id. Callers must verify
        authorization (e.g. via the policy engine) before invoking it.
        """
        scope = self.scope_for(commitment_key_id)
        self._conn.execute(
            "DELETE FROM commitment_keys WHERE commitment_key_id = ?",
            (commitment_key_id,),
        )
        self._conn.commit()
        return ledger.append(
            event_type="commitment_key.destroyed",
            payload={"commitment_key_id": commitment_key_id, "scope": scope},
            actor=actor,
            episode_id=episode_id,
            correlation_id=correlation_id,
        )

    def close(self) -> None:
        self._conn.close()

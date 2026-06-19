# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Consent ledger: OR-Set CRDT with AES-256-GCM DEK vault.

The consent ledger tracks per-subject, per-purpose consent grants.
Revocation is immediate. Crypto-shredding destroys the subject's DEK,
making all encrypted data permanently unreadable without breaking the
audit chain (which stores only hashes, not plaintext).

GDPR Art. 17: destroy DEK → encryption unreadable → erasure demonstrated.
The audit chain entry stays (append-only) — it proves erasure occurred.

OR-Set CRDT semantics:
  - Add/grant: add a (subject, purpose, expiry) tuple to the add-set
  - Remove/revoke: add the same ID to the remove-set
  - Check: ID is in add-set AND NOT in remove-set AND not expired
  - OR-Set: concurrent adds and removes are resolved by bias toward add
    (in Aevum's single-node case, revoke always wins — no concurrent ops)
"""
from __future__ import annotations

import dataclasses
import os
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    from aevum.core.consent.models import ConsentGrant as ProtocolConsentGrant


class ConsentRequired(Exception):
    """Raised when a DEK-protected operation cannot proceed because the DEK was shredded.

    Despite the name, this is NOT the same as Barrier 3 (Consent). ConsentRequired in this
    module is raised specifically by encrypt_for_subject() and decrypt_for_subject() when
    the subject's AES-256-GCM data encryption key (DEK) has been destroyed by shred().
    The "required" is: the DEK is required for the operation but is gone (GDPR Art. 17
    erasure was exercised). Barrier 3 (no consent grant) is enforced in barriers.py and
    returns an error OutputEnvelope rather than raising.
    """


class ConsentExpired(Exception):
    """Raised when a consent grant has expired."""


@dataclasses.dataclass(frozen=True)
class ConsentGrant:
    """An active consent grant record (Phase 3 OR-Set CRDT ledger)."""
    grant_id: str
    subject: str
    purpose: str
    granted_at: datetime
    expires_at: datetime | None

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(UTC) > self.expires_at


class ConsentLedger:
    """Consent ledger with OR-Set CRDT semantics and AES-256-GCM DEK vault.

    All grant/revoke operations are persisted to SQLite immediately. The schema uses two
    tables — consent_grants (add-set) and consent_revocations (remove-set) — implementing
    OR-Set semantics: a grant is active if it is in consent_grants, NOT in consent_revocations,
    and not yet expired. This structure means revocation is immediate and non-destructive:
    the original grant record is preserved for audit purposes.

    The DEK vault (dek_vault table) maps subject_id to a 32-byte AES-256-GCM key. All
    subject data encrypted with this key becomes permanently unreadable when shred() deletes
    the key row. The grant audit records remain (append-only) — this separation of concerns
    is what makes GDPR Art. 17 erasure provable: the chain shows "erasure happened" while
    the encrypted data becomes irrecoverable.

    db_path=":memory:" for in-process or test usage (data lost on close).
    Pass a Path for persistent storage in production deployments.
    """

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        # secure_delete: deleted DEK bytes are overwritten with zeros on disk
        # (including the rollback journal) rather than merely unlinked from
        # the page index. Required for the GDPR Art. 17 erasure guarantee
        # that shred() actually makes the DEK unrecoverable, not just unindexed.
        self._conn.execute("PRAGMA secure_delete=ON;")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS consent_grants (
                grant_id    TEXT PRIMARY KEY,
                subject     TEXT NOT NULL,
                purpose     TEXT NOT NULL,
                granted_at  TEXT NOT NULL,
                expires_at  TEXT
            );
            CREATE TABLE IF NOT EXISTS consent_revocations (
                grant_id    TEXT PRIMARY KEY,
                revoked_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dek_vault (
                subject_id  TEXT PRIMARY KEY,
                dek_bytes   BLOB NOT NULL,
                created_at  TEXT NOT NULL
            );
        """)
        self._conn.commit()

    # ── Phase 3 OR-Set CRDT API ───────────────────────────────────────────────

    def grant(
        self,
        subject: str,
        purpose: str,
        expiry_seconds: int | None = None,
    ) -> ConsentGrant:
        """
        Grant consent for subject/purpose.
        Creates a DEK for the subject if one doesn't exist.
        """
        grant_id = str(uuid.uuid4())
        now = datetime.now(UTC)
        expires_at = None
        if expiry_seconds is not None:
            expires_at = now + timedelta(seconds=expiry_seconds)

        self._conn.execute(
            "INSERT INTO consent_grants VALUES (?, ?, ?, ?, ?)",
            (grant_id, subject, purpose, now.isoformat(),
             expires_at.isoformat() if expires_at else None),
        )
        self._conn.commit()

        self._ensure_dek(subject)

        return ConsentGrant(
            grant_id=grant_id,
            subject=subject,
            purpose=purpose,
            granted_at=now,
            expires_at=expires_at,
        )

    def revoke(self, subject: str, purpose: str) -> None:
        """
        Revoke all consent grants for subject/purpose.
        Does NOT destroy the DEK — use shred() for Art. 17 erasure.
        """
        now = datetime.now(UTC).isoformat()
        grants = self._conn.execute(
            "SELECT grant_id FROM consent_grants "
            "WHERE subject = ? AND purpose = ?",
            (subject, purpose),
        ).fetchall()
        for (grant_id,) in grants:
            self._conn.execute(
                "INSERT OR IGNORE INTO consent_revocations VALUES (?, ?)",
                (grant_id, now),
            )
        self._conn.commit()

    def check(self, subject: str, purpose: str) -> bool:
        """
        Check if subject has active, unexpired consent for purpose.
        Returns True if at least one valid grant exists.
        """
        rows = self._conn.execute(
            """
            SELECT g.grant_id, g.expires_at
            FROM consent_grants g
            WHERE g.subject = ?
              AND g.purpose = ?
              AND g.grant_id NOT IN (SELECT grant_id FROM consent_revocations)
            """,
            (subject, purpose),
        ).fetchall()

        now = datetime.now(UTC)
        for _grant_id, expires_at_str in rows:
            if expires_at_str is None:
                return True  # no expiry
            expires_at = datetime.fromisoformat(expires_at_str)
            if now <= expires_at:
                return True
        return False

    def shred(self, subject: str) -> None:
        """
        GDPR Art. 17 erasure: destroy the subject's DEK.
        All data encrypted with this DEK becomes permanently unreadable.
        The grant records remain (audit trail) but the data is gone.

        Atomic: the DELETE and commit are a single SQLite transaction, so a
        crash cannot leave a half-erased DEK — the row is either fully
        present or fully gone. PRAGMA secure_delete=ON (set in _init_schema)
        ensures the deleted bytes are zeroed on disk rather than merely
        unlinked from the page index.

        Authorization is the caller's responsibility: this method does not
        check whether the caller may erase `subject`'s data. Callers must
        verify authorization (e.g. via the policy engine) before invoking it.
        """
        self._conn.execute(
            "DELETE FROM dek_vault WHERE subject_id = ?", (subject,)
        )
        self._conn.commit()

    def get_dek(self, subject: str) -> bytes | None:
        """Retrieve the DEK for a subject. Returns None if shredded."""
        row = self._conn.execute(
            "SELECT dek_bytes FROM dek_vault WHERE subject_id = ?", (subject,)
        ).fetchone()
        result: bytes | None = row[0] if row else None
        return result

    def encrypt_for_subject(self, subject: str, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext with the subject's DEK using AES-256-GCM.
        Raises ConsentRequired if the DEK has been shredded.
        Returns: nonce (12 bytes) + ciphertext
        """
        dek = self.get_dek(subject)
        if dek is None:
            raise ConsentRequired(
                f"Cannot encrypt for subject {subject!r}: DEK has been shredded. "
                "This subject's data has been erased (GDPR Art. 17)."
            )
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_for_subject(self, subject: str, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext with the subject's DEK.
        Raises ConsentRequired if the DEK has been shredded (data erased).
        """
        dek = self.get_dek(subject)
        if dek is None:
            raise ConsentRequired(
                f"Cannot decrypt for subject {subject!r}: DEK has been shredded."
            )
        aesgcm = AESGCM(dek)
        nonce = ciphertext[:12]
        ct = ciphertext[12:]
        return aesgcm.decrypt(nonce, ct, None)

    def _ensure_dek(self, subject: str) -> None:
        """Create a DEK for subject if one doesn't exist."""
        existing = self._conn.execute(
            "SELECT subject_id FROM dek_vault WHERE subject_id = ?", (subject,)
        ).fetchone()
        if existing is None:
            dek = os.urandom(32)  # 256-bit AES key
            self._conn.execute(
                "INSERT INTO dek_vault VALUES (?, ?, ?)",
                (subject, dek, datetime.now(UTC).isoformat()),
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ── ConsentLedgerProtocol backward-compat wrappers ────────────────────────
    # These adapt the Phase 3 API to the existing ConsentLedgerProtocol so that
    # the Engine can use ConsentLedger() without changes.

    def add_grant(self, grant: ProtocolConsentGrant) -> None:
        """Protocol compat: add a pre-built ConsentGrant to the ledger."""
        # Parse expires_at from the Pydantic model's string field
        try:
            expires_dt = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            expires_dt = None

        now_str = datetime.now(UTC).isoformat()
        self._conn.execute(
            "INSERT OR IGNORE INTO consent_grants VALUES (?, ?, ?, ?, ?)",
            (grant.grant_id, grant.subject_id, grant.purpose,
             now_str, expires_dt.isoformat() if expires_dt else None),
        )
        self._conn.commit()
        self._ensure_dek(grant.subject_id)

    def revoke_grant(self, grant_id: str) -> None:
        """Protocol compat: revoke by grant_id."""
        now = datetime.now(UTC).isoformat()
        self._conn.execute(
            "INSERT OR IGNORE INTO consent_revocations VALUES (?, ?)",
            (grant_id, now),
        )
        self._conn.commit()

    def has_consent(
        self,
        *,
        subject_id: str,
        operation: str,
        grantee_id: str,
        purpose: str | None = None,
    ) -> bool:
        """
        Protocol compat: check if subject has active consent for any purpose.
        Checks across all purposes (or specific purpose if provided).
        """
        query = """
            SELECT g.grant_id, g.expires_at
            FROM consent_grants g
            WHERE g.subject = ?
              AND g.grant_id NOT IN (SELECT grant_id FROM consent_revocations)
        """
        params: list[str] = [subject_id]
        if purpose is not None:
            query += " AND g.purpose = ?"
            params.append(purpose)

        rows = self._conn.execute(query, params).fetchall()
        now = datetime.now(UTC)
        for _grant_id, expires_at_str in rows:
            if expires_at_str is None:
                return True
            try:
                expires_at = datetime.fromisoformat(expires_at_str)
                if now <= expires_at:
                    return True
            except ValueError:
                continue
        return False

    def all_grants(self) -> list[ProtocolConsentGrant]:
        """Protocol compat: return all grants as Pydantic ConsentGrant objects."""
        from aevum.core.consent.models import ConsentGrant as PydanticGrant
        rows = self._conn.execute(
            "SELECT grant_id, subject, purpose, granted_at, expires_at "
            "FROM consent_grants"
        ).fetchall()
        revoked = {
            r[0] for r in self._conn.execute(
                "SELECT grant_id FROM consent_revocations"
            ).fetchall()
        }
        result: list[ProtocolConsentGrant] = []
        for grant_id, subject, purpose, granted_at, expires_at in rows:
            status = "revoked" if grant_id in revoked else "active"
            result.append(PydanticGrant(
                grant_id=grant_id,
                subject_id=subject,
                grantee_id="",
                operations=["ingest", "query"],
                purpose=purpose,
                classification_max=0,
                granted_at=granted_at,
                expires_at=expires_at or "9999-12-31T23:59:59+00:00",
                revocation_status=status,  # type: ignore[arg-type]
            ))
        return result

# SPDX-License-Identifier: Apache-2.0
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aevum.core.consent.ledger import ConsentLedger, ConsentRequired


def make_ledger(tmp_path: Path) -> ConsentLedger:
    return ConsentLedger(tmp_path / "test_consent.db")


class TestConsentGrant:
    def test_grant_returns_consent_grant(self, tmp_path):
        ledger = make_ledger(tmp_path)
        grant = ledger.grant("alice", "support")
        assert grant.subject == "alice"
        assert grant.purpose == "support"
        assert grant.grant_id

    def test_check_returns_true_after_grant(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        assert ledger.check("alice", "support")

    def test_check_returns_false_without_grant(self, tmp_path):
        ledger = make_ledger(tmp_path)
        assert not ledger.check("alice", "support")

    def test_check_purpose_mismatch_returns_false(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        assert not ledger.check("alice", "billing")

    def test_check_subject_mismatch_returns_false(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        assert not ledger.check("bob", "support")

    def test_grant_id_is_non_empty_string(self, tmp_path):
        ledger = make_ledger(tmp_path)
        grant = ledger.grant("alice", "support")
        assert isinstance(grant.grant_id, str)
        assert len(grant.grant_id) > 0

    def test_granted_at_is_timezone_aware(self, tmp_path):
        ledger = make_ledger(tmp_path)
        grant = ledger.grant("alice", "support")
        assert grant.granted_at.tzinfo is not None

    def test_multiple_purposes_independent(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ledger.grant("alice", "billing")
        assert ledger.check("alice", "support")
        assert ledger.check("alice", "billing")

    def test_multiple_subjects_independent(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ledger.grant("bob", "support")
        assert ledger.check("alice", "support")
        assert ledger.check("bob", "support")


class TestConsentRevoke:
    def test_revoke_makes_check_return_false(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ledger.revoke("alice", "support")
        assert not ledger.check("alice", "support")

    def test_revoke_does_not_affect_other_purpose(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ledger.grant("alice", "billing")
        ledger.revoke("alice", "support")
        assert not ledger.check("alice", "support")
        assert ledger.check("alice", "billing")

    def test_revoke_does_not_affect_other_subject(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ledger.grant("bob", "support")
        ledger.revoke("alice", "support")
        assert not ledger.check("alice", "support")
        assert ledger.check("bob", "support")

    def test_revoke_nonexistent_does_not_raise(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.revoke("alice", "never_granted")  # must not raise

    def test_revoke_idempotent(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ledger.revoke("alice", "support")
        ledger.revoke("alice", "support")  # second revoke must not raise
        assert not ledger.check("alice", "support")

    def test_regrant_after_revoke(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ledger.revoke("alice", "support")
        ledger.grant("alice", "support")  # re-grant
        assert ledger.check("alice", "support")


class TestConsentExpiry:
    def test_grant_without_expiry_does_not_expire(self, tmp_path):
        ledger = make_ledger(tmp_path)
        grant = ledger.grant("alice", "support", expiry_seconds=None)
        assert not grant.is_expired
        assert ledger.check("alice", "support")

    def test_grant_with_future_expiry_is_valid(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support", expiry_seconds=3600)
        assert ledger.check("alice", "support")

    def test_grant_with_past_expiry_not_valid(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support", expiry_seconds=-1)  # already expired
        assert not ledger.check("alice", "support")

    def test_grant_expires_at_is_set(self, tmp_path):
        ledger = make_ledger(tmp_path)
        grant = ledger.grant("alice", "support", expiry_seconds=3600)
        assert grant.expires_at is not None

    def test_grant_no_expiry_expires_at_is_none(self, tmp_path):
        ledger = make_ledger(tmp_path)
        grant = ledger.grant("alice", "support", expiry_seconds=None)
        assert grant.expires_at is None


class TestCryptoShredding:
    def test_encrypt_decrypt_roundtrip(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        plaintext = b"sensitive data"
        ciphertext = ledger.encrypt_for_subject("alice", plaintext)
        assert ciphertext != plaintext
        decrypted = ledger.decrypt_for_subject("alice", ciphertext)
        assert decrypted == plaintext

    def test_shred_prevents_decryption(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ciphertext = ledger.encrypt_for_subject("alice", b"data")
        ledger.shred("alice")
        with pytest.raises(ConsentRequired):
            ledger.decrypt_for_subject("alice", ciphertext)

    def test_shred_prevents_encryption(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ledger.shred("alice")
        with pytest.raises(ConsentRequired):
            ledger.encrypt_for_subject("alice", b"new data")

    def test_shred_does_not_affect_other_subject(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ledger.grant("bob", "support")
        ciphertext_bob = ledger.encrypt_for_subject("bob", b"bob data")
        ledger.shred("alice")
        decrypted = ledger.decrypt_for_subject("bob", ciphertext_bob)
        assert decrypted == b"bob data"

    def test_shred_does_not_erase_grant_records(self, tmp_path):
        """Audit trail stays even after shredding (append-only principle)."""
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ledger.shred("alice")
        row = ledger._conn.execute(
            "SELECT COUNT(*) FROM consent_grants WHERE subject = 'alice'"
        ).fetchone()
        assert row[0] > 0

    def test_get_dek_returns_none_after_shred(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        assert ledger.get_dek("alice") is not None
        ledger.shred("alice")
        assert ledger.get_dek("alice") is None

    def test_encrypt_different_nonce_each_time(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ct1 = ledger.encrypt_for_subject("alice", b"data")
        ct2 = ledger.encrypt_for_subject("alice", b"data")
        assert ct1 != ct2  # nonces differ → ciphertexts differ

    def test_ciphertext_longer_than_plaintext(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        plaintext = b"hello"
        ciphertext = ledger.encrypt_for_subject("alice", plaintext)
        # nonce (12) + GCM tag (16) + plaintext
        assert len(ciphertext) > len(plaintext)

    def test_get_dek_returns_bytes_when_present(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        dek = ledger.get_dek("alice")
        assert isinstance(dek, bytes)
        assert len(dek) == 32  # 256-bit AES key

    def test_shred_idempotent(self, tmp_path):
        ledger = make_ledger(tmp_path)
        ledger.grant("alice", "support")
        ledger.shred("alice")
        ledger.shred("alice")  # second shred must not raise
        assert ledger.get_dek("alice") is None


class TestSecureErasure:
    """GREEN: shred() must make the DEK unrecoverable from the raw db file,
    not just unindexed (PRAGMA secure_delete=ON)."""

    def test_init_schema_source_sets_secure_delete(self):
        """Pin the implementation directly. On this sandbox's SQLite build,
        secure_delete already defaults to ON via a compile-time flag (see
        test_without_secure_delete_marker_can_survive_deletion for proof the
        pragma is load-bearing on builds where it isn't) — so a purely
        behavioral check cannot, on its own, catch someone deleting the
        `PRAGMA secure_delete=ON;` line from _init_schema. This source check
        is the backstop."""
        import inspect
        source = inspect.getsource(ConsentLedger._init_schema)
        assert "secure_delete=on" in source.lower().replace(" ", "")

    def test_ledger_enables_secure_delete(self, tmp_path):
        ledger = ConsentLedger(tmp_path / "pragma_check.db")
        assert ledger._conn.execute("PRAGMA secure_delete;").fetchone()[0] == 1
        ledger.close()

    def test_shred_removes_dek_bytes_from_raw_file(self, tmp_path):
        db_path = tmp_path / "secure_erasure.db"
        ledger = ConsentLedger(db_path)
        marker = b"SECURE_DELETE_MARKER_" + os.urandom(8).hex().encode()
        ledger._conn.execute(
            "INSERT INTO dek_vault VALUES (?, ?, ?)",
            ("shred_subject", marker, datetime.now(UTC).isoformat()),
        )
        ledger._conn.commit()

        # Sanity check: the marker is actually on disk before shred (so the
        # assertion below proves erasure, not just that we never wrote it).
        assert marker in db_path.read_bytes()

        ledger.shred("shred_subject")
        ledger.close()

        assert marker not in db_path.read_bytes()

    def test_without_secure_delete_marker_can_survive_deletion(self, tmp_path):
        """Baseline proving the pragma is load-bearing: on a connection with
        secure_delete explicitly OFF, the same insert/delete/commit sequence
        leaves the DEK bytes recoverable on disk. This is the exposure
        PRAGMA secure_delete=ON (set in ConsentLedger._init_schema) closes —
        without it, some SQLite builds default OFF and shred() would not be
        a real erasure."""
        db_path = tmp_path / "secure_erasure_baseline.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA secure_delete=OFF;")
        conn.executescript("""
            CREATE TABLE dek_vault (
                subject_id  TEXT PRIMARY KEY,
                dek_bytes   BLOB NOT NULL,
                created_at  TEXT NOT NULL
            );
        """)
        conn.commit()
        marker = b"BASELINE_MARKER_" + os.urandom(8).hex().encode()
        conn.execute(
            "INSERT INTO dek_vault VALUES (?, ?, ?)",
            ("baseline_subject", marker, datetime.now(UTC).isoformat()),
        )
        conn.commit()
        conn.execute("DELETE FROM dek_vault WHERE subject_id = ?", ("baseline_subject",))
        conn.commit()
        conn.close()
        assert marker in db_path.read_bytes()


class TestConsentLedgerProtocolCompat:
    """Verify ConsentLedger still satisfies ConsentLedgerProtocol for Engine."""

    def test_default_constructor_no_args(self):
        ledger = ConsentLedger()  # in-memory, no path
        assert ledger is not None
        ledger.close()

    def test_has_consent_false_when_no_grants(self):
        ledger = ConsentLedger()
        result = ledger.has_consent(
            subject_id="alice", operation="ingest", grantee_id="agent"
        )
        assert not result
        ledger.close()

    def test_all_grants_empty_initially(self):
        ledger = ConsentLedger()
        assert ledger.all_grants() == []
        ledger.close()

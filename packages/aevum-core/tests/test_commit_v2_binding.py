# SPDX-License-Identifier: Apache-2.0
"""HO-G-PLUMB — v2 principal-binding reachable through the public append()/commit() path.

Before this change, Sigchain.new_event() already supported principal_identity /
principal_claims / commitment_key_id / commitment_key, but AuditLedgerProtocol.append()
(and therefore Engine.commit()) never accepted them — every entry committed through the
public API was sig_format_version=1, no matter what. These tests prove the v2 path is now
reachable end-to-end through engine.commit() (not just a Sigchain unit constructor), that
v1 callers are unaffected (SR3), and that the raw commitment key / principal_identity /
principal_claims never leak into logs or the stored AuditEvent (SR1/SR2).
"""
from __future__ import annotations

import dataclasses
import logging

import pytest

from aevum.core.audit.commitment_key_store import CommitmentKeyStore
from aevum.core.audit.event import MAX_PRINCIPAL_IDENTITY_LEN
from aevum.core.audit.ledger import InMemoryLedger
from aevum.core.audit.sigchain import Sigchain
from aevum.core.engine import Engine


def _v2_engine() -> tuple[Engine, InMemoryLedger, CommitmentKeyStore, str]:
    sc = Sigchain()
    store = CommitmentKeyStore()
    key_id = store.create_key(scope="test-deployment")
    ledger = InMemoryLedger(sc, commitment_key_store=store)
    engine = Engine(sigchain=sc, ledger=ledger)
    return engine, ledger, store, key_id


class TestV2ReachableViaEngineCommit:
    """Un-fakeable GREEN: a binding committed through engine.commit() (not a unit
    constructor) reads back as sig_format_version=2 with blob+commitment populated."""

    def test_principal_binding_reachable_via_engine_commit(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()

        result = engine.commit(
            event_type="app.principal_bound",
            payload={"k": "v"},
            actor="tester",
            principal_identity="urn:oidc:sub:alice",
            principal_claims={
                "iss": "https://idp.example",
                "aud": "aevum",
                "sub": "alice",
                "jti": "abc123",
            },
            commitment_key_id=key_id,
        )

        assert result.status == "ok"
        event = ledger.get(result.audit_id)
        assert event.sig_format_version == 2
        assert event.principal_commitment_key_id == key_id
        assert event.principal_commitment is not None
        assert event.principal_binding is not None
        assert engine.verify_sigchain() is True

    def test_commitment_key_id_alone_opts_into_v2_via_engine_commit(self) -> None:
        """DD2: a v2 entry may carry no external credential at all."""
        engine, ledger, _store, key_id = _v2_engine()

        result = engine.commit(
            event_type="app.v2_no_principal",
            payload={},
            actor="tester",
            commitment_key_id=key_id,
        )

        event = ledger.get(result.audit_id)
        assert event.sig_format_version == 2
        assert event.principal_commitment_key_id == key_id
        assert event.principal_binding is None
        assert event.principal_commitment is None


class TestV1UnaffectedByV2Plumbing:
    """SR3: existing v1 callers (no binding kwargs) keep producing v1 entries, and
    v1 chains still verify after the new optional kwargs are added everywhere."""

    def test_commit_without_binding_kwargs_stays_v1(self) -> None:
        e = Engine()
        result = e.commit(event_type="app.v1", payload={"a": 1}, actor="tester")
        assert result.status == "ok"
        event = e._ledger.get(result.audit_id)
        assert event.sig_format_version == 1
        assert event.principal_binding is None
        assert event.principal_commitment is None
        assert event.principal_commitment_key_id is None
        assert e.verify_sigchain() is True

    def test_mixed_v1_and_v2_chain_still_verifies(self) -> None:
        """DD4: sig_format_version may rise mid-chain without breaking verification."""
        engine, _ledger, _store, key_id = _v2_engine()
        engine.commit(event_type="app.v1_first", payload={}, actor="tester")
        engine.commit(
            event_type="app.v2_second",
            payload={},
            actor="tester",
            principal_identity="urn:oidc:sub:bob",
            commitment_key_id=key_id,
        )
        assert engine.verify_sigchain() is True


class TestSensitiveValuesNeverPersistedOrLogged:
    """SR1/SR2 un-fakeable proof: the raw commitment key, principal_identity, and
    principal_claims values appear in neither the application logs emitted during
    the commit, nor anywhere on the stored AuditEvent."""

    def test_raw_identity_claims_and_key_absent_from_logs_and_storage(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        engine, ledger, store, key_id = _v2_engine()
        raw_key = store.get_key(key_id)
        assert raw_key is not None

        secret_identity = "urn:oidc:sub:super-secret-alice-9f3e21"
        secret_claim_value = "super-secret-custom-claim-zzz"

        with caplog.at_level(logging.DEBUG):
            result = engine.commit(
                event_type="app.principal_bound",
                payload={"k": "v"},
                actor="tester",
                principal_identity=secret_identity,
                principal_claims={
                    "iss": "https://idp.example",
                    "aud": "aevum",
                    "sub": secret_identity,
                    "custom": secret_claim_value,
                },
                commitment_key_id=key_id,
            )
        assert result.status == "ok"

        event = ledger.get(result.audit_id)
        assert event.sig_format_version == 2
        assert event.principal_commitment is not None
        assert event.principal_binding is not None

        stored_repr = repr(dataclasses.asdict(event))
        assert secret_identity not in stored_repr
        assert secret_claim_value not in stored_repr
        assert raw_key.hex() not in stored_repr

        log_text = caplog.text
        assert secret_identity not in log_text
        assert secret_claim_value not in log_text
        assert raw_key.hex() not in log_text


class TestOversizedPrincipalBindingRejected:
    """SR4: oversized principal_identity is rejected through the public engine.commit()
    path too, not just at the Sigchain unit-constructor level."""

    def test_oversized_principal_identity_rejected_via_engine_commit(self) -> None:
        engine, _ledger, _store, key_id = _v2_engine()
        oversized = "x" * (MAX_PRINCIPAL_IDENTITY_LEN + 1)
        with pytest.raises(ValueError, match="principal_identity length"):
            engine.commit(
                event_type="app.oversized",
                payload={},
                actor="tester",
                principal_identity=oversized,
                commitment_key_id=key_id,
            )


class TestCommitmentKeyResolutionFailures:
    """SR1: resolve_commitment_key() fails closed when a key can't be resolved,
    and the raised message never includes the raw principal_identity (SR2)."""

    def test_principal_identity_without_commitment_key_id_rejected(self) -> None:
        engine, _ledger, _store, _key_id = _v2_engine()
        with pytest.raises(ValueError, match="commitment_key_id is required"):
            engine.commit(
                event_type="app.missing_key_id",
                payload={},
                actor="tester",
                principal_identity="urn:oidc:sub:alice",
            )

    def test_unresolvable_commitment_key_id_rejected_without_leaking_identity(self) -> None:
        engine, _ledger, _store, _key_id = _v2_engine()
        secret_identity = "urn:oidc:sub:leak-check-identity"
        with pytest.raises(ValueError) as exc_info:
            engine.commit(
                event_type="app.bad_key_id",
                payload={},
                actor="tester",
                principal_identity=secret_identity,
                commitment_key_id="nonexistent-key-id",
            )
        assert secret_identity not in str(exc_info.value)

    def test_ledger_without_commitment_key_store_rejects_principal_binding(self) -> None:
        """A ledger constructed without a CommitmentKeyStore fails closed (SR1) rather
        than silently dropping the binding."""
        e = Engine()  # default InMemoryLedger has no commitment_key_store configured
        with pytest.raises(ValueError, match="CommitmentKeyStore"):
            e.commit(
                event_type="app.no_store",
                payload={},
                actor="tester",
                principal_identity="urn:oidc:sub:alice",
                commitment_key_id="some-key-id",
            )

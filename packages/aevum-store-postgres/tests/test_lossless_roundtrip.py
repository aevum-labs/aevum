# SPDX-License-Identifier: Apache-2.0
"""
HO-G-PG2 — lossless STORE CONTRACT round trip.

Before this fix, PostgresLedger silently dropped 10 of AuditEvent's 29 fields
on the store -> reconstruct round trip: key_scheme, hash_alg, mldsa65_sig,
mldsa65_pub, tsa_url, tsa_token, receipt_cbor, principal_binding,
principal_commitment, principal_commitment_key_id. Losing key_scheme was the
most severe of these: it is itself a SIGNED field, so a reconstructed event
silently defaulted to key_scheme="ed25519", and the verifier recomputed
signing_fields from that wrong value -- breaking even the primary Ed25519
check, not just ML-DSA-65 verification.

This is a STORE CONTRACT, not a postgres peculiarity: the field list driving
every assertion below comes from dataclasses.fields(AuditEvent) (never a
hand-maintained copy), and the ledger-level tests are parametrized over every
current AuditLedgerProtocol implementor (InMemoryLedger, PostgresLedger) so
the guarantee is enforced for any store, not just this one.
"""
from __future__ import annotations

import dataclasses

import pytest
from aevum.core.audit.commitment_key_store import CommitmentKeyStore
from aevum.core.audit.event import AuditEvent
from aevum.core.audit.ledger import InMemoryLedger
from aevum.core.audit.sigchain import Sigchain
from aevum.core.protocols.audit_ledger import AuditLedgerProtocol

from aevum.store.postgres.ledger import PostgresLedger, _event_to_row, _row_to_event

try:
    import oqs as _oqs_check  # noqa: F401

    _DUAL_SIGNER_AVAILABLE = True
except (ImportError, OSError, SystemExit):
    _DUAL_SIGNER_AVAILABLE = False

if _DUAL_SIGNER_AVAILABLE:
    from aevum.core.signing import DualSigner

from test_ledger import FakeConn

_ALL_FIELDS = [f.name for f in dataclasses.fields(AuditEvent)]


def _assert_lossless(original: AuditEvent, reconstructed: AuditEvent) -> None:
    """Assert every dataclasses.fields(AuditEvent) field round-tripped byte-identical.

    Driven by the programmatic field list rather than a hand-maintained copy --
    a field added to AuditEvent that a store forgets to carry fails here
    automatically, for any AuditLedgerProtocol implementor this helper is used
    against.
    """
    for field in _ALL_FIELDS:
        original_value = getattr(original, field)
        reconstructed_value = getattr(reconstructed, field)
        assert reconstructed_value == original_value, (
            f"field {field!r} did not round-trip losslessly: "
            f"original={original_value!r} reconstructed={reconstructed_value!r}"
        )
    assert reconstructed == original


def _build_variants() -> list[tuple[str, AuditEvent]]:
    """One signed AuditEvent per signer-config variant, each from a fresh
    chain (sequence=1, prior_hash=GENESIS_HASH) so it can be independently
    re-verified with no further chain state required."""
    variants: list[tuple[str, AuditEvent]] = []

    classical = Sigchain().new_event(
        event_type="rt.classical", payload={"a": 1}, actor="tester"
    )
    variants.append(("classical", classical))

    if _DUAL_SIGNER_AVAILABLE:
        hybrid = Sigchain(dual_signer=DualSigner.generate()).new_event(
            event_type="rt.hybrid", payload={"b": 2}, actor="tester"
        )
        variants.append(("hybrid", hybrid))

        hybrid_tsa = Sigchain(dual_signer=DualSigner.generate()).new_event(
            event_type="rt.hybrid_tsa", payload={"c": 3}, actor="tester"
        )
        # tsa_url / tsa_token are attached attestation metadata, not signed
        # fields (see AuditEvent.hash_event_for_chain) -- a live RFC 3161
        # exchange is exercised in aevum-core's own TSA tests (never send real
        # TSA requests from a test suite); this test's job is the STORE's
        # fidelity for whatever value is already present on the event.
        hybrid_tsa = dataclasses.replace(
            hybrid_tsa,
            tsa_url="https://timestamp.example/api/v1/timestamp",
            tsa_token="deadbeef" * 8,
            receipt_cbor=b"\xa1\x01\x02cose-receipt-test-blob",
        )
        variants.append(("hybrid+tsa+receipt", hybrid_tsa))

    v2 = Sigchain().new_event(
        event_type="rt.v2",
        payload={"d": 4},
        actor="tester",
        commitment_key_id="commitment-key-1",
        principal_identity="urn:oidc:sub:alice",
        principal_claims={
            "iss": "https://idp.example",
            "aud": "aevum",
            "sub": "alice",
            "jti": "abc123",
            "cnf": {"jkt": "thumbprint-value", "raw_key": "must-not-survive"},
        },
        commitment_key=b"0" * 32,
    )
    variants.append(("v2-principal-binding", v2))

    return variants


_VARIANTS = _build_variants()
_VARIANT_IDS = [name for name, _ in _VARIANTS]


class TestEventRowRoundTrip:
    """Direct round trip through the store's serialize/deserialize boundary.

    _event_to_row / _row_to_event ARE the persistence boundary -- the SQL
    INSERT/SELECT around them are mechanical pass-throughs of the dict they
    produce/consume. This is the precise unit the field-drop bug lived in.
    """

    @staticmethod
    def _row(event: AuditEvent) -> dict:
        # "sequence" is the BIGSERIAL primary key -- DB-assigned on INSERT, not
        # part of _event_to_row's output. Simulate what a real SELECT would
        # hand back: the row's sequence column matching the signed event.sequence
        # (the INSERT-only ledger keeps these in lockstep by construction).
        row = _event_to_row(event)
        row["sequence"] = event.sequence
        return row

    @pytest.mark.parametrize("name,event", _VARIANTS, ids=_VARIANT_IDS)
    def test_round_trip_every_field(self, name: str, event: AuditEvent) -> None:
        reconstructed = _row_to_event(self._row(event))
        _assert_lossless(event, reconstructed)

    @pytest.mark.parametrize("name,event", _VARIANTS, ids=_VARIANT_IDS)
    def test_reconstructed_chain_hash_unchanged(self, name: str, event: AuditEvent) -> None:
        """hash_event_for_chain must be unaffected by the round trip -- otherwise
        every subsequent prior_hash in a real chain would silently diverge after
        a restart (see PostgresLedger._resume_chain_from_db)."""
        reconstructed = _row_to_event(self._row(event))
        assert AuditEvent.hash_event_for_chain(reconstructed) == AuditEvent.hash_event_for_chain(
            event
        )


@pytest.mark.parametrize(
    "ledger_factory",
    [
        pytest.param(
            lambda sc, store=None: InMemoryLedger(sc, commitment_key_store=store),
            id="InMemoryLedger",
        ),
        pytest.param(
            lambda sc, store=None: PostgresLedger(FakeConn(), sc, commitment_key_store=store),
            id="PostgresLedger",
        ),
    ],
)
class TestLedgerRoundTripAllStores:
    """Parametrized over every current AuditLedgerProtocol implementor (Gate
    P-b) -- InMemoryLedger and PostgresLedger. Exercises real append()/get()/
    all_events() for the signer configs the shared ledger.append() API
    supports today (classical, hybrid, v2 principal-binding). TSA/receipt_cbor
    fields are still exercised only at the _event_to_row/_row_to_event boundary
    above, since no ledger's append() plumbs those through (a TSA exchange is
    attached metadata, not something append() accepts as input)."""

    def test_satisfies_protocol(self, ledger_factory) -> None:
        ledger = ledger_factory(Sigchain())
        assert isinstance(ledger, AuditLedgerProtocol)

    def test_classical_append_get_round_trip_and_verifies(self, ledger_factory) -> None:
        sc = Sigchain()
        ledger = ledger_factory(sc)
        event = ledger.append(event_type="rt.classical", payload={"a": 1}, actor="tester")
        fetched = ledger.get(event.audit_id())
        _assert_lossless(event, fetched)
        assert sc.verify_chain([fetched]) is True

    @pytest.mark.skipif(not _DUAL_SIGNER_AVAILABLE, reason="requires liboqs-python ([pqc] extra)")
    def test_hybrid_append_get_round_trip_and_verifies(self, ledger_factory) -> None:
        """Un-fakeable GREEN criterion (a): DualSigner + ledger must verify
        end-to-end. Before the HO-G-PG2 fix this failed -- the fetched event
        silently defaulted key_scheme back to "ed25519" and dropped
        mldsa65_sig/mldsa65_pub entirely, breaking even the primary Ed25519
        check (key_scheme is itself a signed field)."""
        dual = DualSigner.generate()
        sc = Sigchain(dual_signer=dual)
        ledger = ledger_factory(sc)
        event = ledger.append(event_type="rt.hybrid", payload={"b": 2}, actor="tester")
        fetched = ledger.get(event.audit_id())
        _assert_lossless(event, fetched)
        assert fetched.key_scheme == "ed25519+ml-dsa-65"
        assert fetched.mldsa65_sig is not None
        assert sc.verify_chain([fetched]) is True

    @pytest.mark.skipif(not _DUAL_SIGNER_AVAILABLE, reason="requires liboqs-python ([pqc] extra)")
    def test_hybrid_multi_event_chain_round_trip_and_verifies(self, ledger_factory) -> None:
        """Full-chain version of criterion (a): all_events() after several
        appends must verify as a chain, not just per-entry."""
        dual = DualSigner.generate()
        sc = Sigchain(dual_signer=dual)
        ledger = ledger_factory(sc)
        for i in range(3):
            ledger.append(event_type=f"rt.hybrid.{i}", payload={"i": i}, actor="tester")
        fetched_events = ledger.all_events()
        assert len(fetched_events) == 3
        assert sc.verify_chain(fetched_events) is True

    def test_v2_principal_binding_append_round_trip_and_verifies(self, ledger_factory) -> None:
        """HO-G-PLUMB: v2 principal-binding kwargs are now reachable through the
        public append() signature for every AuditLedgerProtocol implementor, not
        just through Sigchain.new_event() directly."""
        sc = Sigchain()
        store = CommitmentKeyStore()
        key_id = store.create_key(scope="test-deployment")
        ledger = ledger_factory(sc, store)
        event = ledger.append(
            event_type="rt.v2",
            payload={"d": 4},
            actor="tester",
            principal_identity="urn:oidc:sub:alice",
            principal_claims={"iss": "https://idp.example", "aud": "aevum", "sub": "alice"},
            commitment_key_id=key_id,
        )
        assert event.sig_format_version == 2
        assert event.principal_commitment_key_id == key_id
        assert event.principal_commitment is not None
        assert event.principal_binding is not None
        fetched = ledger.get(event.audit_id())
        _assert_lossless(event, fetched)
        assert sc.verify_chain([fetched]) is True


class TestRoundTripHasTeeth:
    """Proves _assert_lossless actually detects a dropped field -- the exact
    failure mode HO-G-PG2 exists to close. Re-running this file against a
    deliberately reverted ledger.py (one field removed from _row_to_event)
    turns test_round_trip_every_field / test_hybrid_append_get_round_trip_and_verifies
    above RED; these two tests prove the detector itself has teeth without
    requiring a source revert."""

    def test_detects_dropped_key_scheme(self) -> None:
        sc = Sigchain()
        event = sc.new_event(event_type="rt.teeth", payload={}, actor="tester")
        # Simulate the pre-fix bug: any drift in a restored key_scheme (the
        # actual bug silently defaulted a hybrid "ed25519+ml-dsa-65" back to
        # "ed25519" on restore) must be caught.
        broken_reconstruction = dataclasses.replace(event, key_scheme="ed25519+ml-dsa-65")
        with pytest.raises(AssertionError, match="key_scheme"):
            _assert_lossless(event, broken_reconstruction)

    @pytest.mark.skipif(not _DUAL_SIGNER_AVAILABLE, reason="requires liboqs-python ([pqc] extra)")
    def test_detects_dropped_mldsa65_sig(self) -> None:
        sc = Sigchain(dual_signer=DualSigner.generate())
        event = sc.new_event(event_type="rt.teeth", payload={}, actor="tester")
        assert event.mldsa65_sig is not None
        broken_reconstruction = dataclasses.replace(event, mldsa65_sig=None)
        with pytest.raises(AssertionError, match="mldsa65_sig"):
            _assert_lossless(event, broken_reconstruction)

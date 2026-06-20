# SPDX-License-Identifier: Apache-2.0
"""P2-IDENTITY-V2 adversary tests for the INDEPENDENT verifier (aevum-verify side).

Mirrors packages/aevum-core/tests/test_identity_binding_v2.py but exercises
aevum.verify._core.verify_chain / verify_entry directly against PINNED keys —
the same code path a third party with no access to the producer's runtime
would use (spec aevum-signing-v2.md). Fixture chains are built with
aevum.core.audit.sigchain.Sigchain, which is the established pattern for
aevum-verify's *tests* (not src/) — see test_classical.py's _classical_chain().
Independence of src/ is enforced separately by test_merkle_sth.py's AST guard.
"""
from __future__ import annotations

import dataclasses
import subprocess
import sys
from pathlib import Path

from aevum.core.audit.commitment_key_store import CommitmentKeyStore
from aevum.core.audit.sigchain import Sigchain

from aevum.verify._core import dump_chain, verify_chain


def _v2_chain() -> tuple[Sigchain, CommitmentKeyStore, str, bytes]:
    chain = Sigchain()
    store = CommitmentKeyStore()
    key_id = store.create_key(scope="verify-test-deployment")
    key = store.get_key(key_id)
    assert key is not None
    return chain, store, key_id, key


class TestV2ChainVerifiesAgainstPinnedKey:
    def test_full_principal_binding_chain_verifies(self) -> None:
        chain, _store, key_id, key = _v2_chain()
        events = [
            chain.new_event(
                event_type=f"t.{i}",
                payload={"i": i},
                actor="test-suite",
                principal_identity=f"urn:test:oidc:sub:user-{i}",
                principal_claims={"iss": "https://idp.test", "aud": "svc", "jti": f"j{i}"},
                commitment_key_id=key_id,
                commitment_key=key,
            )
            for i in range(3)
        ]
        result = verify_chain(events, ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is True

    def test_v2_entry_with_null_principal_fields_verifies(self) -> None:
        """DD2: commitment_key_id alone (no external credential) is still a valid v2 entry."""
        chain, _store, key_id, _key = _v2_chain()
        event = chain.new_event(event_type="t", payload={}, actor="a", commitment_key_id=key_id)
        result = verify_chain([event], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is True

    def test_v1_then_v2_mixed_chain_verifies(self) -> None:
        """DD4: per-entry dispatch — a chain may legitimately span v1 then v2."""
        chain, _store, key_id, key = _v2_chain()
        e1 = chain.new_event(event_type="t.1", payload={}, actor="a")
        e2 = chain.new_event(
            event_type="t.2",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            commitment_key_id=key_id,
            commitment_key=key,
        )
        result = verify_chain([e1, e2], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is True


class TestDowngradeAndSpliceRejectedByVerifier:
    """DD4 hardening, checked from the independent-verifier side: sig_format_version
    must never decrease across a chain, and tampering a v2 entry's principal fields
    must break the Ed25519 signature (DD3)."""

    def test_v2_then_v1_is_rejected_as_downgrade(self) -> None:
        chain, _store, key_id, key = _v2_chain()
        e1 = chain.new_event(
            event_type="t.1",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            commitment_key_id=key_id,
            commitment_key=key,
        )
        e2 = chain.new_event(event_type="t.2", payload={}, actor="a")
        result = verify_chain([e1, e2], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False
        assert result.failing_index == 1

    def test_reversed_chain_order_is_rejected_as_downgrade(self) -> None:
        chain, _store, key_id, key = _v2_chain()
        e1 = chain.new_event(event_type="t.1", payload={}, actor="a")
        e2 = chain.new_event(
            event_type="t.2",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            commitment_key_id=key_id,
            commitment_key=key,
        )
        result = verify_chain([e2, e1], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False

    def test_relabeling_v1_entry_as_v2_fails_signature(self) -> None:
        """DD3: a v1 entry's signature was computed over the 19-field signing set.
        Relabeling sig_format_version to 2 makes the verifier sign-check it against
        the 22-field v2 set instead — the digest mismatches."""
        chain, _store, _key_id, _key = _v2_chain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        forged = dataclasses.replace(event, sig_format_version=2)
        result = verify_chain([forged], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False

    def test_forging_v2_entry_back_to_v1_fails_signature(self) -> None:
        """DD3: the inverse direction — a v2 entry's signature covers the 3 extra
        fields; relabeling it as v1 strips them from the signed set and breaks
        the Ed25519 signature."""
        chain, _store, key_id, key = _v2_chain()
        event = chain.new_event(
            event_type="t",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            principal_claims={"iss": "https://idp.test", "aud": "svc", "jti": "j1"},
            commitment_key_id=key_id,
            commitment_key=key,
        )
        forged_v1 = dataclasses.replace(event, sig_format_version=1)
        result = verify_chain([forged_v1], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False

    def test_unknown_sig_format_version_fails_closed(self) -> None:
        chain, _store, key_id, key = _v2_chain()
        event = chain.new_event(
            event_type="t",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            commitment_key_id=key_id,
            commitment_key=key,
        )
        future = dataclasses.replace(event, sig_format_version=99)
        result = verify_chain([future], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False

    def test_tamper_principal_commitment_fails(self) -> None:
        """principal_commitment is bound in the v2 signing set: mutating it must
        invalidate the Ed25519 signature."""
        chain, _store, key_id, key = _v2_chain()
        event = chain.new_event(
            event_type="t",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            commitment_key_id=key_id,
            commitment_key=key,
        )
        assert event.principal_commitment is not None
        tampered = dataclasses.replace(event, principal_commitment="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        result = verify_chain([tampered], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False

    def test_tamper_principal_binding_fails(self) -> None:
        chain, _store, key_id, key = _v2_chain()
        event = chain.new_event(
            event_type="t",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            principal_claims={"iss": "https://idp.test", "aud": "svc", "jti": "j1"},
            commitment_key_id=key_id,
            commitment_key=key,
        )
        assert event.principal_binding is not None
        tampered = dataclasses.replace(event, principal_binding="forged-blob")
        result = verify_chain([tampered], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False

    def test_tamper_principal_commitment_key_id_fails(self) -> None:
        chain, _store, key_id, key = _v2_chain()
        event = chain.new_event(
            event_type="t",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            commitment_key_id=key_id,
            commitment_key=key,
        )
        tampered = dataclasses.replace(event, principal_commitment_key_id="forged-key-id")
        result = verify_chain([tampered], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False

    def test_nulling_principal_fields_in_place_fails(self) -> None:
        """DD3: nulling the 3 principal fields while keeping sig_format_version=2
        still changes the signed byte representation."""
        chain, _store, key_id, key = _v2_chain()
        event = chain.new_event(
            event_type="t",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            principal_claims={"iss": "https://idp.test", "aud": "svc", "jti": "j1"},
            commitment_key_id=key_id,
            commitment_key=key,
        )
        nulled = dataclasses.replace(
            event,
            principal_binding=None,
            principal_commitment=None,
            principal_commitment_key_id=None,
        )
        result = verify_chain([nulled], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False


class TestCommitmentNeverRequiredByVerifier:
    """DD6: verify_chain's signature takes no commitment-key argument at all —
    the independent verifier cannot consult the CommitmentKeyStore even if it
    wanted to. principal_commitment is opaque signed bytes to it."""

    def test_verify_chain_has_no_commitment_key_parameter(self) -> None:
        import inspect

        params = inspect.signature(verify_chain).parameters
        assert "commitment_key" not in params
        assert "commitment_key_store" not in params

    def test_verify_chain_succeeds_after_commitment_key_destroyed(self) -> None:
        from aevum.core.audit.ledger import InMemoryLedger

        chain, store, key_id, key = _v2_chain()
        event = chain.new_event(
            event_type="t",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            commitment_key_id=key_id,
            commitment_key=key,
        )
        ledger = InMemoryLedger(Sigchain())
        store.destroy(key_id, ledger=ledger, actor="test-admin")
        assert store.get_key(key_id) is None
        result = verify_chain([event], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is True


class TestV2FileRoundTripAndCli:
    """Full file round trip (event_to_dict/event_from_dict) and CLI exit codes
    for a v2 chain — exercises the JSON wire format, not just in-memory objects."""

    def test_dump_and_load_round_trip_verifies(self, tmp_path: Path) -> None:
        from aevum.verify._core import load_chain

        chain, _store, key_id, key = _v2_chain()
        events = [
            chain.new_event(
                event_type=f"t.{i}",
                payload={"i": i},
                actor="test-suite",
                principal_identity=f"urn:test:oidc:sub:user-{i}",
                commitment_key_id=key_id,
                commitment_key=key,
            )
            for i in range(2)
        ]
        path = tmp_path / "v2_chain.json"
        dump_chain(events, path)
        loaded = load_chain(path)
        result = verify_chain(loaded, ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is True

    def test_cli_exits_0_for_valid_v2_chain(self, tmp_path: Path) -> None:
        chain, _store, key_id, key = _v2_chain()
        events = [
            chain.new_event(
                event_type="t",
                payload={},
                actor="test-suite",
                principal_identity="urn:test:oidc:sub:alice",
                commitment_key_id=key_id,
                commitment_key=key,
            )
        ]
        path = tmp_path / "v2_chain.json"
        dump_chain(events, path)
        proc = subprocess.run(
            [
                sys.executable, "-m", "aevum.verify",
                str(path),
                "--ed25519-pub", chain._signer.public_key_bytes().hex(),
            ],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"expected exit 0; stderr: {proc.stderr}"

    def test_cli_exits_1_for_tampered_v2_chain(self, tmp_path: Path) -> None:
        chain, _store, key_id, key = _v2_chain()
        event = chain.new_event(
            event_type="t",
            payload={},
            actor="test-suite",
            principal_identity="urn:test:oidc:sub:alice",
            commitment_key_id=key_id,
            commitment_key=key,
        )
        tampered = dataclasses.replace(event, principal_commitment="forged")
        path = tmp_path / "v2_chain.json"
        dump_chain([tampered], path)
        proc = subprocess.run(
            [
                sys.executable, "-m", "aevum.verify",
                str(path),
                "--ed25519-pub", chain._signer.public_key_bytes().hex(),
            ],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 1, f"expected exit 1; got {proc.returncode}"

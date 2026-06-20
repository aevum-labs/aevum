# SPDX-License-Identifier: Apache-2.0
"""P2-IDENTITY-V2 tests (spec aevum-signing-v2.md): principal-binding signed fields.

Covers the design decisions (DD1-DD8) for the v2 sig_format_version evolution:
  DD1 — principal_commitment is over the bound CREDENTIAL identity, never actor.
  DD2 — the three new fields are nullable even within a v2 entry.
  DD3 — DOMAIN_PREFIX is unchanged; stripping v2 fields to forge v1 breaks the
        signature (no downgrade attack possible without the private key).
  DD4 — per-entry version dispatch; sig_format_version must never DECREASE
        across a chain (downgrade/splice fingerprint).
  DD6 — chain verification needs no commitment key.
  DD7 — principal_binding is an allow-list extraction; "sub" and bearer tokens
        never appear in the signed blob, regardless of what the caller passes.
"""
from __future__ import annotations

import base64
import dataclasses
import json

import pytest

from aevum.core.audit.commitment_key_store import CommitmentKeyStore
from aevum.core.audit.event import build_principal_binding_blob, compute_principal_commitment
from aevum.core.audit.sigchain import Sigchain


def _v2_chain() -> tuple[Sigchain, CommitmentKeyStore, str, bytes]:
    chain = Sigchain()
    store = CommitmentKeyStore()
    key_id = store.create_key(scope="test-deployment")
    key = store.get_key(key_id)
    assert key is not None
    return chain, store, key_id, key


class TestPrincipalBindingBasics:
    def test_default_new_event_is_v1_with_null_principal_fields(self) -> None:
        chain = Sigchain()
        e = chain.new_event(event_type="t", payload={}, actor="a")
        assert e.sig_format_version == 1
        assert e.principal_binding is None
        assert e.principal_commitment is None
        assert e.principal_commitment_key_id is None

    def test_commitment_key_id_alone_opts_into_v2_with_null_principal(self) -> None:
        """DD2: a v2 entry may have no external credential to bind at all."""
        chain, _store, key_id, _key = _v2_chain()
        e = chain.new_event(
            event_type="t", payload={}, actor="a", commitment_key_id=key_id
        )
        assert e.sig_format_version == 2
        assert e.principal_commitment_key_id == key_id
        assert e.principal_binding is None
        assert e.principal_commitment is None

    def test_full_principal_binding_sets_all_three_fields(self) -> None:
        chain, _store, key_id, key = _v2_chain()
        e = chain.new_event(
            event_type="t",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            principal_claims={"iss": "https://idp.test", "aud": "svc", "jti": "j1"},
            commitment_key_id=key_id,
            commitment_key=key,
        )
        assert e.sig_format_version == 2
        assert e.principal_binding is not None
        assert e.principal_commitment is not None
        assert e.principal_commitment_key_id == key_id

    def test_principal_commitment_matches_compute_principal_commitment(self) -> None:
        """DD1: principal_commitment is HMAC over the CREDENTIAL identity, not actor."""
        chain, _store, key_id, key = _v2_chain()
        e = chain.new_event(
            event_type="t",
            payload={},
            actor="completely-different-actor-name",
            principal_identity="urn:test:oidc:sub:alice",
            commitment_key_id=key_id,
            commitment_key=key,
        )
        expected = compute_principal_commitment(key, "urn:test:oidc:sub:alice")
        assert e.principal_commitment == expected
        # And it must NOT equal a commitment computed over actor instead.
        wrong = compute_principal_commitment(key, "completely-different-actor-name")
        assert e.principal_commitment != wrong

    def test_principal_identity_requires_commitment_key(self) -> None:
        chain, _store, key_id, _key = _v2_chain()
        with pytest.raises(ValueError):
            chain.new_event(
                event_type="t",
                payload={},
                actor="a",
                principal_identity="urn:test:oidc:sub:alice",
                commitment_key_id=key_id,
                commitment_key=None,
            )

    def test_principal_fields_require_commitment_key_id(self) -> None:
        """commitment_key_id is the v2 opt-in switch; principal_* alone is not enough."""
        chain = Sigchain()
        with pytest.raises(ValueError):
            chain.new_event(
                event_type="t",
                payload={},
                actor="a",
                principal_identity="urn:test:oidc:sub:alice",
            )

    def test_round_trip_v2_chain_verifies(self) -> None:
        chain, _store, key_id, key = _v2_chain()
        events = [
            chain.new_event(
                event_type=f"t.{i}",
                payload={"i": i},
                actor="a",
                principal_identity=f"urn:test:oidc:sub:user-{i}",
                principal_claims={"iss": "https://idp.test", "aud": "svc", "jti": f"j{i}"},
                commitment_key_id=key_id,
                commitment_key=key,
            )
            for i in range(3)
        ]
        assert chain.verify_chain(events) is True


class TestMixedVersionChain:
    """DD4: a single chain may span v1 then v2; per-entry dispatch governs verification."""

    def test_v1_then_v2_verifies(self) -> None:
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
        assert e1.sig_format_version == 1
        assert e2.sig_format_version == 2
        assert chain.verify_chain([e1, e2]) is True

    def test_v2_then_v1_within_same_sigchain_object_is_impossible_by_construction(self) -> None:
        """new_event always assigns the version per-call; nothing stops calling it with
        commitment_key_id on entry 1 and without it on entry 2 — but verify_chain must
        catch this as a downgrade, since DD4 forbids the version from ever decreasing."""
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
        assert e1.sig_format_version == 2
        assert e2.sig_format_version == 1
        assert chain.verify_chain([e1, e2]) is False


class TestDowngradeAndSpliceRejection:
    """DD4 hardening: sig_format_version must never decrease across a chain."""

    def test_reversed_chain_order_is_a_downgrade_fingerprint(self) -> None:
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
        assert chain.verify_chain([e2, e1]) is False

    def test_stripping_principal_fields_to_forge_v1_breaks_signature(self) -> None:
        """DD3: a v2 entry's signature covers the 3 extra fields. Setting
        sig_format_version back to 1 (or nulling principal_* while keeping it at 2)
        changes the signed byte representation and breaks the Ed25519 signature —
        no downgrade attack is possible without the private key."""
        chain, _store, key_id, key = _v2_chain()
        e = chain.new_event(
            event_type="t",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            principal_claims={"iss": "https://idp.test", "aud": "svc", "jti": "j1"},
            commitment_key_id=key_id,
            commitment_key=key,
        )
        forged_v1 = dataclasses.replace(e, sig_format_version=1)
        assert chain.verify_chain([forged_v1]) is False

        nulled_in_place = dataclasses.replace(
            e, principal_binding=None, principal_commitment=None, principal_commitment_key_id=None
        )
        assert chain.verify_chain([nulled_in_place]) is False

    def test_unknown_sig_format_version_still_fails_closed(self) -> None:
        chain, _store, key_id, key = _v2_chain()
        e = chain.new_event(
            event_type="t",
            payload={},
            actor="a",
            principal_identity="urn:test:oidc:sub:alice",
            commitment_key_id=key_id,
            commitment_key=key,
        )
        future = dataclasses.replace(e, sig_format_version=99)
        assert chain.verify_chain([future]) is False


class TestAllowListNeverLeaksRawSubjectOrBearerTokens:
    """DD7: principal_binding is built by ALLOW-LIST extraction. Whatever the caller
    passes in principal_claims, only iss/aud/jti/iat/exp/cnf.jkt may survive."""

    def _decode(self, blob: str) -> dict:
        pad = blob + "=" * (-len(blob) % 4)
        return json.loads(base64.urlsafe_b64decode(pad))

    def test_sub_never_appears_in_blob(self) -> None:
        blob = build_principal_binding_blob(
            {
                "iss": "https://idp.test",
                "aud": "svc",
                "jti": "j1",
                "sub": "urn:test:oidc:sub:alice",
            }
        )
        decoded = self._decode(blob)
        assert "sub" not in decoded
        assert decoded == {"iss": "https://idp.test", "aud": "svc", "jti": "j1"}

    def test_bearer_token_shaped_claim_never_appears_in_blob(self) -> None:
        """A caller mistakenly passing a bearer token under a non-allow-listed key
        must never survive the allow-list extraction."""
        blob = build_principal_binding_blob(
            {
                "iss": "https://idp.test",
                "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.bearer-token-here",
                "authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.also-a-token",
                "refresh_token": "rt-should-never-be-signed",
            }
        )
        decoded = self._decode(blob)
        assert decoded == {"iss": "https://idp.test"}
        assert "access_token" not in decoded
        assert "authorization" not in decoded
        assert "refresh_token" not in decoded

    def test_cnf_restricted_to_jkt_only(self) -> None:
        """RFC 7800 cnf must never carry raw proof-of-possession key material —
        only the RFC 7638 JWK thumbprint (jkt) survives."""
        blob = build_principal_binding_blob(
            {
                "iss": "https://idp.test",
                "cnf": {"jkt": "thumbprint-value", "jwk": {"kty": "RSA", "n": "...", "e": "AQAB"}},
            }
        )
        decoded = self._decode(blob)
        assert decoded["cnf"] == {"jkt": "thumbprint-value"}
        assert "jwk" not in decoded["cnf"]

    def test_raw_principal_identity_never_appears_in_event_fields(self) -> None:
        """DD1/DD7: the raw bound credential identity must never appear anywhere
        in the constructed AuditEvent — only its HMAC commitment does."""
        chain, _store, key_id, key = _v2_chain()
        raw_identity = "urn:test:oidc:sub:super-secret-alice"
        e = chain.new_event(
            event_type="t",
            payload={},
            actor="a",
            principal_identity=raw_identity,
            principal_claims={"iss": "https://idp.test", "aud": "svc", "jti": "j1", "sub": raw_identity},
            commitment_key_id=key_id,
            commitment_key=key,
        )
        serialized = json.dumps(dataclasses.asdict(e))
        assert raw_identity not in serialized
        assert '"sub"' not in serialized


class TestCommitmentNeverRequiredForChainVerification:
    """DD6: chain verification never calls into the CommitmentKeyStore."""

    def test_verify_chain_succeeds_after_commitment_key_destroyed(self) -> None:
        from aevum.core.audit.ledger import InMemoryLedger

        chain, store, key_id, key = _v2_chain()
        e = chain.new_event(
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
        # The entry it produced still verifies — the key was never needed for this.
        assert chain.verify_chain([e]) is True

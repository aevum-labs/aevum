# SPDX-License-Identifier: Apache-2.0
"""HO-G-OIDC Step 5 -- un-fakeable GREEN for OidcJwtBindingVerifier.

A real v2 principal_binding is committed through engine.commit() (the public
path, not a unit constructor), then re-verified through OidcJwtBindingVerifier
exactly as a deployment would. Negatives prove every malformed/hostile input
fails closed without raising. The honesty test proves checks_not_performed
always names issuer-signature and token-replay regardless of outcome. The
neutrality test proves handles() declines a SPIFFE-shaped blob.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

from aevum.core.audit.commitment_key_store import CommitmentKeyStore, verify_commitment
from aevum.core.audit.ledger import InMemoryLedger
from aevum.core.audit.sigchain import Sigchain
from aevum.core.engine import Engine

from aevum.oidc import OidcJwtBindingVerifier

_ISSUER = "https://idp.example"
_AUDIENCE = "aevum"


def _v2_engine() -> tuple[Engine, InMemoryLedger, CommitmentKeyStore, str]:
    sc = Sigchain()
    store = CommitmentKeyStore()
    key_id = store.create_key(scope="test-deployment")
    ledger = InMemoryLedger(sc, commitment_key_store=store)
    engine = Engine(sigchain=sc, ledger=ledger)
    return engine, ledger, store, key_id


def _commit_binding(
    engine: Engine,
    ledger: InMemoryLedger,
    key_id: str,
    *,
    principal_identity: str = "urn:oidc:sub:alice",
    iss: str = _ISSUER,
    aud: str = _AUDIENCE,
    iat_offset: timedelta = timedelta(seconds=-60),
    exp_offset: timedelta = timedelta(hours=1),
) -> dict[str, str]:
    now = datetime.now(UTC)
    result = engine.commit(
        event_type="app.principal_bound",
        payload={"k": "v"},
        actor="tester",
        principal_identity=principal_identity,
        principal_claims={
            "iss": iss,
            "aud": aud,
            "sub": principal_identity,
            "jti": "jti-001",
            "iat": int((now + iat_offset).timestamp()),
            "exp": int((now + exp_offset).timestamp()),
        },
        commitment_key_id=key_id,
    )
    event = ledger.get(result.audit_id)
    assert event.principal_binding is not None
    return {"principal_binding": event.principal_binding}


def _encode_blob(claims: dict) -> str:
    raw = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class TestEndToEndRealBinding:
    """Un-fakeable GREEN: a real v2 binding committed via engine.commit() is
    re-verified by the OIDC adapter -- valid claims, expected issuer, expected
    audience all match, so verified must be True."""

    def test_real_committed_binding_verifies(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(engine, ledger, key_id)

        verifier = OidcJwtBindingVerifier()
        result = verifier.verify(
            binding,
            at_time=datetime.now(UTC),
            expected_issuers=[_ISSUER],
            expected_audience=_AUDIENCE,
        )

        assert result.verified is True
        assert result.failure_reasons == []
        assert "structure" in result.checks_performed
        assert "validity_window" in result.checks_performed
        assert "issuer_match" in result.checks_performed
        assert "audience_match" in result.checks_performed


class TestNegativesFailClosed:
    """Every malformed/hostile/policy-mismatched input must return
    verified=False with reasons -- never raise."""

    def test_expired_binding_fails_closed(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(
            engine,
            ledger,
            key_id,
            iat_offset=timedelta(hours=-2),
            exp_offset=timedelta(hours=-1),
        )

        verifier = OidcJwtBindingVerifier()
        result = verifier.verify(binding, at_time=datetime.now(UTC))

        assert result.verified is False
        assert any("validity" in r.lower() or "window" in r.lower() for r in result.failure_reasons)

    def test_wrong_issuer_fails_closed(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(engine, ledger, key_id, iss="https://attacker.example")

        verifier = OidcJwtBindingVerifier()
        result = verifier.verify(
            binding,
            at_time=datetime.now(UTC),
            expected_issuers=[_ISSUER],
        )

        assert result.verified is False
        assert any("issuer" in r.lower() for r in result.failure_reasons)

    def test_wrong_audience_fails_closed(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(engine, ledger, key_id, aud="some-other-service")

        verifier = OidcJwtBindingVerifier()
        result = verifier.verify(
            binding,
            at_time=datetime.now(UTC),
            expected_audience=_AUDIENCE,
        )

        assert result.verified is False
        assert any("audience" in r.lower() for r in result.failure_reasons)

    def test_malformed_base64_fails_closed_no_raise(self) -> None:
        verifier = OidcJwtBindingVerifier()
        result = verifier.verify(
            {"principal_binding": "not-valid-base64url!!!"},
            at_time=datetime.now(UTC),
        )
        assert result.verified is False
        assert result.failure_reasons

    def test_malformed_json_fails_closed_no_raise(self) -> None:
        garbage = base64.urlsafe_b64encode(b"not json at all {{{").rstrip(b"=").decode()
        verifier = OidcJwtBindingVerifier()
        result = verifier.verify({"principal_binding": garbage}, at_time=datetime.now(UTC))
        assert result.verified is False
        assert result.failure_reasons

    def test_missing_claim_fails_closed(self) -> None:
        blob = _encode_blob({"iss": _ISSUER, "aud": _AUDIENCE})  # no iat/exp
        verifier = OidcJwtBindingVerifier()
        result = verifier.verify({"principal_binding": blob}, at_time=datetime.now(UTC))
        assert result.verified is False
        assert any("missing required claim" in r for r in result.failure_reasons)

    def test_garbage_cnf_jkt_fails_closed(self) -> None:
        now = int(datetime.now(UTC).timestamp())
        blob = _encode_blob(
            {
                "iss": _ISSUER,
                "aud": _AUDIENCE,
                "iat": now - 60,
                "exp": now + 3600,
                "cnf": {"jkt": "not-a-real-thumbprint"},
            }
        )
        verifier = OidcJwtBindingVerifier()
        result = verifier.verify({"principal_binding": blob}, at_time=datetime.now(UTC))
        assert result.verified is False
        assert any("jkt" in r for r in result.failure_reasons)

    def test_missing_principal_binding_key_fails_closed(self) -> None:
        verifier = OidcJwtBindingVerifier()
        result = verifier.verify({}, at_time=datetime.now(UTC))
        assert result.verified is False

    def test_non_dict_binding_fails_closed_no_raise(self) -> None:
        verifier = OidcJwtBindingVerifier()
        result = verifier.verify(None, at_time=datetime.now(UTC))  # type: ignore[arg-type]
        assert result.verified is False


class TestHonestyScope:
    """checks_not_performed must always name issuer-signature re-verification
    and token replay, regardless of how the other checks come out."""

    def test_checks_not_performed_always_present_on_success(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(engine, ledger, key_id)

        verifier = OidcJwtBindingVerifier()
        result = verifier.verify(binding, at_time=datetime.now(UTC))

        assert any("signature" in c.lower() for c in result.checks_not_performed)
        assert any("replay" in c.lower() for c in result.checks_not_performed)

    def test_checks_not_performed_always_present_on_failure(self) -> None:
        verifier = OidcJwtBindingVerifier()
        result = verifier.verify({"principal_binding": "garbage"}, at_time=datetime.now(UTC))

        assert any("signature" in c.lower() for c in result.checks_not_performed)
        assert any("replay" in c.lower() for c in result.checks_not_performed)


class TestCommitmentMatch:
    """The issuer-neutral commitment-match check (DD-I5) lives in core, not in
    this adapter -- confirms a claimed identity against the recorded
    principal_commitment using the deployment's commitment key."""

    def test_verify_commitment_confirms_bound_identity(self) -> None:
        engine, ledger, store, key_id = _v2_engine()
        identity = "urn:oidc:sub:alice"
        result = engine.commit(
            event_type="app.principal_bound",
            payload={},
            actor="tester",
            principal_identity=identity,
            principal_claims={"iss": _ISSUER, "aud": _AUDIENCE, "sub": identity},
            commitment_key_id=key_id,
        )
        event = ledger.get(result.audit_id)
        key = store.get_key(key_id)
        assert key is not None
        assert event.principal_commitment is not None

        assert verify_commitment(event.principal_commitment, key, identity) is True
        assert verify_commitment(event.principal_commitment, key, "urn:oidc:sub:bob") is False


class TestNeutrality:
    """handles() must decline a SPIFFE-shaped blob cleanly -- the neutral
    Protocol must not silently assume OIDC."""

    def test_spiffe_shaped_blob_not_handled(self) -> None:
        blob = _encode_blob(
            {
                "trust_domain": "example.org",
                "spiffe_id": "spiffe://example.org/billing",
            }
        )
        verifier = OidcJwtBindingVerifier()
        assert verifier.handles({"principal_binding": blob}) is False

    def test_oidc_shaped_blob_is_handled(self) -> None:
        blob = _encode_blob({"iss": _ISSUER, "aud": _AUDIENCE})
        verifier = OidcJwtBindingVerifier()
        assert verifier.handles({"principal_binding": blob}) is True

    def test_malformed_blob_not_handled(self) -> None:
        verifier = OidcJwtBindingVerifier()
        assert verifier.handles({"principal_binding": "!!!not-base64"}) is False

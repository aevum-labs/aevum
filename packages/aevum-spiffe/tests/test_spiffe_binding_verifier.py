# SPDX-License-Identifier: Apache-2.0
"""HO-G2-SPIFFE Part 3 -- un-fakeable GREEN for SpiffeBindingVerifier.

A real v2 principal_binding is committed through engine.commit() (the public
path, not a unit constructor), then re-verified through SpiffeBindingVerifier
exactly as a deployment would. Negatives prove every malformed/hostile input
fails closed without raising. The honesty test proves checks_not_performed
always names cnf_jkt_holder_match, issuer-signature, and token-replay
regardless of outcome. The neutrality test proves SpiffeBindingVerifier and
OidcJwtBindingVerifier each decline the other's claim shape -- mutual proof
that the PrincipalBindingVerifier Protocol is genuinely neutral.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

from aevum.core.audit.commitment_key_store import CommitmentKeyStore
from aevum.core.audit.ledger import InMemoryLedger
from aevum.core.audit.sigchain import Sigchain
from aevum.core.engine import Engine

from aevum.spiffe import SpiffeBindingVerifier

_ISSUER = "spiffe://example.org"
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
    principal_identity: str = "spiffe://example.org/billing",
    iss: str = _ISSUER,
    aud: list[str] | None = None,
    exp_offset: timedelta = timedelta(hours=1),
    include_iat: bool = False,
) -> dict[str, str]:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": iss,
        "aud": list(aud) if aud is not None else [_AUDIENCE],
        "exp": int((now + exp_offset).timestamp()),
    }
    if include_iat:
        claims["iat"] = int((now - timedelta(seconds=60)).timestamp())

    result = engine.commit(
        event_type="spiffe.attested",
        payload={"trust_domain": "example.org"},
        actor="tester",
        principal_identity=principal_identity,
        principal_claims=claims,
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
    re-verified by the SPIFFE adapter -- valid claims, expected issuer,
    expected audience all match, so verified must be True."""

    def test_real_committed_binding_verifies(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(engine, ledger, key_id)

        verifier = SpiffeBindingVerifier()
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
        binding = _commit_binding(engine, ledger, key_id, exp_offset=timedelta(hours=-1))

        verifier = SpiffeBindingVerifier()
        result = verifier.verify(binding, at_time=datetime.now(UTC))

        assert result.verified is False
        assert any(
            "validity" in r.lower() or "exp" in r.lower() for r in result.failure_reasons
        )

    def test_wrong_trust_domain_fails_closed(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(engine, ledger, key_id, iss="spiffe://attacker.example")

        verifier = SpiffeBindingVerifier()
        result = verifier.verify(
            binding,
            at_time=datetime.now(UTC),
            expected_issuers=[_ISSUER],
        )

        assert result.verified is False
        assert any("issuer" in r.lower() for r in result.failure_reasons)

    def test_wrong_audience_fails_closed(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(engine, ledger, key_id, aud=["some-other-service"])

        verifier = SpiffeBindingVerifier()
        result = verifier.verify(
            binding,
            at_time=datetime.now(UTC),
            expected_audience=_AUDIENCE,
        )

        assert result.verified is False
        assert any("audience" in r.lower() for r in result.failure_reasons)

    def test_malformed_base64_fails_closed_no_raise(self) -> None:
        verifier = SpiffeBindingVerifier()
        result = verifier.verify(
            {"principal_binding": "not-valid-base64url!!!"},
            at_time=datetime.now(UTC),
        )
        assert result.verified is False
        assert result.failure_reasons

    def test_malformed_json_fails_closed_no_raise(self) -> None:
        garbage = base64.urlsafe_b64encode(b"not json at all {{{").rstrip(b"=").decode()
        verifier = SpiffeBindingVerifier()
        result = verifier.verify({"principal_binding": garbage}, at_time=datetime.now(UTC))
        assert result.verified is False
        assert result.failure_reasons

    def test_missing_exp_fails_closed(self) -> None:
        blob = _encode_blob({"iss": _ISSUER, "aud": [_AUDIENCE]})  # no exp
        verifier = SpiffeBindingVerifier()
        result = verifier.verify({"principal_binding": blob}, at_time=datetime.now(UTC))
        assert result.verified is False
        assert any("missing required claim" in r for r in result.failure_reasons)

    def test_missing_principal_binding_key_fails_closed(self) -> None:
        verifier = SpiffeBindingVerifier()
        result = verifier.verify({}, at_time=datetime.now(UTC))
        assert result.verified is False

    def test_non_dict_binding_fails_closed_no_raise(self) -> None:
        verifier = SpiffeBindingVerifier()
        result = verifier.verify(None, at_time=datetime.now(UTC))  # type: ignore[arg-type]
        assert result.verified is False


class TestArrayAudience:
    """JWT-SVID's aud claim is an array -- expected_audience must match via
    list-containment, not scalar equality (the OIDC adapter's aud is scalar)."""

    def test_expected_audience_among_several_verifies(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(
            engine, ledger, key_id, aud=["other-service", _AUDIENCE, "third-service"]
        )

        verifier = SpiffeBindingVerifier()
        result = verifier.verify(
            binding,
            at_time=datetime.now(UTC),
            expected_audience=_AUDIENCE,
        )

        assert result.verified is True
        assert result.failure_reasons == []

    def test_expected_audience_absent_from_array_fails_closed(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(engine, ledger, key_id, aud=["other-service", "third-service"])

        verifier = SpiffeBindingVerifier()
        result = verifier.verify(
            binding,
            at_time=datetime.now(UTC),
            expected_audience=_AUDIENCE,
        )

        assert result.verified is False
        assert any("audience" in r.lower() for r in result.failure_reasons)

    def test_scalar_aud_fails_closed(self) -> None:
        """A scalar aud (OIDC-shaped) is not a well-formed SPIFFE aud array."""
        blob = _encode_blob(
            {"iss": _ISSUER, "aud": _AUDIENCE, "exp": int(datetime.now(UTC).timestamp()) + 3600}
        )
        verifier = SpiffeBindingVerifier()
        result = verifier.verify(
            {"principal_binding": blob},
            at_time=datetime.now(UTC),
            expected_audience=_AUDIENCE,
        )
        assert result.verified is False
        assert any("audience" in r.lower() for r in result.failure_reasons)


class TestNoIat:
    """JWT-SVID does not mandate iat (unlike OIDC) -- a valid binding lacking
    iat entirely must still verify."""

    def test_binding_without_iat_verifies(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(engine, ledger, key_id, include_iat=False)

        verifier = SpiffeBindingVerifier()
        result = verifier.verify(
            binding,
            at_time=datetime.now(UTC),
            expected_issuers=[_ISSUER],
            expected_audience=_AUDIENCE,
        )

        assert result.verified is True
        assert result.failure_reasons == []

    def test_binding_with_iat_still_verifies(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(engine, ledger, key_id, include_iat=True)

        verifier = SpiffeBindingVerifier()
        result = verifier.verify(binding, at_time=datetime.now(UTC))

        assert result.verified is True


class TestHonestyScope:
    """checks_not_performed must always name cnf_jkt_holder_match (JWT-SVID
    has no PoP key, so this is unconditional unlike OIDC's conditional check),
    issuer-signature re-verification, and token replay -- regardless of how
    the other checks come out."""

    def test_checks_not_performed_always_present_on_success(self) -> None:
        engine, ledger, _store, key_id = _v2_engine()
        binding = _commit_binding(engine, ledger, key_id)

        verifier = SpiffeBindingVerifier()
        result = verifier.verify(binding, at_time=datetime.now(UTC))

        assert any("cnf" in c.lower() or "jkt" in c.lower() for c in result.checks_not_performed)
        assert any("signature" in c.lower() for c in result.checks_not_performed)
        assert any("replay" in c.lower() for c in result.checks_not_performed)

    def test_checks_not_performed_always_present_on_failure(self) -> None:
        verifier = SpiffeBindingVerifier()
        result = verifier.verify({"principal_binding": "garbage"}, at_time=datetime.now(UTC))

        assert any("cnf" in c.lower() or "jkt" in c.lower() for c in result.checks_not_performed)
        assert any("signature" in c.lower() for c in result.checks_not_performed)
        assert any("replay" in c.lower() for c in result.checks_not_performed)


class TestNeutrality:
    """Mutual proof that the PrincipalBindingVerifier Protocol is neutral:
    SpiffeBindingVerifier must decline an OIDC-shaped blob, and
    OidcJwtBindingVerifier must decline a SPIFFE-shaped blob. Neither adapter
    silently assumes the other's issuer shape."""

    def test_oidc_shaped_blob_not_handled(self) -> None:
        blob = _encode_blob({"iss": "https://idp.example", "aud": "aevum"})
        verifier = SpiffeBindingVerifier()
        assert verifier.handles({"principal_binding": blob}) is False

    def test_spiffe_shaped_blob_is_handled(self) -> None:
        blob = _encode_blob({"iss": _ISSUER, "aud": [_AUDIENCE]})
        verifier = SpiffeBindingVerifier()
        assert verifier.handles({"principal_binding": blob}) is True

    def test_malformed_blob_not_handled(self) -> None:
        verifier = SpiffeBindingVerifier()
        assert verifier.handles({"principal_binding": "!!!not-base64"}) is False

    def test_oidc_verifier_declines_spiffe_blob(self) -> None:
        """Cross-adapter proof: a real OIDC adapter, given a SPIFFE-shaped
        claim set, must decline via handles() -- the two adapters' gates are
        mutually exclusive on a real spiffe:// issuer."""
        from aevum.oidc import OidcJwtBindingVerifier

        blob = _encode_blob({"iss": _ISSUER, "aud": [_AUDIENCE], "exp": 9999999999})
        oidc_verifier = OidcJwtBindingVerifier()
        assert oidc_verifier.handles({"principal_binding": blob}) is False

    def test_spiffe_verifier_declines_oidc_blob(self) -> None:
        """Cross-adapter proof: SpiffeBindingVerifier, given an OIDC-shaped
        claim set (https:// issuer, scalar aud), must decline via handles()."""
        blob = _encode_blob(
            {"iss": "https://idp.example", "aud": "aevum", "iat": 1000, "exp": 9999999999}
        )
        spiffe_verifier = SpiffeBindingVerifier()
        assert spiffe_verifier.handles({"principal_binding": blob}) is False

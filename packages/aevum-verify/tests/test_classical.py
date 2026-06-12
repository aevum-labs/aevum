# SPDX-License-Identifier: Apache-2.0
"""Classical (Ed25519-only) chain verification tests — no liboqs required."""
from __future__ import annotations

import dataclasses

from aevum.core.audit.sigchain import Sigchain

from aevum.verify._core import verify_chain


def _classical_chain(n: int = 3) -> tuple[Sigchain, list]:
    chain = Sigchain()
    events = [
        chain.new_event(event_type=f"t.{i}", payload={"i": i}, actor="test-suite")
        for i in range(n)
    ]
    return chain, events


class TestClassicalChainVerified:
    def test_valid_classical_chain_verified(self) -> None:
        chain, events = _classical_chain(3)
        result = verify_chain(events, ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is True

    def test_empty_chain_verified(self) -> None:
        chain = Sigchain()
        result = verify_chain([], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is True

    def test_single_entry_verified(self) -> None:
        chain, events = _classical_chain(1)
        result = verify_chain(events, ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is True

    def test_wrong_ed25519_key_fails(self) -> None:
        """Verifying against a different pinned key → FAIL — this is the real trust-anchor check."""
        chain, events = _classical_chain(3)
        wrong_chain = Sigchain()  # independent key
        result = verify_chain(events, ed25519_pub=wrong_chain._signer.public_key_bytes())
        assert result.ok is False

    def test_tamper_prior_hash_fails(self) -> None:
        chain, events = _classical_chain(3)
        tampered = dataclasses.replace(events[1], prior_hash="aa" * 32)
        result = verify_chain(
            [events[0], tampered, events[2]],
            ed25519_pub=chain._signer.public_key_bytes(),
        )
        assert result.ok is False
        assert result.failing_index == 1

    def test_tamper_payload_fails(self) -> None:
        chain, events = _classical_chain(3)
        tampered = dataclasses.replace(events[1], payload={"tampered": True})
        result = verify_chain(
            [events[0], tampered, events[2]],
            ed25519_pub=chain._signer.public_key_bytes(),
        )
        assert result.ok is False
        assert result.failing_index == 1

    def test_tamper_signature_fails(self) -> None:
        chain, events = _classical_chain(1)
        tampered = dataclasses.replace(events[0], signature="AAAA" * 16)
        result = verify_chain([tampered], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False
        assert result.failing_index == 0

    def test_signer_key_id_tamper_fails_via_signature_breakage(self) -> None:
        """signer_key_id is a signed field: mutating it breaks the Ed25519 signature.

        The field's integrity is signature-protected, not identity-compared.
        There is NO check that signer_key_id equals ed25519_pub.hex() — that
        fabricated check (removed in P2j) caused CI failures for hybrid chains
        where InProcessSigner uses a UUID key_id, not the pubkey hex.
        """
        chain, events = _classical_chain(1)
        tampered = dataclasses.replace(events[0], signer_key_id="forged-key-id")
        result = verify_chain([tampered], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False
        assert result.failing_index == 0

    def test_sig_format_version_none_fails(self) -> None:
        chain, events = _classical_chain(1)
        tampered = dataclasses.replace(events[0], sig_format_version=None)
        result = verify_chain([tampered], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False

    def test_sig_format_version_wrong_value_fails(self) -> None:
        chain, events = _classical_chain(1)
        tampered = dataclasses.replace(events[0], sig_format_version=0)
        result = verify_chain([tampered], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False

    def test_tamper_actor_fails(self) -> None:
        """actor is a signed field — mutating it breaks the signature."""
        chain, events = _classical_chain(1)
        tampered = dataclasses.replace(events[0], actor="forged-actor")
        result = verify_chain([tampered], ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False
        assert result.failing_index == 0

    def test_failing_index_is_correct(self) -> None:
        chain, events = _classical_chain(5)
        tamper_idx = 3
        tampered = list(events)
        tampered[tamper_idx] = dataclasses.replace(events[tamper_idx], actor="forged")
        result = verify_chain(tampered, ed25519_pub=chain._signer.public_key_bytes())
        assert result.ok is False
        assert result.failing_index == tamper_idx

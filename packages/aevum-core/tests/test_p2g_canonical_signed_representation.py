# SPDX-License-Identifier: Apache-2.0
"""P2g gate tests: frozen canonical signed representation.

Validates that the per-entry signing bytes are correct, self-describing,
domain-separated, and truly independently verifiable. This is the atomic
freeze pass — the format tested here is the permanent frozen representation.

Test inventory:
  - RFC 8785 official vectors (linchpin guard)
  - Compute-once preserved: chain hash == Ed25519 signed digest
  - Both signatures verify (Ed25519 + ML-DSA-65) over the new representative
  - Domain separation is real: unprefixed bytes do not verify
  - hash_alg is bound: mutating it breaks verification
  - Non-ASCII actor canonicalizes correctly (independent-verify bug fixed)
  - ML-DSA scheme derived from signer (not literal "65")
  - Unknown ML-DSA level rejected
  - Classical chain still verifies
  - Hybrid chain verifies WITH liboqs (not skipped)
"""
from __future__ import annotations

import base64
import hashlib

import pytest
import rfc8785

from aevum.core.audit.event import (
    DOMAIN_PREFIX,
    AuditEvent,
    _canonicalize,
    _message_representative,
)
from aevum.core.audit.sigchain import Sigchain

try:
    import oqs as _oqs_check  # noqa: F401
    _HAS_LIBOQS = True
except (ImportError, OSError, SystemExit):
    _HAS_LIBOQS = False

needs_liboqs = pytest.mark.skipif(not _HAS_LIBOQS, reason="liboqs not available")


# ---------------------------------------------------------------------------
# RFC 8785 official test vectors (linchpin guard)
# These vectors pin the canonicalizer to the RFC — if this test breaks,
# the entire signing foundation is invalid.
# ---------------------------------------------------------------------------

class TestRFC8785OfficialVectors:
    """RFC 8785 §3 normative behavior: string encoding, number formatting, key ordering."""

    def test_nonascii_string_is_utf8_not_escaped(self) -> None:
        """Non-ASCII code points must appear as UTF-8 bytes, not \\uXXXX escapes."""
        result = rfc8785.dumps({"a": "€"})
        assert isinstance(result, bytes)
        assert b"\\u" not in result, "rfc8785 must NOT produce \\uXXXX for printable non-ASCII"
        # Euro sign U+20AC → UTF-8 bytes 0xE2 0x82 0xAC
        assert result == b'{"a":"\xe2\x82\xac"}'

    def test_cjk_chars_are_utf8(self) -> None:
        result = rfc8785.dumps({"a": "hello世界"})
        assert b"\\u" not in result
        assert result == b'{"a":"hello\xe4\xb8\x96\xe7\x95\x8c"}'

    def test_latin_extended_is_utf8(self) -> None:
        result = rfc8785.dumps({"a": "ä"})
        assert b"\\u" not in result
        assert result == b'{"a":"\xc3\xa4"}'

    def test_control_chars_are_escaped(self) -> None:
        assert rfc8785.dumps({"a": "\n"}) == b'{"a":"\\n"}'
        assert rfc8785.dumps({"a": "\t"}) == b'{"a":"\\t"}'
        assert rfc8785.dumps({"a": "\r"}) == b'{"a":"\\r"}'

    def test_quotes_and_backslash_escaped(self) -> None:
        assert rfc8785.dumps({"a": '"'}) == b'{"a":"\\""}'
        assert rfc8785.dumps({"a": "\\"}) == b'{"a":"\\\\"}'

    def test_key_ordering_lexicographic(self) -> None:
        result = rfc8785.dumps({"b": 1, "a": 2})
        assert result == b'{"a":2,"b":1}'

    def test_key_ordering_case_sensitive(self) -> None:
        result = rfc8785.dumps({"z": 1, "Z": 2, "A": 3})
        assert result == b'{"A":3,"Z":2,"z":1}'

    def test_null_literal(self) -> None:
        assert rfc8785.dumps({"k": None}) == b'{"k":null}'

    def test_bool_literals(self) -> None:
        assert rfc8785.dumps({"a": True}) == b'{"a":true}'
        assert rfc8785.dumps({"a": False}) == b'{"a":false}'

    def test_integer_values(self) -> None:
        assert rfc8785.dumps({"n": 42}) == b'{"n":42}'
        assert rfc8785.dumps({"n": 0}) == b'{"n":0}'
        assert rfc8785.dumps({"n": -1}) == b'{"n":-1}'

    def test_float_canonicalization(self) -> None:
        assert rfc8785.dumps({"a": 333333333.33333329}) == b'{"a":333333333.3333333}'
        assert rfc8785.dumps({"a": 1e30}) == b'{"a":1e+30}'
        assert rfc8785.dumps({"a": 4.50}) == b'{"a":4.5}'
        assert rfc8785.dumps({"a": 0.0}) == b'{"a":0}'

    def test_returns_bytes(self) -> None:
        assert isinstance(rfc8785.dumps({"k": "v"}), bytes)

    def test_diverges_from_json_dumps_for_nonascii(self) -> None:
        """Confirm rfc8785 and json.dumps differ for non-ASCII — the bug we're fixing."""
        import json
        sample = {"actor": "café"}
        rf = rfc8785.dumps(sample)
        jf = json.dumps(sample, sort_keys=True, separators=(",", ":")).encode()
        assert rf != jf, "rfc8785 and json.dumps must differ for non-ASCII input"
        assert b"\\u" not in rf
        assert b"\\u" in jf


# ---------------------------------------------------------------------------
# _canonicalize guards
# ---------------------------------------------------------------------------

class TestCanonicalizeGuards:
    def test_float_forbidden(self) -> None:
        with pytest.raises(ValueError, match="float"):
            _canonicalize({"x": 1.5})

    def test_large_int_forbidden(self) -> None:
        with pytest.raises(ValueError, match="exceeds RFC 8785 safe domain"):
            _canonicalize({"ts": 2**53})

    def test_safe_int_allowed(self) -> None:
        result = _canonicalize({"n": 42, "m": -(2**53 - 1)})
        assert isinstance(result, bytes)

    def test_bool_not_flagged_as_int(self) -> None:
        # bool is a subclass of int; must NOT be rejected
        result = _canonicalize({"ok": True})
        assert b"true" in result


# ---------------------------------------------------------------------------
# DOMAIN_PREFIX binding
# ---------------------------------------------------------------------------

class TestDomainPrefix:
    def test_prefix_constant(self) -> None:
        assert DOMAIN_PREFIX == b"aevum-sigchain-v1\x00"
        assert DOMAIN_PREFIX.endswith(b"\x00"), "null byte separates prefix from JSON body"

    def test_message_representative_starts_with_prefix(self) -> None:
        rep = _message_representative({"a": "b"})
        assert rep.startswith(DOMAIN_PREFIX)

    def test_message_representative_suffix_is_rfc8785(self) -> None:
        fields = {"a": "café", "n": 1, "z": None}
        rep = _message_representative(fields)
        assert rep == DOMAIN_PREFIX + rfc8785.dumps(fields)


# ---------------------------------------------------------------------------
# DualSigner.scheme_suffix and mldsa_alg (agility properties)
# ---------------------------------------------------------------------------

class TestDualSignerAgilityProperties:
    @needs_liboqs
    def test_scheme_suffix(self) -> None:
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        assert ds.scheme_suffix == "ml-dsa-65"

    @needs_liboqs
    def test_mldsa_alg(self) -> None:
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        assert ds.mldsa_alg == "ML-DSA-65"

    @needs_liboqs
    def test_scheme_derived_not_hardcoded(self) -> None:
        """scheme in new_event is derived from signer.scheme_suffix, not a literal."""
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        event = chain.new_event(event_type="t", payload={}, actor="a")
        expected_scheme = f"ed25519+{ds.scheme_suffix}"
        assert event.key_scheme == expected_scheme == "ed25519+ml-dsa-65"


# ---------------------------------------------------------------------------
# hash_alg field is in the signed set
# ---------------------------------------------------------------------------

class TestHashAlgBound:
    def test_hash_alg_present_in_event(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        assert event.hash_alg == "sha3-256"

    def test_hash_alg_tamper_breaks_verification(self) -> None:
        """Mutating hash_alg must invalidate chain verification."""
        import dataclasses
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        assert chain.verify_chain([event]) is True

        tampered = dataclasses.replace(event, hash_alg="sha2-256")
        assert chain.verify_chain([tampered]) is False


# ---------------------------------------------------------------------------
# Compute-once preserved
# ---------------------------------------------------------------------------

class TestComputeOncePreserved:
    """chain hash == Ed25519 signed digest — the P2e invariant, now with the new format."""

    def _independent_digest(self, event: AuditEvent) -> bytes:
        """Independently recompute sha3_256(DOMAIN_PREFIX + rfc8785.dumps(19 fields))."""
        fields = {
            "event_id": event.event_id,
            "episode_id": event.episode_id,
            "sequence": event.sequence,
            "event_type": event.event_type,
            "schema_version": event.schema_version,
            "valid_from": event.valid_from,
            "valid_to": event.valid_to,
            "system_time": str(event.system_time),
            "causation_id": event.causation_id,
            "correlation_id": event.correlation_id,
            "actor": event.actor,
            "trace_id": event.trace_id,
            "span_id": event.span_id,
            "payload_hash": event.payload_hash,
            "prior_hash": event.prior_hash,
            "signer_key_id": event.signer_key_id,
            "key_scheme": event.key_scheme,
            "sig_format_version": 1,
            "hash_alg": event.hash_alg,
        }
        representative = DOMAIN_PREFIX + rfc8785.dumps(fields)
        return hashlib.sha3_256(representative).digest()

    def test_chain_hash_equals_independent_digest(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="p2g.compute_once", payload={"x": 1}, actor="a")

        independent_digest = self._independent_digest(event)
        chain_hash_bytes = bytes.fromhex(AuditEvent.hash_event_for_chain(event))
        assert chain_hash_bytes == independent_digest

    def test_ed25519_signed_digest_equals_chain_hash(self) -> None:
        """The digest that Ed25519 signed must equal the chain hash (hex)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        chain = Sigchain()
        event = chain.new_event(event_type="p2g.digest_equals_hash", payload={}, actor="a")

        chain_hash = AuditEvent.hash_event_for_chain(event)
        expected_digest = bytes.fromhex(chain_hash)

        sig_bytes = base64.urlsafe_b64decode(event.signature + "==")
        pub = Ed25519PublicKey.from_public_bytes(chain._signer.public_key_bytes())
        # Raises if the digest doesn't match — verifies chain_hash == signed digest
        pub.verify(sig_bytes, expected_digest)

    @needs_liboqs
    def test_hybrid_compute_once_preserved(self) -> None:
        from aevum.core.signing import DualSigner
        chain = Sigchain(dual_signer=DualSigner.generate())
        event = chain.new_event(event_type="p2g.hybrid_compute_once", payload={}, actor="a")

        independent_digest = self._independent_digest(event)
        chain_hash_bytes = bytes.fromhex(AuditEvent.hash_event_for_chain(event))
        assert chain_hash_bytes == independent_digest


# ---------------------------------------------------------------------------
# Domain separation is real
# ---------------------------------------------------------------------------

class TestDomainSeparationReal:
    """Signing with prefix, attempting verify without prefix → reject."""

    def test_unprefixed_bytes_do_not_verify(self) -> None:
        """A representative without the domain prefix must not verify against the real signature."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        chain = Sigchain()
        event = chain.new_event(event_type="p2g.domain_sep", payload={}, actor="a")

        fields = {
            "event_id": event.event_id,
            "episode_id": event.episode_id,
            "sequence": event.sequence,
            "event_type": event.event_type,
            "schema_version": event.schema_version,
            "valid_from": event.valid_from,
            "valid_to": event.valid_to,
            "system_time": str(event.system_time),
            "causation_id": event.causation_id,
            "correlation_id": event.correlation_id,
            "actor": event.actor,
            "trace_id": event.trace_id,
            "span_id": event.span_id,
            "payload_hash": event.payload_hash,
            "prior_hash": event.prior_hash,
            "signer_key_id": event.signer_key_id,
            "key_scheme": event.key_scheme,
            "sig_format_version": 1,
            "hash_alg": event.hash_alg,
        }

        # No domain prefix — bare rfc8785 bytes
        unprefixed_representative = rfc8785.dumps(fields)
        unprefixed_digest = hashlib.sha3_256(unprefixed_representative).digest()

        sig_bytes = base64.urlsafe_b64decode(event.signature + "==")
        pub = Ed25519PublicKey.from_public_bytes(chain._signer.public_key_bytes())

        with pytest.raises(InvalidSignature):
            pub.verify(sig_bytes, unprefixed_digest)

    def test_prefixed_bytes_verify(self) -> None:
        """Sanity: sign-with-prefix then verify-with-prefix must succeed."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        chain = Sigchain()
        event = chain.new_event(event_type="p2g.domain_sep_ok", payload={}, actor="a")

        # hash_event_for_chain uses the prefixed representative — equals signed digest
        expected = bytes.fromhex(AuditEvent.hash_event_for_chain(event))
        sig_bytes = base64.urlsafe_b64decode(event.signature + "==")
        pub = Ed25519PublicKey.from_public_bytes(chain._signer.public_key_bytes())
        pub.verify(sig_bytes, expected)  # must not raise


# ---------------------------------------------------------------------------
# Non-ASCII independent-verify fix
# ---------------------------------------------------------------------------

class TestNonASCIIIndependentVerify:
    """An entry with a non-ASCII actor verifies via rfc8785 independently — no \\uXXXX."""

    def test_nonascii_actor_verifies(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="p2g.nonascii", payload={}, actor="café-agent")
        assert chain.verify_chain([event]) is True

    def test_nonascii_actor_canonical_bytes_match_rfc8785(self) -> None:
        """The canonical bytes produced during signing match an independent rfc8785.dumps call."""
        chain = Sigchain()
        event = chain.new_event(event_type="p2g.nonascii_bytes", payload={}, actor="日本語エージェント")

        fields = {
            "event_id": event.event_id,
            "episode_id": event.episode_id,
            "sequence": event.sequence,
            "event_type": event.event_type,
            "schema_version": event.schema_version,
            "valid_from": event.valid_from,
            "valid_to": event.valid_to,
            "system_time": str(event.system_time),
            "causation_id": event.causation_id,
            "correlation_id": event.correlation_id,
            "actor": event.actor,
            "trace_id": event.trace_id,
            "span_id": event.span_id,
            "payload_hash": event.payload_hash,
            "prior_hash": event.prior_hash,
            "signer_key_id": event.signer_key_id,
            "key_scheme": event.key_scheme,
            "sig_format_version": 1,
            "hash_alg": event.hash_alg,
        }
        independent_rep = DOMAIN_PREFIX + rfc8785.dumps(fields)
        expected_hash = hashlib.sha3_256(independent_rep).hexdigest()

        # Must match hash_event_for_chain (which uses _message_representative internally)
        assert AuditEvent.hash_event_for_chain(event) == expected_hash

    def test_nonascii_canonical_has_utf8_not_escape(self) -> None:
        """The canonical bytes for the actor field must be UTF-8, not \\uXXXX."""
        fields = {"actor": "café"}
        canonical = _canonicalize(fields)
        assert b"\\u" not in canonical
        assert b"caf\xc3\xa9" in canonical  # é encoded as UTF-8 bytes 0xC3 0xA9


# ---------------------------------------------------------------------------
# Full chain verification — classical and hybrid
# ---------------------------------------------------------------------------

class TestFullChainVerification:
    def test_classical_chain_verifies(self) -> None:
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"p2g.classical.{i}", payload={"i": i}, actor="a")
            for i in range(5)
        ]
        assert chain.verify_chain(events) is True

    @needs_liboqs
    def test_hybrid_chain_verifies_with_liboqs(self) -> None:
        """Hybrid chain must produce PASSED (not skipped) WITH liboqs installed."""
        from aevum.core.signing import DualSigner
        chain = Sigchain(dual_signer=DualSigner.generate())
        events = [
            chain.new_event(event_type=f"p2g.hybrid.{i}", payload={"i": i}, actor="a")
            for i in range(3)
        ]
        assert all(e.key_scheme == "ed25519+ml-dsa-65" for e in events)
        assert all(e.mldsa65_sig is not None for e in events)
        assert chain.verify_chain(events) is True

    @needs_liboqs
    def test_both_signatures_verify_over_new_representative(self) -> None:
        """Both Ed25519 and ML-DSA-65 verify over DOMAIN_PREFIX + rfc8785.dumps(19 fields)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        event = chain.new_event(event_type="p2g.both_sigs", payload={}, actor="a")

        fields = {
            "event_id": event.event_id,
            "episode_id": event.episode_id,
            "sequence": event.sequence,
            "event_type": event.event_type,
            "schema_version": event.schema_version,
            "valid_from": event.valid_from,
            "valid_to": event.valid_to,
            "system_time": str(event.system_time),
            "causation_id": event.causation_id,
            "correlation_id": event.correlation_id,
            "actor": event.actor,
            "trace_id": event.trace_id,
            "span_id": event.span_id,
            "payload_hash": event.payload_hash,
            "prior_hash": event.prior_hash,
            "signer_key_id": event.signer_key_id,
            "key_scheme": event.key_scheme,
            "sig_format_version": 1,
            "hash_alg": event.hash_alg,
        }
        representative = DOMAIN_PREFIX + rfc8785.dumps(fields)

        # Verify Ed25519 against sha3_256(representative)
        digest = hashlib.sha3_256(representative).digest()
        sig_bytes = base64.urlsafe_b64decode(event.signature + "==")
        pub_ed25519 = Ed25519PublicKey.from_public_bytes(chain._signer.public_key_bytes())
        pub_ed25519.verify(sig_bytes, digest)  # must not raise

        # Verify ML-DSA-65 against representative directly (not its hash)
        assert event.mldsa65_sig is not None
        assert event.mldsa65_pub is not None
        DualSigner.verify_mldsa(
            representative,
            bytes.fromhex(event.mldsa65_sig),
            bytes.fromhex(event.mldsa65_pub),
        )


# ---------------------------------------------------------------------------
# ML-DSA level agility
# ---------------------------------------------------------------------------

class TestMLDSALevelAgility:
    @needs_liboqs
    def test_scheme_string_is_ed25519_plus_suffix(self) -> None:
        from aevum.core.signing import DualSigner
        ds = DualSigner.generate()
        chain = Sigchain(dual_signer=ds)
        event = chain.new_event(event_type="t", payload={}, actor="a")
        assert event.key_scheme == f"ed25519+{ds.scheme_suffix}"

    def test_unknown_mldsa_level_rejected(self) -> None:
        """verify_chain must reject an unknown ML-DSA level suffix — fail closed."""
        import dataclasses
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")

        # Tamper the key_scheme to an unknown ML-DSA level
        tampered = dataclasses.replace(event, key_scheme="ed25519+ml-dsa-999")
        assert chain.verify_chain([tampered]) is False

    def test_verify_mldsa_alg_parameter(self) -> None:
        """DualSigner.verify_mldsa accepts an alg kwarg for level agility."""
        import inspect

        from aevum.core.signing import DualSigner
        sig = inspect.signature(DualSigner.verify_mldsa)
        assert "alg" in sig.parameters, "verify_mldsa must have an alg keyword parameter"


# ---------------------------------------------------------------------------
# sig_format_version still required
# ---------------------------------------------------------------------------

class TestSigFormatVersionStillEnforced:
    def test_events_have_sig_format_version_1(self) -> None:
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        assert event.sig_format_version == 1

    def test_verify_chain_rejects_none_format_version(self) -> None:
        import dataclasses
        chain = Sigchain()
        event = chain.new_event(event_type="t", payload={}, actor="a")
        bad = dataclasses.replace(event, sig_format_version=None)
        assert chain.verify_chain([bad]) is False

# SPDX-License-Identifier: Apache-2.0
"""Tests for Phase 1 sigchain upgrade: ImmutableLedgerError and dual-sig integration."""
import pytest

try:
    import oqs as _oqs_check  # noqa: F401
except (ImportError, OSError, SystemExit):
    pytest.skip("liboqs native library not available — skipping oqs-dependent tests", allow_module_level=True)

from aevum.core.audit.sigchain import GENESIS_HASH, ImmutableLedgerError, Sigchain
from aevum.core.sigchain import ImmutableLedgerError as FacadeImmutableLedgerError
from aevum.core.sigchain import Sigchain as FacadeSigchain
from aevum.core.signing import DualSigner
from aevum.core.tsa import TSAClient


class TestImmutableLedgerError:
    def test_is_exception_subclass(self):
        assert issubclass(ImmutableLedgerError, Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(ImmutableLedgerError):
            raise ImmutableLedgerError("test")

    def test_facade_re_exports_same_class(self):
        assert FacadeImmutableLedgerError is ImmutableLedgerError


class TestSigchainFacade:
    def test_facade_sigchain_is_same_class(self):
        assert FacadeSigchain is Sigchain

    def test_facade_genesis_hash(self):
        from aevum.core.sigchain import GENESIS_HASH as facade_genesis
        assert facade_genesis == GENESIS_HASH


class TestSigchainDualSig:
    def test_sigchain_with_dual_signer_stores_fields(self):
        """P2f: AuditEvent stores only ML-DSA-65 fields; ed25519_sig/ed25519_pub removed."""
        dual_signer = DualSigner.generate()
        tsa_client = TSAClient(enabled=False)
        chain = Sigchain(dual_signer=dual_signer, tsa_client=tsa_client)
        event = chain.new_event(event_type="test.e", payload={}, actor="test")

        assert not hasattr(event, "ed25519_sig"), "ed25519_sig must not exist on AuditEvent (P2f)"
        assert not hasattr(event, "ed25519_pub"), "ed25519_pub must not exist on AuditEvent (P2f)"
        assert event.mldsa65_sig is not None
        assert event.mldsa65_pub is not None

    def test_sigchain_with_dual_signer_sig_lengths(self):
        """P2b-2: only ML-DSA-65 signature fields are stored."""
        dual_signer = DualSigner.generate()
        chain = Sigchain(dual_signer=dual_signer)
        event = chain.new_event(event_type="test.e", payload={}, actor="test")

        # mldsa65_sig: 3309 bytes -> 6618 hex chars
        assert len(event.mldsa65_sig) == 6618
        # mldsa65_pub: 1952 bytes -> 3904 hex chars
        assert len(event.mldsa65_pub) == 3904

    def test_sigchain_without_dual_signer_has_none_fields(self):
        chain = Sigchain()
        event = chain.new_event(event_type="test.e", payload={}, actor="test")

        assert event.mldsa65_sig is None
        assert event.mldsa65_pub is None

    def test_sigchain_tsa_disabled_stores_none(self):
        dual_signer = DualSigner.generate()
        tsa_client = TSAClient(enabled=False)
        chain = Sigchain(dual_signer=dual_signer, tsa_client=tsa_client)
        event = chain.new_event(event_type="test.e", payload={}, actor="test")

        assert event.tsa_url is None
        assert event.tsa_token is None

    def test_verify_chain_with_dual_sig(self):
        dual_signer = DualSigner.generate()
        tsa_client = TSAClient(enabled=False)
        chain = Sigchain(dual_signer=dual_signer, tsa_client=tsa_client)
        events = [
            chain.new_event(event_type=f"test.{i}", payload={"i": i}, actor="a")
            for i in range(3)
        ]
        assert chain.verify_chain(events) is True

    def test_old_entries_without_dual_sig_pass_verify(self):
        """Pre-Phase-1 entries (no mldsa65_sig) must still verify."""
        chain = Sigchain()
        events = [
            chain.new_event(event_type=f"test.{i}", payload={}, actor="a")
            for i in range(3)
        ]
        assert all(e.mldsa65_sig is None for e in events)
        assert chain.verify_chain(events) is True


class _ExplodingDualSigner:
    """Duck-typed dual_signer stub: new_event() only accesses .scheme_suffix and
    .sign() — no isinstance check — so this is sufficient to drive the dual-sig
    exception-handling branch without depending on a real key-corruption scenario."""

    scheme_suffix = "ml-dsa-65"

    def sign(self, data: bytes) -> object:
        raise RuntimeError("dual-sig hardware fault")


class _StubTSAToken:
    def __init__(self, tsa_url: str, token_bytes: bytes) -> None:
        self.tsa_url = tsa_url
        self.token_bytes = token_bytes


class _StubTSAClientSuccess:
    """Duck-typed tsa_client stub returning a successful token on every call."""

    def __init__(self, token: _StubTSAToken) -> None:
        self._token = token

    def timestamp(self, data: bytes) -> _StubTSAToken:
        return self._token


class _ExplodingTSAClient:
    def timestamp(self, data: bytes) -> object:
        raise RuntimeError("TSA endpoint unreachable")


class TestSigchainPipelineExceptionPaths:
    """These tests use a real DualSigner alongside stub TSA clients to exercise
    the dual-sig + TSA paths together. See test_sigchain_escalation_tsa_wiring.py
    for coverage of TSA firing independently of dual_signer."""

    def test_dual_sig_failure_is_caught_and_non_blocking(self):
        chain = Sigchain(dual_signer=_ExplodingDualSigner())
        event = chain.new_event(event_type="test.e", payload={}, actor="a")
        assert event.mldsa65_sig is None
        assert event.mldsa65_pub is None

    def test_tsa_success_path_stores_token_on_event(self):
        dual_signer = DualSigner.generate()
        token = _StubTSAToken(tsa_url="https://tsa.example.test", token_bytes=b"\x01\x02\x03")
        chain = Sigchain(dual_signer=dual_signer, tsa_client=_StubTSAClientSuccess(token))
        event = chain.new_event(event_type="test.e", payload={}, actor="a")
        assert event.tsa_url == "https://tsa.example.test"
        assert event.tsa_token == token.token_bytes.hex()

    def test_tsa_failure_is_caught_and_non_blocking(self):
        dual_signer = DualSigner.generate()
        chain = Sigchain(dual_signer=dual_signer, tsa_client=_ExplodingTSAClient())
        event = chain.new_event(event_type="test.e", payload={}, actor="a")
        assert event.tsa_url is None
        assert event.tsa_token is None

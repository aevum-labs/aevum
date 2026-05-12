# SPDX-License-Identifier: Apache-2.0
"""Tests for Phase 1 sigchain upgrade: ImmutableLedgerError and dual-sig integration."""
import pytest

from aevum.core.audit.sigchain import Sigchain, ImmutableLedgerError, GENESIS_HASH
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
        dual_signer = DualSigner.generate()
        tsa_client = TSAClient(enabled=False)
        chain = Sigchain(dual_signer=dual_signer, tsa_client=tsa_client)
        event = chain.new_event(event_type="test.e", payload={}, actor="test")

        assert event.ed25519_sig is not None
        assert event.mldsa65_sig is not None
        assert event.ed25519_pub is not None
        assert event.mldsa65_pub is not None

    def test_sigchain_with_dual_signer_sig_lengths(self):
        dual_signer = DualSigner.generate()
        chain = Sigchain(dual_signer=dual_signer)
        event = chain.new_event(event_type="test.e", payload={}, actor="test")

        # ed25519_sig: 64 bytes -> 128 hex chars
        assert len(event.ed25519_sig) == 128
        # mldsa65_sig: 3309 bytes -> 6618 hex chars
        assert len(event.mldsa65_sig) == 6618
        # ed25519_pub: 32 bytes -> 64 hex chars
        assert len(event.ed25519_pub) == 64
        # mldsa65_pub: 1952 bytes -> 3904 hex chars
        assert len(event.mldsa65_pub) == 3904

    def test_sigchain_without_dual_signer_has_none_fields(self):
        chain = Sigchain()
        event = chain.new_event(event_type="test.e", payload={}, actor="test")

        assert event.ed25519_sig is None
        assert event.mldsa65_sig is None
        assert event.ed25519_pub is None
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

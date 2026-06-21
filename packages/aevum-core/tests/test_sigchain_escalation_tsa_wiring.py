# SPDX-License-Identifier: Apache-2.0
"""HO-SIGCHAIN-FIX: regression tests for two new_event() wiring bugs.

FIX #2 — AevumReceipt.from_sigchain_event(event) was always called with no
kwargs, so handoff_type/human_override_action/barrier_evaluations defaulted
to non-escalating values regardless of what the caller's payload said.
should_escalate() could never return True via Sigchain.new_event().

FIX #1 — the TSA timestamp block was nested inside `if self._dual_signer is
not None`, so an Ed25519-only chain with a configured tsa_client silently
never got a TSA token (this is the documented Kernel.local() default for
posture="classical-only", tsa_enabled=True — not a purely theoretical gap).
"""

from __future__ import annotations

from aevum.publish.encoder import ReceiptEncoder

from aevum.core.audit.sigchain import Sigchain
from aevum.core.audit.signer import InProcessSigner


class _RecordingReceiptStore:
    """Duck-typed receipt_store stub recording put()/lock() calls."""

    def __init__(self) -> None:
        self.put_calls: list[str] = []
        self.locked_hashes: list[str] = []

    def put(
        self,
        receipt_hash: str,
        blob: bytes,
        entry_hash: str = "",
        rekor_entry_ref: str = "",
        tier: str = "operational",
    ) -> None:
        self.put_calls.append(receipt_hash)

    def get(self, receipt_hash: str) -> bytes | None:
        return None

    def lock(self, receipt_hash: str) -> None:
        self.locked_hashes.append(receipt_hash)

    def list_hashes(
        self, after: str | None = None, limit: int = 100, tier: str | None = None
    ) -> list[str]:
        return []

    def put_ambient(self, snapshot_id: str, blob: bytes, session_id: str, trigger: str) -> None:
        pass

    def get_ambient(self, snapshot_id: str) -> bytes | None:
        return None


class TestEscalationWiring:
    """FIX #2: new_event()'s receipt pipeline must wire real escalation fields."""

    def _make_chain(self) -> tuple[Sigchain, _RecordingReceiptStore]:
        signer = InProcessSigner()
        store = _RecordingReceiptStore()
        chain = Sigchain(
            signer=signer,
            receipt_encoder=ReceiptEncoder(signer=signer),
            receipt_store=store,
        )
        return chain, store

    def test_escalating_handoff_type_triggers_lock(self) -> None:
        """A MINIMUM_RISK handoff in the payload must escalate (lock the receipt)."""
        chain, store = self._make_chain()
        chain.new_event(
            event_type="test.e",
            payload={"handoff_type": "MINIMUM_RISK"},
            actor="a",
        )
        assert len(store.locked_hashes) == 1

    def test_escalating_human_override_reject_triggers_lock(self) -> None:
        chain, store = self._make_chain()
        chain.new_event(
            event_type="test.e",
            payload={"human_override_action": "REJECT"},
            actor="a",
        )
        assert len(store.locked_hashes) == 1

    def test_escalating_barrier_deny_triggers_lock(self) -> None:
        chain, store = self._make_chain()
        chain.new_event(
            event_type="test.e",
            payload={"barrier_evaluations": {"Crisis": "DENY"}},
            actor="a",
        )
        assert len(store.locked_hashes) == 1

    def test_non_escalating_event_does_not_lock(self) -> None:
        chain, store = self._make_chain()
        chain.new_event(
            event_type="test.e",
            payload={"handoff_type": "ACTIVATION"},
            actor="a",
        )
        assert len(store.put_calls) == 1
        assert store.locked_hashes == []

    def test_default_payload_does_not_lock(self) -> None:
        chain, store = self._make_chain()
        chain.new_event(event_type="test.e", payload={}, actor="a")
        assert store.locked_hashes == []


class TestTSAIndependentOfDualSigner:
    """FIX #1: TSA must fire whenever tsa_client is configured, regardless of
    whether a dual_signer is present (Ed25519-only + TSA is a supported
    posture — Kernel.local() default is classical-only with tsa_enabled=True)."""

    def test_tsa_fires_without_dual_signer(self) -> None:
        class _StubTSAToken:
            def __init__(self, tsa_url: str, token_bytes: bytes) -> None:
                self.tsa_url = tsa_url
                self.token_bytes = token_bytes

        class _StubTSAClientSuccess:
            def __init__(self, token: _StubTSAToken) -> None:
                self._token = token

            def timestamp(self, data: bytes) -> _StubTSAToken:
                return self._token

        token = _StubTSAToken(tsa_url="https://tsa.example.test", token_bytes=b"\x01\x02\x03")
        chain = Sigchain(dual_signer=None, tsa_client=_StubTSAClientSuccess(token))
        event = chain.new_event(event_type="test.e", payload={}, actor="a")

        assert event.mldsa65_sig is None  # no dual signer configured
        assert event.tsa_url == "https://tsa.example.test"
        assert event.tsa_token == token.token_bytes.hex()

    def test_tsa_failure_without_dual_signer_is_non_blocking(self) -> None:
        class _ExplodingTSAClient:
            def timestamp(self, data: bytes) -> object:
                raise RuntimeError("TSA endpoint unreachable")

        chain = Sigchain(dual_signer=None, tsa_client=_ExplodingTSAClient())
        event = chain.new_event(event_type="test.e", payload={}, actor="a")
        assert event.tsa_url is None
        assert event.tsa_token is None

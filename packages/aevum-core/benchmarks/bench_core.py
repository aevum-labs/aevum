# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum core benchmarks — pytest-benchmark.

Run: pytest packages/aevum-core/benchmarks/ --benchmark-only -v

Benchmarks four core operations:

1. Ed25519 signing (PyNaCl, without ML-DSA-65)
2. Cedar ABAC evaluation (CedarPolicyEngine)
3. Merkle root computation (SessionRecord)
4. Consent ledger grant+check

These establish the performance baseline before any optimization.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

# ── Fixture: Ed25519 signer (no ML-DSA-65 to avoid oqs dependency) ─────────

@pytest.fixture(scope="session")
def ed25519_sk() -> object:
    import nacl.signing
    return nacl.signing.SigningKey.generate()


@pytest.fixture(scope="session")
def cedar_engine() -> object:
    from aevum.core.cedar_engine import CedarPolicyEngine
    return CedarPolicyEngine.default()


@pytest.fixture(scope="session")
def consent_ledger(tmp_path_factory: pytest.TempPathFactory) -> object:  # type: ignore[misc]
    tmp = tmp_path_factory.mktemp("bench")
    from aevum.core.consent.ledger import ConsentLedger
    ledger = ConsentLedger(tmp / "bench.db")
    yield ledger
    ledger.close()


# ── Benchmark 1: Ed25519 signing ─────────────────────────────────────────────

def test_bench_ed25519_sign(benchmark: object, ed25519_sk: object) -> None:
    data = b"aevum-benchmark-payload-" * 10

    def _sign() -> None:
        ed25519_sk.sign(data)

    benchmark.pedantic(_sign, iterations=100, rounds=10)


def test_bench_ed25519_verify(benchmark: object, ed25519_sk: object) -> None:
    data = b"aevum-benchmark-payload-" * 10
    signed = ed25519_sk.sign(data)
    vk = ed25519_sk.verify_key

    def _verify() -> None:
        vk.verify(signed)

    benchmark.pedantic(_verify, iterations=100, rounds=10)


# ── Benchmark 2: Cedar ABAC ──────────────────────────────────────────────────

def test_bench_cedar_permit(benchmark: object, cedar_engine: object) -> None:
    ctx = {
        "has_crisis_content": False,
        "has_active_consent": True,
        "consent_purpose_matches": True,
        "data_classification_level": 0,
        "deployment_ceiling_level": 3,
        "taint_reads_untrusted": False,
        "taint_reads_private": False,
        "taint_can_exfiltrate": False,
    }

    def _eval() -> None:
        cedar_engine.is_permitted(
            "AevumAgent", "agent", "relate_graph_write", "DataGraph", "knowledge", ctx
        )

    benchmark.pedantic(_eval, iterations=100, rounds=10)


def test_bench_cedar_deny_crisis(benchmark: object, cedar_engine: object) -> None:
    ctx = {"has_crisis_content": True}

    def _eval() -> None:
        cedar_engine.is_permitted(
            "AevumAgent", "agent", "relate_graph_write", "DataGraph", "knowledge", ctx
        )

    benchmark.pedantic(_eval, iterations=100, rounds=10)


# ── Benchmark 3: Merkle root ─────────────────────────────────────────────────

def test_bench_merkle_root_10_events(benchmark: object) -> None:
    from aevum.core.session_record import EventType, SessionEvent, SessionRecord
    now = datetime.now(UTC)
    h = hashlib.sha256(b"test").hexdigest()
    events = tuple(
        SessionEvent(f"ev-{i}", "sess", i, EventType.RELATE, now, h, h, 10, ())
        for i in range(10)
    )

    def _root() -> None:
        SessionRecord.compute_merkle_root(events)

    benchmark.pedantic(_root, iterations=100, rounds=10)


def test_bench_merkle_root_100_events(benchmark: object) -> None:
    from aevum.core.session_record import EventType, SessionEvent, SessionRecord
    now = datetime.now(UTC)
    h = hashlib.sha256(b"test").hexdigest()
    events = tuple(
        SessionEvent(f"ev-{i}", "sess", i, EventType.RELATE, now, h, h, 10, ())
        for i in range(100)
    )

    def _root() -> None:
        SessionRecord.compute_merkle_root(events)

    benchmark.pedantic(_root, iterations=20, rounds=5)


# ── Benchmark 4: Consent ledger ──────────────────────────────────────────────

def test_bench_consent_grant_and_check(benchmark: object, consent_ledger: object) -> None:
    counter = [0]

    def _grant_check() -> None:
        subject = f"bench-{counter[0]}"
        consent_ledger.grant(subject, "benchmark")
        consent_ledger.check(subject, "benchmark")
        counter[0] += 1

    benchmark.pedantic(_grant_check, iterations=20, rounds=5)

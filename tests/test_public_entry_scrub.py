# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Invariant tests for PublicSigchainEntry scrubbing.

If SignedEntry gains a new field this suite fails, forcing an explicit
decision about whether that field should be exposed publicly.
"""
from aevum_maintainer.demo_routes import (
    PublicSigchainEntry,
    _scrub_entry,
)
from aevum_maintainer.persistence import SignedEntry

KNOWN_SIGNED_ENTRY_KEYS = {
    "entry_hash", "prior_hash", "action", "resource",
    "principal", "payload", "timestamp", "signature",
    "session_id",
}


def _raw(**overrides: object) -> dict:
    base: dict = dict(
        entry_hash="a" * 64,
        prior_hash="genesis",
        action="ingest",
        resource="scan_results",
        principal="github_actions",
        payload={"secret": "must-not-appear"},
        timestamp="2026-06-01T00:00:00Z",
        signature="",
        session_id="s",
        rekor_anchor=None,
    )
    return {**base, **overrides}


def test_known_signed_entry_schema() -> None:
    assert set(SignedEntry.model_fields) == KNOWN_SIGNED_ENTRY_KEYS, (
        "SignedEntry gained a new field — update "
        "PublicSigchainEntry explicitly."
    )


def test_payload_excluded() -> None:
    r = _scrub_entry(_raw())
    assert "payload" not in r
    assert "must-not-appear" not in str(r)
    assert len(r["payload_hash"]) == 64


def test_whitelist_only() -> None:
    r = _scrub_entry(_raw())
    assert set(r.keys()) == set(PublicSigchainEntry.model_fields)


def test_deterministic() -> None:
    raw = _raw(payload={"k": "v"})
    assert _scrub_entry(raw)["payload_hash"] == _scrub_entry(raw)["payload_hash"]


def test_payload_summary_extracted() -> None:
    r = _scrub_entry(_raw(payload={"secret": "x", "summary": "2 CVEs found · status: findings"}))
    assert r["payload_summary"] == "2 CVEs found · status: findings"


def test_payload_summary_empty_when_absent() -> None:
    r = _scrub_entry(_raw(payload={"secret": "x"}))
    assert r["payload_summary"] == ""

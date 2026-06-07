# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Session record types for REMEMBER and REPLAY.

A Session accumulates SessionEvents as it runs. When the session closes,
REMEMBER builds a SessionRecord (the immutable, signed summary) and
commits it to the sigchain.

The Merkle root of all event input/output hashes is stored in the sigchain.
This means: you cannot silently reorder, add, or remove events from a session
without invalidating the root — and the root is dual-signed.

REPLAY uses the stored events to re-execute a session deterministically.
fork_at_step creates a new session branch from an existing one at a given step.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Any


class CommitType(StrEnum):
    """
    The reason a session was closed and committed to the sigchain.
    Six types — every session commit has one.
    """
    COMPLETE  = "complete"    # Normal close via context manager exit
    PARTIAL   = "partial"     # Session closed with incomplete work
    VETOED    = "vetoed"      # GOVERN checkpoint vetoed; session halted
    CRISIS    = "crisis"      # Crisis barrier fired; session halted immediately
    EMERGENCY = "emergency"   # Exception during session (exc_type is not None)
    TIMEOUT   = "timeout"     # Session exceeded maximum duration


class EventType(StrEnum):
    """The kind of operation recorded in a SessionEvent."""
    RELATE   = "relate"    # RELATE (ingest) call
    NAVIGATE = "navigate"  # NAVIGATE (query) call
    GOVERN   = "govern"    # GOVERN checkpoint call
    LLM      = "llm"       # LLM call (prompt + response)
    TOOL     = "tool"      # Tool/function call
    SYSTEM   = "system"    # Internal kernel event


@dataclasses.dataclass(frozen=True)
class SessionEvent:
    """
    A single recorded step within a session.

    input_hash and output_hash are SHA-256 over canonical JSON of the
    inputs/outputs. Storing hashes (not plaintext) preserves privacy
    while enabling tamper detection and replay verification.

    For verifiable decision records, the full inputs must be stored elsewhere
    (e.g. encrypted with the subject's DEK in the consent store).
    The sigchain stores only hashes.
    """
    event_id: str
    session_id: str
    sequence: int              # monotonically increasing within session (0, 1, 2, ...)
    event_type: EventType
    occurred_at: datetime
    input_hash: str            # SHA-256 hex of canonical JSON inputs
    output_hash: str           # SHA-256 hex of canonical JSON outputs
    latency_ms: int            # wall-clock time for this event
    taint_labels: tuple[str, ...]   # active taint labels during this event
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError(f"SessionEvent.sequence must be >= 0, got {self.sequence}")
        if len(self.input_hash) != 64:
            raise ValueError(
                f"input_hash must be 64-char hex, got {len(self.input_hash)}"
            )
        if len(self.output_hash) != 64:
            raise ValueError(
                f"output_hash must be 64-char hex, got {len(self.output_hash)}"
            )

    @staticmethod
    def hash_payload(payload: dict[str, Any]) -> str:
        """SHA-256 over canonical JSON of payload. Deterministic."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclasses.dataclass(frozen=True)
class SessionRecord:
    """
    The immutable, signed summary of a completed session.
    Written to the sigchain by REMEMBER on every session close.

    merkle_root: SHA-256 over all event hashes in sequence order.
    This makes the event sequence tamper-evident. The sigchain stores
    the root and both signatures (Ed25519 + ML-DSA-65).
    """
    session_id: str
    commit_type: CommitType
    principal: str         # agent or user identifier
    purpose: str
    started_at: datetime
    closed_at: datetime
    events: tuple[SessionEvent, ...]
    fact_ids: tuple[str, ...]          # TypedFact IDs created in this session
    checkpoint_ids: tuple[str, ...]    # GovernCheckpoint IDs from this session
    merkle_root: str                   # SHA-256 over ordered event hashes
    sigchain_entry_id: int | None = None    # populated after write
    tsa_token_hex: str | None = None        # populated after RFC 3161

    def __post_init__(self) -> None:
        if not self.session_id:
            raise ValueError("session_id must be non-empty")
        if not self.purpose:
            raise ValueError("purpose must be non-empty")
        if self.closed_at < self.started_at:
            raise ValueError("closed_at must be >= started_at")
        if len(self.merkle_root) != 64:
            raise ValueError(
                f"merkle_root must be 64-char hex, got {len(self.merkle_root)}"
            )

    @staticmethod
    def compute_merkle_root(events: tuple[SessionEvent, ...]) -> str:
        """
        Compute the Merkle root of the event sequence.
        Simple binary Merkle tree over sorted-sequence event hashes.
        Empty session: SHA-256 of empty string.
        """
        if not events:
            return hashlib.sha256(b"").hexdigest()

        # Leaf hashes: SHA-256(input_hash || output_hash) per event in sequence order
        leaves = [
            hashlib.sha256(
                (ev.input_hash + ev.output_hash).encode("ascii")
            ).hexdigest()
            for ev in sorted(events, key=lambda e: e.sequence)
        ]

        # Build tree bottom-up
        current = leaves
        while len(current) > 1:
            next_level: list[str] = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                combined = hashlib.sha256(
                    (left + right).encode("ascii")
                ).hexdigest()
                next_level.append(combined)
            current = next_level

        return current[0]

    @property
    def duration_seconds(self) -> float:
        return (self.closed_at - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Serializable dict for storage and display."""
        return {
            "session_id": self.session_id,
            "commit_type": self.commit_type.value,
            "principal": self.principal,
            "purpose": self.purpose,
            "started_at": self.started_at.isoformat(),
            "closed_at": self.closed_at.isoformat(),
            "event_count": len(self.events),
            "fact_count": len(self.fact_ids),
            "checkpoint_count": len(self.checkpoint_ids),
            "merkle_root": self.merkle_root,
            "sigchain_entry_id": self.sigchain_entry_id,
            "duration_seconds": self.duration_seconds,
        }

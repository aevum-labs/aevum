# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""Seven formal invariants for the Aevum black box receipt format layer."""

from __future__ import annotations

__all__ = ["INVARIANTS", "INVARIANT_IDS", "invariant_description"]

INVARIANTS: dict[str, str] = {
    "I1-APPEND_ONLY":
        "No sigchain entry may be modified or deleted after commit.",
    "I2-COMPLETENESS":
        "Every agent action produces exactly one receipt before acknowledgment.",
    "I3-INTEGRITY":
        "Every receipt carries an Ed25519 signature over SHA3-256 of the canonical payload.",
    "I4-BOUNDARY_ENFORCEMENT":
        "Cedar policy is evaluated for every tool invocation before execution.",
    "I5-MONOTONIC_SEQUENCE":
        "The sequence counter is strictly monotonically increasing.",
    "I6-CRASH_PROTECTED":
        "In production mode, receipt blob is written to WORM or replicated off-host before acknowledgment.",
    "I7-SCITT_REGISTERED":
        "In production mode, a transparency service inclusion proof is available within the Maximum Merge Delay.",
}

INVARIANT_IDS: list[str] = list(INVARIANTS.keys())


def invariant_description(invariant_id: str) -> str:
    return INVARIANTS[invariant_id]

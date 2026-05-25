# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Escalation trigger logic for crash_protected tier.

DSSAD-equivalent (UNECE WP.29 UN R157): captures "why it happened" for events
that required regulatory-grade crash protection. Escalation is permanent —
crash_protected receipts cannot be demoted (no unlock()).

Escalation check is non-blocking: failures are logged and do not propagate to
the caller of SigChain.new_event().
"""

from __future__ import annotations

from typing import Any

from aevum.core.store import ReceiptStore

# Trigger conditions that escalate a receipt to crash_protected tier.
CRASH_PROTECTED_TRIGGERS = frozenset({
    "POLICY_DENY",           # any Cedar policy DENY decision
    "HUMAN_OVERRIDE_REJECT", # human override action = REJECT
    "MINIMUM_RISK",          # handoff_type = MINIMUM_RISK
    "SYSTEM_FAILURE",        # handoff_type = FAILURE
    "ODD_EXIT",              # handoff_type = ODD_EXIT
})


def should_escalate(
    event_action: str,
    handoff_type: str | None,
    human_override_action: str | None,
    barrier_evaluations: dict[str, Any],
) -> bool:
    """
    Returns True if this event should trigger crash_protected tier escalation.
    Called AFTER the receipt is stored in operational tier.
    """
    if any(v == "DENY" for v in barrier_evaluations.values()):
        return True
    if human_override_action == "REJECT":
        return True
    return handoff_type in ("MINIMUM_RISK", "FAILURE", "ODD_EXIT")


def escalate_if_triggered(
    store: ReceiptStore,
    receipt_hash: str,
    event_action: str,
    handoff_type: str | None,
    human_override_action: str | None,
    barrier_evaluations: dict[str, Any],
) -> bool:
    """
    Check escalation conditions and lock the receipt if triggered.
    Returns True if the receipt was escalated, False otherwise.
    Designed to be called immediately after store.put().
    """
    if should_escalate(
        event_action, handoff_type, human_override_action, barrier_evaluations
    ):
        store.lock(receipt_hash)
        return True
    return False

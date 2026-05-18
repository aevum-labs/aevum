# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""Test helper — normalized sigchain output for snapshot assertions."""
from __future__ import annotations

from typing import Any

from dirty_equals import IsStr


def fetch_normalized_sigchain_entries(kernel: Any) -> list[dict[str, Any]]:
    """
    Return all ledger entries as plain dicts with dynamic fields replaced
    by dirty-equals matchers for stable snapshot assertions.

    Dynamic fields (timestamps, hashes, IDs) are normalized — they are
    present in the snapshot but matched loosely so snapshot literals remain
    stable across runs.

    kernel: an Engine instance with ._ledger.all_events()
    """
    entries = []
    for event in kernel._ledger.all_events():
        entries.append({
            "event_type": event.event_type,
            "actor": event.actor,
            "event_id": IsStr(regex=r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
            "system_time": IsStr() | int,
            "prior_hash": IsStr(regex=r"^[0-9a-f]{64}$"),
            "payload_hash": IsStr(regex=r"^[0-9a-f]{64}$"),
            "signature": IsStr(),
            "payload": event.payload,
        })
    return entries

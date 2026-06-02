# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Internal sigchain entry representation for aevum-maintainer.

SignedEntry is the raw internal format used to expose ledger data through
the public demo routes.  PublicSigchainEntry in demo_routes.py is derived
from this and scrubs the raw payload before it reaches the browser.

S-12: fields are additive-only once a tagged release ships.
"""
from typing import Any

from pydantic import BaseModel


class SignedEntry(BaseModel):
    """Raw sigchain entry as stored in the aevum-maintainer ledger.

    Field additions require an explicit update to PublicSigchainEntry in
    demo_routes.py — the test_public_entry_scrub suite enforces this by
    comparing SignedEntry.__annotations__ to a known-good set.
    """

    entry_hash: str
    prior_hash: str
    action: str
    resource: str
    principal: str
    payload: dict[str, Any]
    timestamp: str
    signature: str
    session_id: str

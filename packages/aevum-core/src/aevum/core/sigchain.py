# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
aevum.core.sigchain — public facade for the sigchain module.

Re-exports from aevum.core.audit.sigchain so that callers can use:
    from aevum.core.sigchain import ImmutableLedgerError, Sigchain
"""
from __future__ import annotations

from aevum.core.audit.sigchain import (
    GENESIS_HASH,
    ImmutableLedgerError,
    Sigchain,
)

__all__ = ["GENESIS_HASH", "ImmutableLedgerError", "Sigchain"]

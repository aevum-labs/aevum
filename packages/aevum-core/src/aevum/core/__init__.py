"""
aevum.core — The Aevum context kernel.

Usage:
    from aevum.core import Engine
    engine = Engine()
    result = engine.commit(event_type="app.event", payload={}, actor="user-1")
"""

from __future__ import annotations

from aevum.core.engine import Engine
from aevum.core.envelope.models import OutputEnvelope
from aevum.core.exceptions import (
    AevumError,
    BarrierViolationError,
    ConsentRequiredError,
    ProvenanceRequiredError,
)

__version__ = "0.2.0"

__all__ = [
    "Engine",
    "OutputEnvelope",
    "AevumError",
    "BarrierViolationError",
    "ConsentRequiredError",
    "ProvenanceRequiredError",
]

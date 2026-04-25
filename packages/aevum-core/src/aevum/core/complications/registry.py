"""
ComplicationRegistry — 7-state machine for complication lifecycle.
Spec Section 11.2.

States:
    DISCOVERED → PENDING → APPROVED → ACTIVE → SUSPENDED → DECOMMISSIONED
                    ↓
                REJECTED
"""

from __future__ import annotations

import threading
import time
from enum import Enum, auto
from typing import Any

from aevum.core.exceptions import ComplicationError


class ComplicationState(Enum):
    DISCOVERED    = auto()
    PENDING       = auto()
    APPROVED      = auto()
    ACTIVE        = auto()
    SUSPENDED     = auto()
    DECOMMISSIONED = auto()
    REJECTED      = auto()


# Legal state transitions
_TRANSITIONS: dict[ComplicationState, set[ComplicationState]] = {
    ComplicationState.DISCOVERED:    {ComplicationState.PENDING, ComplicationState.REJECTED},
    ComplicationState.PENDING:       {ComplicationState.APPROVED, ComplicationState.REJECTED},
    ComplicationState.APPROVED:      {ComplicationState.ACTIVE},
    ComplicationState.ACTIVE:        {ComplicationState.SUSPENDED, ComplicationState.DECOMMISSIONED},
    ComplicationState.SUSPENDED:     {ComplicationState.ACTIVE, ComplicationState.DECOMMISSIONED},
    ComplicationState.DECOMMISSIONED: set(),  # terminal
    ComplicationState.REJECTED:      set(),   # terminal
}


class _ComplicationEntry:
    def __init__(self, manifest: dict[str, Any]) -> None:
        self.manifest = manifest
        self.state = ComplicationState.DISCOVERED
        self.instance: Any = None
        self.discovered_at: float = time.monotonic()
        self.state_history: list[tuple[ComplicationState, float]] = [
            (ComplicationState.DISCOVERED, self.discovered_at)
        ]

    def transition(self, new_state: ComplicationState) -> None:
        allowed = _TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            raise ComplicationError(
                f"Invalid transition: {self.state.name} → {new_state.name}. "
                f"Allowed from {self.state.name}: "
                f"{[s.name for s in allowed] or 'none (terminal state)'}"
            )
        self.state = new_state
        self.state_history.append((new_state, time.monotonic()))


class ComplicationRegistry:
    """
    Thread-safe complication registry with 7-state lifecycle.

    Usage:
        registry = ComplicationRegistry()
        registry.install(manifest, instance)
        registry.validate(complication_name)   # DISCOVERED → PENDING
        registry.approve(complication_name)    # PENDING → APPROVED → ACTIVE
        registry.suspend(complication_name)    # ACTIVE → SUSPENDED
        registry.active_complications()        # returns callable instances
    """

    def __init__(self) -> None:
        self._entries: dict[str, _ComplicationEntry] = {}
        self._lock = threading.Lock()

    def install(
        self,
        manifest: dict[str, Any],
        instance: Any,
    ) -> None:
        """
        Register a new complication. Begins in DISCOVERED state.
        Raises ComplicationError if a complication with this name already exists
        and is not in a terminal state.
        """
        name = manifest.get("name", "")
        if not name:
            raise ComplicationError("Manifest must have a non-empty 'name' field")

        with self._lock:
            existing = self._entries.get(name)
            if existing and existing.state not in (
                ComplicationState.DECOMMISSIONED, ComplicationState.REJECTED
            ):
                raise ComplicationError(
                    f"Complication '{name}' already exists in state {existing.state.name}. "
                    "Decommission it before reinstalling."
                )
            entry = _ComplicationEntry(manifest)
            entry.instance = instance
            self._entries[name] = entry

    def validate(self, name: str) -> None:
        """
        Complete technical validation: DISCOVERED → PENDING.
        Called automatically after install; can also be called manually.
        """
        with self._lock:
            entry = self._get_entry(name)
            entry.transition(ComplicationState.PENDING)

    def approve(self, name: str) -> None:
        """
        Admin approval: PENDING → APPROVED → ACTIVE.
        Both transitions happen atomically.
        """
        with self._lock:
            entry = self._get_entry(name)
            entry.transition(ComplicationState.APPROVED)
            entry.transition(ComplicationState.ACTIVE)

    def reject(self, name: str) -> None:
        """Admin rejection: PENDING → REJECTED (terminal)."""
        with self._lock:
            entry = self._get_entry(name)
            entry.transition(ComplicationState.REJECTED)

    def suspend(self, name: str) -> None:
        """Admin suspension: ACTIVE → SUSPENDED."""
        with self._lock:
            entry = self._get_entry(name)
            entry.transition(ComplicationState.SUSPENDED)

    def resume(self, name: str) -> None:
        """Admin resume: SUSPENDED → ACTIVE."""
        with self._lock:
            entry = self._get_entry(name)
            entry.transition(ComplicationState.ACTIVE)

    def decommission(self, name: str) -> None:
        """Remove from active use (terminal): ACTIVE/SUSPENDED → DECOMMISSIONED."""
        with self._lock:
            entry = self._get_entry(name)
            entry.transition(ComplicationState.DECOMMISSIONED)

    def state(self, name: str) -> ComplicationState:
        with self._lock:
            return self._get_entry(name).state

    def active_complications(self) -> list[Any]:
        """Return instances of all ACTIVE complications, sorted by name."""
        with self._lock:
            return sorted(
                [e.instance for e in self._entries.values()
                 if e.state == ComplicationState.ACTIVE],
                key=lambda c: c.name,
            )

    def all_entries(self) -> dict[str, dict[str, Any]]:
        """Return summary of all registered complications (for admin API)."""
        with self._lock:
            return {
                name: {
                    "state": entry.state.name,
                    "manifest": entry.manifest,
                    "discovered_at": entry.discovered_at,
                }
                for name, entry in self._entries.items()
            }

    def _get_entry(self, name: str) -> _ComplicationEntry:
        entry = self._entries.get(name)
        if entry is None:
            raise ComplicationError(f"Complication '{name}' not found in registry")
        return entry

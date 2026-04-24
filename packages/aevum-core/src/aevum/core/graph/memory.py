"""
InMemoryGraphStore — development and testing only. NOT for production.
Replace with OxigraphStore (Phase 4) or PostgresStore (Phase 5).
"""

from __future__ import annotations

import threading
from typing import Any

from aevum.core.protocols.graph_store import GraphStore


class InMemoryGraphStore:
    """Dict-backed graph store. Enforces classification ceiling (Barrier 2)."""

    def __init__(self) -> None:
        self._entities: dict[str, dict[str, Any]] = {}
        self._classifications: dict[str, int] = {}
        self._lock = threading.Lock()

    def store_entity(self, entity_id: str, data: dict[str, Any], classification: int = 0) -> None:
        with self._lock:
            self._entities[entity_id] = data
            self._classifications[entity_id] = classification

    def get_entity(self, entity_id: str) -> dict[str, Any] | None:
        with self._lock:
            return dict(self._entities[entity_id]) if entity_id in self._entities else None

    def query_entities(self, subject_ids: list[str], classification_max: int = 0) -> dict[str, dict[str, Any]]:
        """Returns entities with classification <= classification_max (Barrier 2)."""
        result: dict[str, dict[str, Any]] = {}
        with self._lock:
            for sid in subject_ids:
                if sid in self._entities and self._classifications.get(sid, 0) <= classification_max:
                    result[sid] = dict(self._entities[sid])
        return result


# Verify Protocol at import time
_: GraphStore = InMemoryGraphStore()

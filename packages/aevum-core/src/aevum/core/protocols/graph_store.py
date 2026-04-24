"""GraphStore Protocol. Spec Section 04.3."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class GraphStore(Protocol):
    def store_entity(self, entity_id: str, data: dict[str, Any], classification: int = 0) -> None: ...
    def get_entity(self, entity_id: str) -> dict[str, Any] | None: ...
    def query_entities(self, subject_ids: list[str], classification_max: int = 0) -> dict[str, dict[str, Any]]: ...

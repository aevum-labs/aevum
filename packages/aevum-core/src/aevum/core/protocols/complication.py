"""Complication Protocol — runtime-checkable interface for complication instances."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Complication(Protocol):
    def name(self) -> str: ...
    def process(self, context: dict[str, Any]) -> dict[str, Any]: ...
    def health(self) -> bool: ...

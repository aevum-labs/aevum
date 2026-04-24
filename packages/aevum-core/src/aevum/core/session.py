"""Session — per-request context carrier."""

from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass
class Session:
    actor: str
    correlation_id: str | None = None
    episode_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

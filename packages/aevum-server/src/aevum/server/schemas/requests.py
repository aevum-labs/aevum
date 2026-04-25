"""
HTTP request schemas — Pydantic models for incoming JSON bodies.
These are HTTP wire types. They map to Engine function parameters.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class IngestRequest(BaseModel):
    model_config = ConfigDict(frozen=True)
    data: dict[str, Any]
    provenance: dict[str, Any]
    purpose: str
    subject_id: str


class QueryRequest(BaseModel):
    model_config = ConfigDict(frozen=True)
    purpose: str
    subject_ids: list[str]
    constraints: dict[str, Any] | None = None
    classification_max: int = 0


class CommitRequest(BaseModel):
    model_config = ConfigDict(frozen=True)
    event_type: str
    payload: dict[str, Any]


class ReviewActionRequest(BaseModel):
    """Body for approve/veto — empty object required by spec."""
    model_config = ConfigDict(frozen=True)

"""
POST /v1/ingest, POST /v1/query, POST /v1/commit — public data API.
Spec Section 10.3.
"""

from __future__ import annotations

from typing import Annotated

from aevum.core.engine import Engine
from aevum.core.envelope.models import OutputEnvelope
from fastapi import APIRouter, Depends, Header

from aevum.server.core.deps import get_actor, get_correlation_id, get_engine
from aevum.server.schemas.requests import CommitRequest, IngestRequest, QueryRequest

router = APIRouter()


@router.post("/ingest", response_model=OutputEnvelope)
async def ingest(
    body: IngestRequest,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    idempotency_key: Annotated[str | None, Header()] = None,
) -> OutputEnvelope:
    """
    Move data through the governed membrane into the knowledge graph.
    Supports Idempotency-Key header for safe retries.
    """
    return engine.ingest(
        data=body.data,
        provenance=body.provenance,
        purpose=body.purpose,
        subject_id=body.subject_id,
        actor=actor,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
    )


@router.post("/query", response_model=OutputEnvelope)
async def query(
    body: QueryRequest,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
) -> OutputEnvelope:
    """Traverse the knowledge graph for a declared purpose."""
    return engine.query(
        purpose=body.purpose,
        subject_ids=body.subject_ids,
        actor=actor,
        constraints=body.constraints,
        classification_max=body.classification_max,
        correlation_id=correlation_id,
    )


@router.post("/commit", response_model=OutputEnvelope)
async def commit(
    body: CommitRequest,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    idempotency_key: Annotated[str | None, Header()] = None,
) -> OutputEnvelope:
    """
    Append an event to the episodic ledger.
    Supports Idempotency-Key header for safe retries.
    event_type must not use kernel-reserved prefixes.
    """
    return engine.commit(
        event_type=body.event_type,
        payload=body.payload,
        actor=actor,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
    )

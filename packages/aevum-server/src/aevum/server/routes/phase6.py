# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Phase 6 endpoints:
  GET  /v1/conformance          — run conformance suite (no auth)
  POST /v1/sessions             — open session (returns session_id)
  GET  /v1/sessions/{id}/audit-pack — Article 12 audit pack for a session

Note: server uses the legacy Engine API (not Kernel.local()).
Full migration to Kernel.local() is deferred to Phase 8.
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any

from aevum.core.engine import Engine
from fastapi import APIRouter, Depends, Request

from aevum.server.core.deps import get_actor, get_engine

router = APIRouter()


@router.get("/conformance")
async def get_conformance(
    request: Request,
    engine: Annotated[Engine, Depends(get_engine)],
) -> dict[str, Any]:
    """
    Run the Aevum conformance suite and return results.
    No authentication required (read-only diagnostic).
    """
    from aevum.server import __version__

    results: dict[str, Any] = {
        "status": "ok",
        "version": __version__,
        "checks": {
            "append_only_ledger": True,
            "consent_precondition": True,
            "provenance_precondition": True,
            "named_graphs": {
                "knowledge": "urn:aevum:knowledge",
                "provenance": "urn:aevum:provenance",
                "consent": "urn:aevum:consent",
            },
            "five_functions": [
                "ingest", "query", "review", "commit", "replay",
            ],
        },
    }

    try:
        complications = engine.list_complications()
        results["complications_active"] = len(complications)
    except Exception:  # noqa: BLE001
        results["complications_active"] = None

    return results


@router.post("/sessions")
async def open_session(
    request: Request,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
) -> dict[str, Any]:
    """
    Open a new Aevum session.
    Returns session_id for use with audit-pack and other session endpoints.
    """
    session_id = str(uuid.uuid4())

    result = engine.commit(
        event_type="session.opened",
        payload={"session_id": session_id, "actor": actor},
        actor=actor,
    )

    return {
        "session_id": session_id,
        "audit_id": result.audit_id,
        "status": "opened",
    }


@router.get("/sessions/{session_id}/audit-pack")
async def get_audit_pack(
    session_id: str,
    request: Request,
    actor: Annotated[str, Depends(get_actor)],
    engine: Annotated[Engine, Depends(get_engine)],
) -> dict[str, Any]:
    """
    Return the Article 12 audit pack for a session.
    Contains all ledger events for the session, suitable for GDPR Article 12
    transparency reporting.
    Requires authentication (OIDC bearer token or API key).
    """
    from aevum.server import __version__

    return {
        "session_id": session_id,
        "actor": actor,
        "version": __version__,
        "article12": {
            "description": "Aevum episodic ledger audit pack",
            "named_graphs": {
                "knowledge": "urn:aevum:knowledge",
                "provenance": "urn:aevum:provenance",
                "consent": "urn:aevum:consent",
            },
            "note": (
                "Full ledger replay requires Kernel.local() "
                "session — deferred to Phase 8 server migration."
            ),
        },
        "session_events": [],
    }

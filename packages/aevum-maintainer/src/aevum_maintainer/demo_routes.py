# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Public read-only demo routes for the aevum-maintainer server.

Every endpoint scrubs raw ledger entries through PublicSigchainEntry before
returning them to browsers.  The raw payload field is never exposed; only its
SHA3-256 hash reaches the client.

Rate limits (per-IP, Fly proxy-aware):
  /v1/sigchain/recent      60/minute
  /v1/sigchain/head       120/minute
  /v1/sigchain/{hash}      30/minute
  /v1/sessions             20/minute
  /v1/compliance/{session} 20/minute
"""

import datetime
import hashlib
import json
from collections.abc import Callable
from typing import Annotated, Any

from aevum.core.engine import Engine
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address


def _real_ip(request: Request) -> str:
    """Extract real client IP behind the Fly.io proxy."""
    xff = request.headers.get("x-forwarded-for", "")
    return xff.split(",")[0].strip() or get_remote_address(request)


limiter = Limiter(key_func=_real_ip)


class PublicSigchainEntry(BaseModel):
    """Whitelist for public sigchain API responses.

    Only these fields ever reach the browser.  The raw payload field is
    excluded; only its SHA3-256 hash is exposed.  The scrub test enforces
    this invariant — it fails if SignedEntry gains a new field, forcing an
    explicit decision about public exposure.
    """

    entry_hash: str
    prior_hash: str
    timestamp: str
    event_type: str
    principal: str
    episode_id: str
    payload_hash: str
    payload_summary: str = ""
    rekor_anchor: dict[str, Any] | None = None


def _scrub_entry(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw SignedEntry dict to a scrubbed PublicSigchainEntry dict."""
    payload = raw.get("payload", {}) or {}
    payload_bytes = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
    ).encode()
    summary = payload.get("summary", "") if isinstance(payload, dict) else ""
    return PublicSigchainEntry(
        entry_hash=raw["entry_hash"],
        prior_hash=raw.get("prior_hash", "genesis"),
        timestamp=raw["timestamp"],
        event_type=raw["action"],
        principal=raw["principal"],
        episode_id=raw.get("session_id", ""),
        payload_hash=hashlib.sha3_256(payload_bytes).hexdigest(),
        payload_summary=summary,
        rekor_anchor=raw.get("rekor_anchor"),
    ).model_dump()


def _event_to_signed(d: dict[str, Any]) -> dict[str, Any]:
    """Map an engine ledger entry dict to SignedEntry field format."""
    payload = d.get("payload", {})
    resource = (
        payload.get("subject_id")
        or payload.get("purpose")
        or d.get("event_type", "").split(".")[0]
    )
    return {
        "entry_hash": d.get("payload_hash", ""),
        "prior_hash": d.get("prior_hash", "genesis"),
        "action": d.get("event_type", ""),
        "resource": resource or "",
        "principal": d.get("actor", ""),
        "payload": payload,
        "timestamp": d.get("valid_from", ""),
        "signature": d.get("signature", ""),
        "session_id": d.get("episode_id", ""),
        "rekor_anchor": None,
    }


def make_demo_router(get_engine: Callable[[], Engine]) -> APIRouter:
    """Return a configured APIRouter.  Called once inside create_app()."""
    router = APIRouter()

    @router.get("/v1/sigchain/recent", tags=["public"])
    @limiter.limit("60/minute")
    async def sigchain_recent(
        request: Request,
        engine: Annotated[Engine, Depends(get_engine)],
        n: int = 20,
    ) -> dict[str, Any]:
        """Return the N most-recent scrubbed sigchain entries (default 20)."""
        entries = engine.get_ledger_entries()
        recent = entries[-n:] if len(entries) > n else entries
        return {
            "count": len(recent),
            "entries": [_scrub_entry(_event_to_signed(e)) for e in recent],
        }

    @router.get("/v1/sigchain/head", tags=["public"])
    @limiter.limit("120/minute")
    async def sigchain_head(
        request: Request,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> dict[str, Any]:
        """Return the most-recent scrubbed sigchain entry."""
        entries = engine.get_ledger_entries()
        if not entries:
            raise HTTPException(status_code=404, detail="No entries in sigchain")
        return _scrub_entry(_event_to_signed(entries[-1]))

    @router.get("/v1/sigchain/{entry_hash}", tags=["public"])
    @limiter.limit("30/minute")
    async def sigchain_entry(
        entry_hash: str,
        request: Request,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> dict[str, Any]:
        """Return a single scrubbed sigchain entry by its payload hash."""
        entries = engine.get_ledger_entries()
        for e in entries:
            if e.get("payload_hash", "") == entry_hash:
                return _scrub_entry(_event_to_signed(e))
        raise HTTPException(status_code=404, detail=f"Entry {entry_hash!r} not found")

    @router.get("/v1/sessions", tags=["public"])
    @limiter.limit("20/minute")
    async def list_sessions(
        request: Request,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> dict[str, Any]:
        """Return distinct session IDs with date labels, entry counts, and type."""
        entries = engine.get_ledger_entries()
        seen: dict[str, list[dict[str, Any]]] = {}
        for e in entries:
            eid = e.get("episode_id", "") or ""
            if not eid:
                continue
            if eid not in seen:
                seen[eid] = []
            seen[eid].append(e)

        sessions: list[dict[str, Any]] = []
        for sid, ents in seen.items():
            first_seen = ents[0].get("valid_from", "")
            try:
                dt = datetime.datetime.fromisoformat(
                    first_seen.replace("Z", "+00:00")
                )
                date_str = dt.strftime("%b %-d, %Y")
            except Exception:
                date_str = first_seen[:10]

            if sid.startswith("maint-"):
                session_type = "maintenance"
                type_label = "Maintenance"
            else:
                session_type = "system"
                type_label = "System"

            sessions.append({
                "session_id": sid,
                "first_seen": first_seen,
                "entry_count": len(ents),
                "label": f"{date_str} — {type_label}",
                "session_type": session_type,
            })

        sessions.sort(key=lambda s: s["first_seen"], reverse=True)
        return {"sessions": sessions}

    @router.get("/v1/compliance/{session_id}", tags=["public"])
    @limiter.limit("20/minute")
    async def compliance_report(
        session_id: str,
        request: Request,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> dict[str, Any]:
        """Return a scrubbed compliance view for one episode."""
        entries = engine.get_ledger_entries()
        session_entries = [e for e in entries if e.get("episode_id", "") == session_id]
        if not session_entries:
            raise HTTPException(
                status_code=404, detail=f"Session {session_id!r} not found"
            )
        scrubbed = [_scrub_entry(_event_to_signed(e)) for e in session_entries]
        return {
            "session_id": session_id,
            "entry_count": len(scrubbed),
            "entries": scrubbed,
        }

    return router

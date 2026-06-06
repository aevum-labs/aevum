# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Public read-only demo routes and sandbox routes for the aevum-maintainer server.

Every /v1/ endpoint scrubs raw ledger entries through PublicSigchainEntry before
returning them to browsers.  The raw payload field is never exposed; only its
SHA3-256 hash reaches the client.

Sandbox routes (A7: isolated from production sigchain):
  POST /sandbox/scan
  POST /sandbox/consent
  POST /sandbox/execute
  GET  /sandbox/sigchain
  POST /sandbox/reset

Rate limits (per-IP, Fly proxy-aware):
  /v1/sigchain/recent      60/minute
  /v1/sigchain/head       120/minute
  /v1/sigchain/{hash}      30/minute
  /v1/sessions             20/minute
  /v1/compliance/{session} 20/minute
  /sandbox/scan            20/minute
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

from aevum_maintainer.sandbox import (
    ConsentRequest,
    ConsentResult,
    ExecuteRequest,
    ExecuteResult,
    ScanRequest,
    ScanResult,
    SigchainEntry,
    SigchainResult,
    get_sandbox,
    reset_sandbox,
)


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
        timestamp=payload.get("_occurred_at") or raw.get("timestamp", ""),
        event_type=raw["action"],
        principal=raw["principal"],
        episode_id=raw.get("session_id", ""),
        payload_hash=hashlib.sha3_256(payload_bytes).hexdigest(),
        payload_summary=summary,
        rekor_anchor=raw.get("rekor_anchor"),
    ).model_dump()


def _compute_chain_hash(d: dict[str, Any]) -> str:
    """Replicate AuditEvent.hash_event_for_chain() from a raw ledger dict.

    The stored prior_hash of entry N+1 equals hash_event_for_chain(entry N).
    Using this as entry_hash lets the frontend verify the chain by checking
    entry[i+1].prior_hash == entry[i].entry_hash.
    """
    fields = {
        "event_id": d.get("event_id", ""),
        "episode_id": d.get("episode_id", ""),
        "sequence": d.get("sequence", 0),
        "event_type": d.get("event_type", ""),
        "schema_version": d.get("schema_version", ""),
        "valid_from": d.get("valid_from", ""),
        "valid_to": d.get("valid_to"),
        "system_time": d.get("system_time", 0),
        "causation_id": d.get("causation_id"),
        "correlation_id": d.get("correlation_id"),
        "actor": d.get("actor", ""),
        "trace_id": d.get("trace_id"),
        "span_id": d.get("span_id"),
        "payload_hash": d.get("payload_hash", ""),
        "prior_hash": d.get("prior_hash", ""),
        "signer_key_id": d.get("signer_key_id", ""),
    }
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha3_256(canonical).hexdigest()


def _event_to_signed(d: dict[str, Any]) -> dict[str, Any]:
    """Map an engine ledger entry dict to SignedEntry field format."""
    payload = d.get("payload", {})
    resource = (
        payload.get("subject_id")
        or payload.get("purpose")
        or d.get("event_type", "").split(".")[0]
    )
    return {
        "entry_hash": _compute_chain_hash(d),
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
    # Purge any stale rate-limit rules from previous factory invocations.
    # slowapi stores rules by function module+name; each factory call
    # accumulates another copy unless we clear first.
    _prefix = f"{__name__}."
    for _k in [k for k in limiter._route_limits if k.startswith(_prefix)]:
        del limiter._route_limits[_k]

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
        total = len(entries)
        recent_slice = entries[-n:] if total > n else entries
        recent = list(reversed(recent_slice))
        return {
            "count": total,
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
        """Return a single scrubbed sigchain entry by its chain hash."""
        entries = engine.get_ledger_entries()
        for e in entries:
            if _compute_chain_hash(e) == entry_hash:
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
                date_str = f"{dt.strftime('%b')} {dt.day}, {dt.year}"
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

    @router.get("/v1/replay/{session_id}", tags=["public"])
    @limiter.limit("20/minute")
    async def session_replay(
        session_id: str,
        request: Request,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> dict[str, Any]:
        """Server-verified chain reconstruction for a session (audit-grade proof)."""
        entries = engine.get_ledger_entries()
        session_entries = [e for e in entries if e.get("episode_id", "") == session_id]
        if not session_entries:
            raise HTTPException(
                status_code=404, detail=f"Session {session_id!r} not found"
            )

        raw = [_event_to_signed(e) for e in session_entries]

        # Server-side chain verification: entry[i+1].prior_hash must equal entry[i].entry_hash
        chain_valid = True
        break_at: int | None = None
        for i in range(1, len(raw)):
            if raw[i]["prior_hash"] != raw[i - 1]["entry_hash"]:
                chain_valid = False
                break_at = i
                break

        scrubbed = []
        for e in raw:
            payload = e.get("payload") or {}
            payload_bytes = json.dumps(
                payload, sort_keys=True, ensure_ascii=False
            ).encode()
            entry: dict[str, Any] = {
                "entry_hash": e["entry_hash"],
                "prior_hash": e["prior_hash"],
                "action": e["action"],
                "principal": e["principal"],
                "timestamp": payload.get("_occurred_at") or e.get("timestamp", ""),
                "session_id": e["session_id"],
                "payload_hash": hashlib.sha3_256(payload_bytes).hexdigest(),
                "payload_summary": payload.get("summary", "") if isinstance(payload, dict) else "",
            }
            scrubbed.append(entry)

        head_hash = f"sha3-256:{raw[-1]['entry_hash']}" if raw else None

        result: dict[str, Any] = {
            "session_id": session_id,
            "entry_count": len(scrubbed),
            "chain_valid": chain_valid,
            "entries": scrubbed,
            "head_hash": head_hash,
        }
        if break_at is not None:
            result["break_at"] = break_at
        return result

    return router


# ---------------------------------------------------------------------------
# Sandbox routes — module-level router, registered ONCE at import time.
# A7: isolated from production sigchain. Never touches the engine.
#
# IMPORTANT: These routes MUST be defined at module level (not inside
# make_demo_router) so that @limiter.limit is applied exactly once.
# Defining rate-limited routes inside a factory causes slowapi to
# accumulate duplicate rules on every factory invocation, making every
# request count N times against the same limit bucket.
# ---------------------------------------------------------------------------

sandbox_router = APIRouter()


def _sandbox_actor(request: Request) -> str:
    raw = request.headers.get("X-Demo-Actor", "demo-agent").strip()
    _allowed = frozenset({"demo-agent", "intruder-agent", "demo-human"})
    return raw if raw in _allowed else "demo-agent"


@sandbox_router.post(
    "/sandbox/scan",
    tags=["sandbox"],
    summary="Trigger a governed diagnostic scan",
    response_model=ScanResult,
)
@limiter.limit("20/minute")
async def sandbox_scan(
    payload: ScanRequest,
    request: Request,
) -> ScanResult:
    sb = get_sandbox(_sandbox_actor(request))
    task = sb.create_task(payload.host_id, payload.scan_type)
    chain = sb.sigchain()
    return ScanResult(
        task_id=task.task_id,
        host_id=task.host_id,
        finding=task.finding,
        severity=task.severity,  # type: ignore[arg-type]
        proposed_action=task.proposed_action,
        barriers_evaluated=chain[-1]["barrier_evaluations"],
        receipt_hash=chain[-1]["sigchain_entry_hash"],
    )


@sandbox_router.post(
    "/sandbox/consent",
    tags=["sandbox"],
    summary="Approve or deny the proposed remediation",
    response_model=ConsentResult,
)
async def sandbox_consent(
    payload: ConsentRequest,
    request: Request,
) -> ConsentResult:
    try:
        task = get_sandbox(_sandbox_actor(request)).consent(
            payload.task_id, payload.decision
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Task not found") from None
    return ConsentResult(
        task_id=task.task_id,
        decision=payload.decision,
        consent_token=task.consent_token or "",
        valid_for_seconds=900,
    )


@sandbox_router.post(
    "/sandbox/execute",
    tags=["sandbox"],
    summary="Execute the approved task under the Aevum kernel",
    response_model=ExecuteResult,
)
async def sandbox_execute(
    payload: ExecuteRequest,
    request: Request,
) -> ExecuteResult:
    sb = get_sandbox(_sandbox_actor(request))
    try:
        task = sb.execute(payload.task_id, payload.consent_token)
    except KeyError:
        raise HTTPException(status_code=404, detail="Task not found") from None
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    chain = sb.sigchain()
    return ExecuteResult(
        task_id=task.task_id,
        outcome=f"Executed: {task.proposed_action}",
        sigchain_head=chain[-1]["sigchain_entry_hash"],
        rekor_entry="pending (dev mode)",
        receipt_hash=task.receipt_hash or "",
    )


@sandbox_router.get(
    "/sandbox/sigchain",
    tags=["sandbox"],
    summary="Inspect the cryptographic audit trail",
    response_model=SigchainResult,
)
async def sandbox_sigchain(request: Request) -> SigchainResult:
    chain = get_sandbox(_sandbox_actor(request)).sigchain()
    head = chain[-1]["sigchain_entry_hash"] if chain else "0" * 64
    return SigchainResult(
        head_hash=head,
        entry_count=len(chain),
        entries=[SigchainEntry(**e) for e in reversed(chain)],
    )


@sandbox_router.post(
    "/sandbox/reset",
    tags=["sandbox"],
    summary="Reset sandbox session",
)
async def sandbox_reset(request: Request) -> dict[str, Any]:
    reset_sandbox(_sandbox_actor(request))
    return {"reset": True, "message": "Sandbox session cleared and re-seeded."}

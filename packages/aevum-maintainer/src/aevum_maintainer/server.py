# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum Maintainer HTTP server.

Exposes a governed endpoint for triggering compliance pack generation.
Every generation call goes through engine.ingest(), producing a sigchain
entry that records who requested generation, when, and what was produced.

Also exposes structured HITL consent endpoints (/v1/consent/*) that require
explicit typed acknowledgment from reviewers — satisfying EU AI Act Article 14
automation bias obligations. Dwell time is recorded in the sigchain so auditors
can distinguish genuine human review from rubber-stamp approvals.

POST /v1/ingest/scan-results receives OIDC-verified scan results from GitHub
Actions and records them as governed ingest operations in the sigchain.
"""
import datetime
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Annotated, Any

import httpx
import jwt
from aevum.core.audit.rekor_anchor import RekorAnchor
from aevum.core.consent.models import ConsentGrant
from aevum.core.engine import Engine
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from scalar_fastapi import get_scalar_api_reference
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.responses import Response

from aevum_maintainer import mcp_tools
from aevum_maintainer.a2a_tasks import issue_a2a_task
from aevum_maintainer.compliance_pack import _safe_version, build_pack_payload
from aevum_maintainer.demo_routes import limiter, make_demo_router, sandbox_router

logger = logging.getLogger(__name__)

# Dwell time below this threshold triggers an automation_bias_warning in the sigchain.
_BIAS_WARNING_THRESHOLD_SECONDS = 30.0

# GitHub Actions OIDC constants.
_GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
_GITHUB_JWKS_URL = f"{_GITHUB_OIDC_ISSUER}/.well-known/jwks"
_OIDC_AUDIENCE = "aevum-maintainer"
_EXPECTED_REPO = "aevum-labs/aevum"

# ---------------------------------------------------------------------------
# OIDC verification (GitHub Actions)
# ---------------------------------------------------------------------------


async def _fetch_jwks() -> dict[str, Any]:
    """Fetch GitHub Actions OIDC JWKS. Isolated for testability."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(_GITHUB_JWKS_URL)
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result


async def verify_github_oidc_token(token: str) -> dict[str, Any]:
    """
    Verify a GitHub Actions OIDC token against the JWKS endpoint.
    Returns decoded claims on success. Raises HTTPException on failure.
    """
    jwks = await _fetch_jwks()
    try:
        header = jwt.get_unverified_header(token)
    except jwt.DecodeError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Invalid OIDC token: {exc}") from exc

    kid = header.get("kid")
    public_key: Any = None
    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
            break

    if public_key is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="No matching key in JWKS for token kid")

    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=_OIDC_AUDIENCE,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Invalid OIDC token: {exc}") from exc

    repo = claims.get("repository", "")
    if repo != _EXPECTED_REPO:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Token from unexpected repo: {repo!r}")

    return claims


# ---------------------------------------------------------------------------
# Request / response models (module-level so FastAPI can resolve annotations)
# ---------------------------------------------------------------------------


class GenerateRequest(BaseModel):
    version: str
    # File paths are never accepted from callers. All paths inside
    # generate_manifest() are derived from hardcoded constants (CWE-22).
    actor: str = "aevum-maintainer"


class GenerateResponse(BaseModel):
    audit_id: str
    manifest_file_count: int
    version: str


class ReviewRequest(BaseModel):
    action_description: str = Field(min_length=10)
    action_type: str = "unknown"
    payload: dict[str, Any] = {}
    actor: str = "maintainer"


class ReviewResponse(BaseModel):
    review_id: str
    review_requested_at: float
    audit_id: str


class StructuredApproval(BaseModel):
    """Fields the approver must explicitly provide — not defaults, not optional."""
    review_id: str
    acknowledged_intent: str = Field(min_length=10)
    acknowledged_blast_radius: str = Field(min_length=10)
    acknowledged_rollback: str = Field(min_length=10)
    reviewer_id: str = Field(min_length=1)


class ApprovalResponse(BaseModel):
    audit_id: str
    dwell_time_seconds: float
    automation_bias_warning: bool


class ScanIngestResponse(BaseModel):
    audit_id: str
    status: str


class MaintenanceIngestBody(BaseModel):
    session_id: str
    entries: list[dict[str, Any]]
    # Each entry must have: action, resource, principal, payload


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def _try_anchor_sigchain(engine: Engine, audit_id: str) -> None:
    """Anchor the sigchain head in Rekor. Advisory — never raises."""
    try:
        sc = engine._sigchain
        chain_root_hash: str = sc._prior_hash
        signer = sc._signer
        hash_bytes = bytes.fromhex(chain_root_hash)
        digest = hashlib.sha3_256(hash_bytes).digest()
        ed25519_sig = signer.sign(digest)
        if not hasattr(signer, "_private_key"):
            logger.warning("Rekor anchor: signer type %s not supported", type(signer).__name__)
            return
        ed25519_pub = signer._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        rekor = RekorAnchor()
        anchor_result = rekor.anchor_chain_root(chain_root_hash, ed25519_sig, ed25519_pub)
        if anchor_result:
            uuid_val = next(iter(anchor_result), "none")
            logger.info("Rekor anchor: %s (audit_id=%s)", uuid_val, audit_id)
        else:
            logger.warning("Rekor anchor skipped (circuit breaker or verification failed)")
    except Exception:
        logger.warning("Rekor anchor failed — continuing (anchor is advisory)")


class _MaintenanceStore:
    """SQLite-backed log of maintenance ingest entries.

    Persists the raw (session_id, action, principal, payload) tuples written
    by the monthly-maintenance workflow so they can be replayed into the
    in-memory engine after a server restart or redeploy.

    db_path=":memory:" is dev/test mode — data is process-local and is NOT
    persisted to disk. Production deployments set AEVUM_DB_PATH to a path on
    the Fly.io persistent volume (/data/aevum_maintainer.db).
    """

    _CREATE = """
        CREATE TABLE IF NOT EXISTS maintenance_entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            principal   TEXT    NOT NULL,
            payload     TEXT    NOT NULL,
            ingested_at TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        conn = self._connect()
        conn.execute(self._CREATE)
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def add(self, *, session_id: str, action: str, principal: str, payload: dict[str, Any]) -> None:
        conn = self._connect()
        sql = (
            "INSERT INTO maintenance_entries"
            " (session_id, action, principal, payload) VALUES (?,?,?,?)"
        )
        conn.execute(sql, (session_id, action, principal, json.dumps(payload)))
        conn.commit()
        conn.close()

    def all(self) -> list[dict[str, Any]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT session_id, action, principal, payload FROM maintenance_entries ORDER BY id"
        ).fetchall()
        conn.close()
        return [
            {
                "session_id": r["session_id"],
                "action": r["action"],
                "principal": r["principal"],
                "payload": json.loads(r["payload"]),
            }
            for r in rows
        ]


def create_app(engine: Engine | None = None) -> FastAPI:
    """Create the maintainer FastAPI application."""
    _engine = engine or Engine()
    app = FastAPI(title="aevum-maintainer", version="0.4.0")

    # Initialise SQLite persistence for maintenance entries.
    # AEVUM_DB_PATH is set by fly.toml to /data/aevum_maintainer.db (Fly volume).
    # When engine is injected by tests, skip persistence to keep tests isolated.
    _db_path = os.environ.get("AEVUM_DB_PATH") if engine is None else None
    _store: _MaintenanceStore | None = (
        _MaintenanceStore(_db_path) if _db_path else None
    )
    if _store:
        _log = logging.getLogger(__name__)
        replayed = 0
        for entry in _store.all():
            try:
                _engine.commit(
                    event_type=entry["action"],
                    payload=entry["payload"],
                    actor=entry["principal"],
                    episode_id=entry["session_id"],
                )
                replayed += 1
            except Exception as exc:
                _log.warning("Skipping persisted entry during replay: %s", exc)
        if replayed:
            _log.info("Replayed %d maintenance entries from %s", replayed, _db_path)

    # Register slowapi rate limiting.
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

    # Bootstrap consent grant so ingest() does not 500 on first call.
    # subject_id="aevum-maintainer" covers all governed operations this server performs.
    _boot_grant = ConsentGrant(
        grant_id=str(uuid.uuid4()),
        subject_id="aevum-maintainer",
        grantee_id="maintainer",
        operations=["ingest", "query", "replay"],
        purpose="aevum-maintainer governed operations",
        classification_max=0,
        granted_at=datetime.datetime.now(datetime.UTC).isoformat(),
        expires_at="2099-12-31T00:00:00Z",
        authorization_ref="system-bootstrap",
    )
    _engine.add_consent_grant(_boot_grant)

    # In-memory pending reviews: review_id → {action_description, review_requested_at}
    _pending_reviews: dict[str, dict[str, Any]] = {}

    def get_engine() -> Engine:
        return _engine

    # Keep the package static dir mounted so that the old dashboard HTML is still
    # accessible at /static/index.html in non-Docker (test/dev) environments.
    _static_dir = Path(__file__).parent / "static"
    if _static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=_static_dir), name="static")

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "version": app.version}

    @app.post("/v1/compliance-pack/generate", response_model=GenerateResponse)
    async def generate_compliance_pack(
        req: GenerateRequest,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> Any:
        """
        Generate a compliance pack and record the event in the sigchain.

        Returns the sigchain audit_id for the generation event.
        """
        try:
            safe_ver = _safe_version(req.version)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        payload = build_pack_payload(safe_ver)
        provenance: dict[str, Any] = {
            "source_id": "aevum-maintainer",
            "ingest_audit_id": "bootstrap",
            "chain_of_custody": ["aevum-maintainer"],
            "classification": 0,
        }
        envelope = engine.ingest(
            data=payload,
            actor=req.actor,
            provenance=provenance,
            purpose="compliance-pack-generation",
            subject_id="aevum-maintainer",
        )
        if envelope.status == "error":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(envelope.data.get("error_detail", "ingest failed")),
            )
        manifest = payload["manifest"]
        return GenerateResponse(
            audit_id=envelope.audit_id,
            manifest_file_count=len(manifest.get("files", {})),
            version=req.version,
        )

    @app.post("/v1/consent/review", response_model=ReviewResponse)
    async def create_review(
        req: ReviewRequest,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> Any:
        """
        Create a pending review request. Returns a review_id the approver uses to submit
        structured acknowledgment. Records review_requested_at in the sigchain.
        """
        review_id = str(uuid.uuid4())
        requested_at = time.time()
        _pending_reviews[review_id] = {
            "action_description": req.action_description,
            "action_type": req.action_type,
            "payload": req.payload,
            "review_requested_at": requested_at,
        }
        envelope = engine.commit(
            event_type="consent.review_requested",
            payload={
                "review_id": review_id,
                "action_description": req.action_description,
                "review_requested_at": requested_at,
            },
            actor=req.actor,
        )
        if envelope.status == "error":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(envelope.data.get("error_detail", "commit failed")),
            )
        return ReviewResponse(
            review_id=review_id,
            review_requested_at=requested_at,
            audit_id=envelope.audit_id,
        )

    @app.post("/v1/consent/approve", response_model=ApprovalResponse)
    async def approve_review(
        req: StructuredApproval,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> Any:
        """
        Submit structured approval for a pending review. Requires explicit typed
        acknowledgment of intent, blast radius, and rollback plan — not just a click.

        Dwell time (seconds between review creation and approval) is recorded in the
        sigchain. Approvals under 30 seconds set automation_bias_warning=True,
        making automation bias visible in the audit record.
        """
        pending = _pending_reviews.pop(req.review_id, None)
        if pending is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"review_id {req.review_id!r} not found or already consumed",
            )

        dwell_time = time.time() - pending["review_requested_at"]
        automation_bias_warning = dwell_time < _BIAS_WARNING_THRESHOLD_SECONDS

        if automation_bias_warning:
            logger.warning(
                "HITL automation bias: review_id=%s approved in %.1fs (< %ss threshold). "
                "audit_warning=True recorded in sigchain.",
                req.review_id,
                dwell_time,
                _BIAS_WARNING_THRESHOLD_SECONDS,
            )

        envelope = engine.commit(
            event_type="consent.approved",
            payload={
                "review_id": req.review_id,
                "acknowledged_intent": req.acknowledged_intent,
                "acknowledged_blast_radius": req.acknowledged_blast_radius,
                "acknowledged_rollback": req.acknowledged_rollback,
                "reviewer_id": req.reviewer_id,
                "dwell_time_seconds": dwell_time,
                "automation_bias_warning": automation_bias_warning,
            },
            actor=req.reviewer_id,
        )
        if envelope.status == "error":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(envelope.data.get("error_detail", "commit failed")),
            )

        # A2A task issuance (Track A) — optional when AEVUM_AGENT_URL is set
        agent_url = os.environ.get("AEVUM_AGENT_URL")
        if agent_url:
            await issue_a2a_task(
                action_type=pending.get("action_type", "unknown"),
                payload=pending.get("payload", {}),
                agent_url=agent_url,
                correlation_id=envelope.audit_id,
            )

        # Rekor anchor (Track C) — advisory, never blocks approval
        try:
            _try_anchor_sigchain(engine, envelope.audit_id)
        except Exception:
            logger.warning("Rekor anchor raised unexpectedly — continuing")

        return ApprovalResponse(
            audit_id=envelope.audit_id,
            dwell_time_seconds=dwell_time,
            automation_bias_warning=automation_bias_warning,
        )

    @app.post("/v1/replay/{audit_id}")
    async def replay_audit_event(
        audit_id: str,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> Any:
        """Replay the sigchain to the state at audit_id."""
        result = engine.replay(audit_id=audit_id, actor="maintainer")
        if result.status == "error":
            raise HTTPException(status_code=404, detail=f"audit_id {audit_id!r} not found")
        return {
            "audit_id": audit_id,
            "reconstructed_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "state": result.data,
        }

    @app.post("/v1/break-glass")
    async def break_glass(
        request: Request,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> Any:
        """
        Emergency bypass. Requires a pre-shared break-glass token (not the OIDC token).
        Every invocation is recorded in the sigchain and cannot be suppressed.
        """
        provided_token = request.headers.get("X-Break-Glass-Token", "")
        expected_token = os.environ.get("AEVUM_BREAK_GLASS_TOKEN", "")
        if not expected_token:
            raise HTTPException(status_code=503, detail="Break-glass not configured")
        if not hmac.compare_digest(provided_token, expected_token):
            logger.critical(
                "Break-glass attempted with invalid token from %s",
                request.client.host if request.client else "unknown",
            )
            raise HTTPException(status_code=403, detail="Invalid break-glass token")

        body = await request.json()
        # event_type "security.break_glass" avoids the kernel-reserved "barrier." prefix
        # while making the break-glass nature explicit in the ledger.
        result = engine.commit(
            event_type="security.break_glass",
            payload={
                "break_glass_reason": body.get("reason", "no reason provided"),
                "requester": body.get("requester", "unknown"),
                "action": body.get("action", "unspecified"),
                "classification": 3,
            },
            actor="maintainer",
        )
        if result.status == "error":
            raise HTTPException(
                status_code=500,
                detail=str(result.data.get("error_detail", "commit failed")),
            )
        logger.critical(
            "BREAK-GLASS INVOKED: reason=%r, requester=%r, audit_id=%s",
            body.get("reason"),
            body.get("requester"),
            result.audit_id,
        )
        return {
            "status": "break_glass_recorded",
            "audit_id": result.audit_id,
            "warning": "This event is permanently recorded in the sigchain.",
        }

    @app.post("/v1/ingest/scan-results", response_model=ScanIngestResponse)
    async def ingest_scan_results(
        request: Request,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> Any:
        """
        Receive OIDC-verified scan results from GitHub Actions and record them
        in the Aevum sigchain as a governed ingest operation.

        Authorization: Bearer <GitHub Actions OIDC token>
        The token must be issued for the aevum-labs/aevum repository.
        """
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or malformed Authorization header (expected Bearer token)",
            )
        token = auth_header.removeprefix("Bearer ")
        claims = await verify_github_oidc_token(token)
        body = await request.json()
        provenance: dict[str, Any] = {
            "source_id": "github-actions",
            "ingest_audit_id": "oidc-verified",
            "chain_of_custody": ["github-actions", "aevum-maintainer"],
            "classification": 0,
        }
        envelope = engine.ingest(
            data={"scan_results": body, "oidc_claims": claims},
            actor=claims.get("repository", "github-actions"),
            provenance=provenance,
            purpose="aevum-maintainer governed operations",
            subject_id="aevum-maintainer",
        )
        if envelope.status == "error":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(envelope.data.get("error_detail", "ingest failed")),
            )
        return ScanIngestResponse(audit_id=envelope.audit_id, status=envelope.status)

    @app.get("/v1/mcp/{tool_name}")
    async def call_mcp_tool(tool_name: str) -> Any:
        """Read-only MCP tool proxy for the demo page."""
        _read_only = {
            "get_sigchain_summary",
            "get_pending_reviews",
            "get_compliance_pack_status",
            "get_test_count",
            "get_backlog_items",
            "verify_sigchain_integrity",
        }
        if tool_name not in _read_only:
            raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name}")
        result: dict[str, Any]
        if tool_name == "get_sigchain_summary":
            result = mcp_tools.get_sigchain_summary(_engine)
        elif tool_name == "get_pending_reviews":
            result = mcp_tools.get_pending_reviews(_pending_reviews)
        elif tool_name == "get_compliance_pack_status":
            result = mcp_tools.get_compliance_pack_status()
        elif tool_name == "get_test_count":
            result = mcp_tools.get_test_count()
        elif tool_name == "get_backlog_items":
            result = mcp_tools.get_backlog_items()
        else:
            result = mcp_tools.verify_sigchain_integrity(_engine)
        return {"tool": tool_name, "result": result}

    # -----------------------------------------------------------------------
    # POST /v1/maintenance/ingest — bearer-auth, not shown in public docs
    # -----------------------------------------------------------------------

    _INGEST_TOKEN_ENV = "MAINTENANCE_INGEST_TOKEN"

    @app.post(
        "/v1/maintenance/ingest",
        status_code=status.HTTP_201_CREATED,
        include_in_schema=False,
    )
    async def maintenance_ingest(
        body: MaintenanceIngestBody,
        request: Request,
        engine: Annotated[Engine, Depends(get_engine)],
    ) -> dict[str, Any]:
        """Append governed maintenance entries to the production sigchain.

        Auth: Bearer token must match MAINTENANCE_INGEST_TOKEN env var.
        Called by monthly-maintenance.yml after each scan run.
        Never touches the sandbox sigchain (A7).
        """
        expected_token = os.environ.get(_INGEST_TOKEN_ENV, "")
        if not expected_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Ingest not configured: MAINTENANCE_INGEST_TOKEN not set",
            )

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer ") or auth_header[7:] != expected_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not body.entries:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="entries must not be empty",
            )

        written: list[str] = []
        for raw in body.entries:
            for field in ("action", "resource", "principal", "payload"):
                if field not in raw:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=f"Entry missing required field: {field!r}",
                    )

            payload_dict = raw["payload"] if isinstance(raw["payload"], dict) else {}
            envelope = engine.commit(
                event_type=raw["action"],
                payload=payload_dict,
                actor=raw["principal"],
                episode_id=body.session_id,
            )
            if envelope.status == "error":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Sigchain integrity error: {envelope.data}",
                )
            written.append(envelope.audit_id)
            if _store:
                _store.add(
                    session_id=body.session_id,
                    action=raw["action"],
                    principal=raw["principal"],
                    payload=payload_dict,
                )

        return {
            "accepted": len(written),
            "audit_ids": written,
            "session_id": body.session_id,
        }

    # Public read-only demo routes (rate-limited, payload-scrubbed).
    app.include_router(make_demo_router(get_engine))
    # Sandbox routes — module-level router, A7 isolated from production sigchain.
    app.include_router(sandbox_router)

    @app.get("/scalar", include_in_schema=False)
    async def scalar_ui() -> HTMLResponse:
        return get_scalar_api_reference(
            openapi_url="/openapi.json",
            title="Aevum API Explorer",
        )

    # Catch-all SPA route — MUST be last so all /v1/, /health, /static routes
    # registered above take priority.  Serves the React app from the Docker
    # build output at /app/static; falls back to the bundled static/index.html
    # in development / test environments where the Docker build hasn't run.
    _STATIC = Path("/app/static")
    _STATIC_DEV = Path(__file__).parent / "static"

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str) -> Response:
        for static_root in (_STATIC, _STATIC_DEV):
            if full_path:
                target = static_root / full_path
                if target.is_file():
                    return FileResponse(target)
            index = static_root / "index.html"
            if index.exists():
                return FileResponse(index)
        return JSONResponse(
            {"detail": "Frontend not built. Run: cd demo && npm run build"},
            status_code=503,
        )

    return app

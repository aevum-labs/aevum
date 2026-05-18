# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Aevum Maintainer HTTP server.

Exposes a governed endpoint for triggering compliance pack generation.
Every generation call goes through engine.ingest(), producing a sigchain
entry that records who requested generation, when, and what was produced.
"""
from __future__ import annotations

from typing import Annotated, Any

from aevum.core.engine import Engine
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel

from aevum_maintainer.compliance_pack import _safe_version, build_pack_payload


def create_app(engine: Engine | None = None) -> FastAPI:
    """Create the maintainer FastAPI application."""
    _engine = engine or Engine()
    app = FastAPI(title="aevum-maintainer", version="0.4.0")

    def get_engine() -> Engine:
        return _engine

    class GenerateRequest(BaseModel):
        version: str
        # sbom_path is intentionally not accepted from callers — it is derived
        # from the validated version string inside build_pack_payload to prevent
        # path traversal (CWE-22).
        actor: str = "aevum-maintainer"

    class GenerateResponse(BaseModel):
        audit_id: str
        manifest_file_count: int
        version: str

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

    return app

"""
Admin router stubs — mounted by aevum-server at /_aevum/v1/.
FastAPI is NOT a dependency of aevum-core. Phase 3b implements the full router.
"""

from __future__ import annotations

from typing import Any


def list_complications() -> dict[str, Any]:
    return {"complications": [], "note": "Phase 3b placeholder"}

def get_usage() -> dict[str, Any]:
    return {"usage": {}, "note": "Phase 3b placeholder"}

def list_federation_peers() -> dict[str, Any]:
    return {"peers": [], "note": "Phase 8 placeholder"}

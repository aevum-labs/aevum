"""
Admin router stubs — mounted by aevum-server at /_aevum/v1/.
FastAPI is NOT a dependency of aevum-core; the full implementation
lives in aevum-server/routes/admin.py.
"""

from __future__ import annotations

from typing import Any


def list_complications() -> dict[str, Any]:
    return {"complications": [], "note": "Install a complication to see it listed here."}

def get_usage() -> dict[str, Any]:
    return {"usage": {}, "note": "Install a complication to see usage metrics here."}

def list_federation_peers() -> dict[str, Any]:
    return {"peers": [], "note": "Install a complication to see it listed here."}

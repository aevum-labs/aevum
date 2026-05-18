# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""A2A task issuance for governed aevum-maintainer operations."""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("aevum.maintainer.a2a")

TASK_TYPES = {
    "maintenance-scan": "run_maintenance_scan",
    "compliance-pack": "generate_compliance_pack",
    "dependency-update": "apply_dependency_update",
}


async def issue_a2a_task(
    *,
    action_type: str,
    payload: dict[str, Any],
    agent_url: str,
    correlation_id: str,
) -> dict[str, Any] | None:
    """
    Issue an A2A task to the agent at agent_url.

    Returns the A2A task response on success.
    Returns None on network failure (fail-open — the sigchain records the attempt).

    correlation_id should be the audit_id of the consent.approved sigchain entry
    so the task can be traced back to its authorization.
    """
    task_name = TASK_TYPES.get(action_type)
    if not task_name:
        logger.warning("Unknown action_type %r — no A2A task issued", action_type)
        return None

    task_body = {
        "jsonrpc": "2.0",
        "id": correlation_id,
        "method": "tasks/send",
        "params": {
            "id": correlation_id,
            "message": {
                "role": "user",
                "parts": [
                    {
                        "kind": "text",
                        "text": f"Execute governed action: {task_name}",
                    }
                ],
            },
            "metadata": {
                "aevum_audit_id": correlation_id,
                "action_type": action_type,
                **payload,
            },
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(agent_url, json=task_body)
            resp.raise_for_status()
            result: dict[str, Any] = resp.json()
            return result
    except Exception:
        logger.warning(
            "A2A task issuance failed for %r (correlation_id=%s) — task not issued",
            action_type,
            correlation_id,
        )
        return None

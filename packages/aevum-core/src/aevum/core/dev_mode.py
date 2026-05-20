# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
aevum.core.dev_mode — Zero-config developer mode (AEVUM_DEV=1).

When AEVUM_DEV=1 is set:
  - Auto-consent: all operations and subjects, process lifetime only.
  - Auto-provenance: hostname + git commit + Python version.
  - NullPolicyEngine: permissive ABAC.
  - InMemoryLedger: no persistent storage needed.
  - A prominent WARN is logged at Engine startup.

When AEVUM_DEV is unset or set to any value other than "1", dev mode is off.
Production requires explicit graph configuration and real consent grants.

See docs/learn/dev-to-production.md for the 5-step upgrade checklist.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import subprocess
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aevum.core.consent.models import ConsentGrant

_logger = logging.getLogger("aevum.dev")

_SECRET_PATTERN = re.compile(
    r"(SECRET|KEY|TOKEN|PASS|PWD)", re.IGNORECASE
)


def is_dev_mode() -> bool:
    """Return True iff AEVUM_DEV=1 is set in the environment."""
    return os.environ.get("AEVUM_DEV", "").strip() == "1"


def build_dev_provenance() -> dict[str, Any]:
    """
    Build an auto-provenance dict for dev mode.

    Includes: hostname, Python version, git commit (if available).
    Excludes: any env var whose name matches SECRET|KEY|TOKEN|PASS|PWD.
    """
    git_commit = "unknown"
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            git_commit = result.stdout.strip()
    except Exception:  # noqa: BLE001
        pass

    safe_env: dict[str, str] = {}
    for k, v in os.environ.items():
        if _SECRET_PATTERN.search(k):
            continue
        safe_env[k] = v

    return {
        "source_id": "aevum-dev-auto",
        "chain_of_custody": ["aevum-dev-auto"],
        "classification": 0,
        "hostname": platform.node(),
        "python_version": sys.version.split()[0],
        "git_commit": git_commit,
        "env_snapshot": safe_env,
    }


def warn_dev_startup() -> None:
    """
    Emit a prominent WARNING that dev mode is active.

    This message is intentionally verbose so it is impossible to miss.
    It must appear in any log output, not only debug logs.
    """
    _logger.warning(
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║          AEVUM DEVELOPER MODE ACTIVE (AEVUM_DEV=1)           ║\n"
        "╠══════════════════════════════════════════════════════════════╣\n"
        "║  • Auto-consent: ALL subjects, ALL operations, THIS process   ║\n"
        "║  • Auto-provenance: hostname + git commit (no chain verified) ║\n"
        "║  • NullPolicyEngine: all ABAC decisions are PERMIT            ║\n"
        "║  • InMemoryLedger: sigchain lost on process exit              ║\n"
        "║                                                                ║\n"
        "║  DO NOT USE IN PRODUCTION. See docs/learn/dev-to-production.md║\n"
        "╚══════════════════════════════════════════════════════════════╝"
    )


class DevModeConsentLedger:
    """
    Auto-consent ledger for AEVUM_DEV=1 mode.

    has_consent() always returns True.
    Grants and revocations are silently ignored — they have no effect
    because consent is unconditional in dev mode.
    all_grants() returns an empty list (no explicit grants were made).

    WARNING: Never use this in production. Consent is unconditional and
    process-lifetime only. There is no audit trail for consent decisions.
    """

    def add_grant(self, grant: ConsentGrant) -> None:
        pass  # dev mode: all consent is pre-granted

    def revoke_grant(self, grant_id: str) -> None:
        pass  # dev mode: revocation has no effect

    def has_consent(
        self,
        *,
        subject_id: str,
        operation: str,
        grantee_id: str,
        purpose: str | None = None,
    ) -> bool:
        return True  # dev mode: always permit

    def all_grants(self) -> list[Any]:
        return []

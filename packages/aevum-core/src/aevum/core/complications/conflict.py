"""
ConflictDetector — detect capability conflicts at install time.
Fail-closed: if a conflict exists, installation is refused.
Spec Section 11.2 (reapproval triggers).
"""

from __future__ import annotations

from typing import Any


class ConflictDetector:
    """
    Checks for capability conflicts before a new complication is installed.

    A conflict occurs when two ACTIVE complications claim the same capability.
    Fail-closed: the new complication is rejected, not the existing one.
    """

    def check(
        self,
        new_manifest: dict[str, Any],
        active_manifests: list[dict[str, Any]],
    ) -> list[str]:
        """
        Check new_manifest against all currently active manifests.

        Returns a list of conflict descriptions. Empty list = no conflicts.
        """
        new_capabilities = set(new_manifest.get("capabilities", []))
        conflicts: list[str] = []

        for existing in active_manifests:
            existing_name = existing.get("name", "unknown")
            existing_capabilities = set(existing.get("capabilities", []))
            overlap = new_capabilities & existing_capabilities
            if overlap:
                conflicts.append(
                    f"Capability conflict with '{existing_name}': "
                    f"both claim {sorted(overlap)}"
                )

        return conflicts

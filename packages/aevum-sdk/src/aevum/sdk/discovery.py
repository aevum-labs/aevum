"""
Complication discovery via Python entry points.

Complications register themselves in pyproject.toml:

    [project.entry-points."aevum.complications"]
    my-comp = "my_package.complication:MyComplication"

The kernel calls discover_complications() to find all installed complications.
Results are passed through Engine.install_complication() for manifest validation and approval gating.
"""

from __future__ import annotations

import importlib.metadata
import logging
from typing import Any

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "aevum.complications"


def discover_complications() -> list[Any]:
    """
    Find all installed complications via entry points.

    Returns a list of Complication instances.
    Logs and skips any that fail to load.
    """
    complications = []
    for ep in importlib.metadata.entry_points(group=ENTRY_POINT_GROUP):
        try:
            cls = ep.load()
            instance = cls()
            complications.append(instance)
            logger.info("Discovered complication: %s v%s", instance.name, instance.version)
        except Exception as e:
            logger.warning("Failed to load complication %s: %s", ep.name, e)
    return complications

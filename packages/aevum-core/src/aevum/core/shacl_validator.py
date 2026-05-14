# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
pySHACL validation helper for RELATE-time fact validation.
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_SHAPES_DIR = Path(__file__).parent / "shapes"


class SHACLValidationError(Exception):
    """Raised when a fact fails SHACL validation at RELATE time."""


def validate_fact_rdf(
    data_graph_ttl: str,
    shapes_path: Path | None = None,
) -> None:
    """
    Validate an RDF graph (Turtle string) against SHACL shapes.
    Raises SHACLValidationError if invalid.
    Does NOT make network calls — all shapes are local.

    data_graph_ttl: Turtle-format RDF string of the fact to validate
    shapes_path: path to .ttl shapes file (defaults to typed_fact.ttl)
    """
    try:
        from pyshacl import validate
    except ImportError as exc:
        raise ImportError(
            "pySHACL is required for RELATE-time validation. "
            "pip install pyshacl"
        ) from exc

    if not data_graph_ttl or not data_graph_ttl.strip():
        return

    _shapes = shapes_path or (_SHAPES_DIR / "typed_fact.ttl")
    if not _shapes.exists():
        logger.warning(
            "SHACL shapes file not found at %s. "
            "Skipping SHACL validation.", _shapes,
        )
        return

    conforms, _results_graph, results_text = validate(
        data_graph=data_graph_ttl,
        shacl_graph=str(_shapes),
        data_graph_format="turtle",
        shacl_graph_format="turtle",
        inference="none",
        abort_on_first=True,
    )

    if not conforms:
        raise SHACLValidationError(
            f"Fact failed SHACL validation:\n{results_text}"
        )

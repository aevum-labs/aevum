"""
OxigraphStore — GraphStore Protocol backed by pyoxigraph.

Satisfies the aevum.core.protocols.graph_store.GraphStore Protocol.
Uses three Named Graphs (frozen invariants from spec Section 04.3):
  urn:aevum:knowledge   — working graph (entities and relationships)
  urn:aevum:provenance  — per-entity provenance records as quads
  urn:aevum:consent     — consent ledger (managed by aevum-core)

RDF-star is NOT used (dropped in pyoxigraph 0.5).
Provenance is stored as separate quads in urn:aevum:provenance.
"""

from __future__ import annotations

import datetime
import json
import threading
from pathlib import Path
from typing import Any

from pyoxigraph import Literal, NamedNode, Quad, QuerySolutions, Store

from aevum.store.oxigraph.vocabulary import (
    PRED_CLASS_LVL,
    PRED_INGEST_AT,
    PRED_SUBJECT_ID,
    PRED_TYPE,
    TYPE_ENTITY,
)

# Three Named Graphs — FROZEN INVARIANTS (spec Section 04.3)
GRAPH_KNOWLEDGE  = NamedNode("urn:aevum:knowledge")
GRAPH_PROVENANCE = NamedNode("urn:aevum:provenance")
GRAPH_CONSENT    = NamedNode("urn:aevum:consent")

# XSD datatypes
XSD_STRING   = NamedNode("http://www.w3.org/2001/XMLSchema#string")
XSD_INTEGER  = NamedNode("http://www.w3.org/2001/XMLSchema#integer")
XSD_DATETIME = NamedNode("http://www.w3.org/2001/XMLSchema#dateTime")


def _entity_node(entity_id: str) -> NamedNode:
    """Map an entity_id string to an RDF NamedNode IRI."""
    if entity_id.startswith("http") or entity_id.startswith("urn:"):
        return NamedNode(entity_id)
    return NamedNode(f"urn:aevum:entity:{entity_id}")


def _lit_str(value: str) -> Literal:
    return Literal(value, datatype=XSD_STRING)


def _lit_int(value: int) -> Literal:
    return Literal(str(value), datatype=XSD_INTEGER)


def _lit_dt(value: str) -> Literal:
    return Literal(value, datatype=XSD_DATETIME)


class OxigraphStore:
    """
    GraphStore implementation backed by pyoxigraph.

    Thread-safe via internal lock.
    Satisfies aevum.core.protocols.graph_store.GraphStore Protocol.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        """
        Create an OxigraphStore.

        Args:
            path: Directory for disk-backed persistence.
                  None = in-memory (dev/test only, lost on restart).
        """
        if path is not None:
            self._store = Store(str(path))
        else:
            self._store = Store()
        self._lock = threading.Lock()
        self._init_named_graphs()

    def _init_named_graphs(self) -> None:
        """Ensure all three Named Graphs exist in the store."""
        with self._lock:
            for graph in (GRAPH_KNOWLEDGE, GRAPH_PROVENANCE, GRAPH_CONSENT):
                self._store.add_graph(graph)

    def store_entity(
        self,
        entity_id: str,
        data: dict[str, Any],
        classification: int = 0,
    ) -> None:
        """
        Store or update an entity in urn:aevum:knowledge.
        Stores provenance metadata in urn:aevum:provenance.

        Classification level enforces Barrier 2 at read time.
        """
        node = _entity_node(entity_id)
        now_iso = datetime.datetime.now(datetime.UTC).isoformat()

        with self._lock:
            # Remove existing quads for this entity before re-inserting
            # (update semantics — last write wins within a subject)
            existing = list(self._store.quads_for_pattern(
                node, None, None, GRAPH_KNOWLEDGE
            ))
            for quad in existing:
                self._store.remove(quad)

            # Core type quad
            self._store.add(Quad(node, PRED_TYPE, TYPE_ENTITY, GRAPH_KNOWLEDGE))

            # Store each data field as a separate quad
            # Non-string values are JSON-serialized as string literals
            for key, value in data.items():
                pred = NamedNode(f"urn:aevum:field:{key}")
                if isinstance(value, str):
                    obj: Literal = _lit_str(value)
                elif isinstance(value, int):
                    obj = _lit_int(value)
                elif isinstance(value, float):
                    obj = Literal(str(value), datatype=NamedNode(
                        "http://www.w3.org/2001/XMLSchema#double"
                    ))
                else:
                    obj = _lit_str(json.dumps(value))
                self._store.add(Quad(node, pred, obj, GRAPH_KNOWLEDGE))

            # Store provenance in urn:aevum:provenance
            # (separate quads — not RDF-star, which is dropped in 0.5)
            prov_quads = [
                Quad(node, PRED_SUBJECT_ID, _lit_str(entity_id), GRAPH_PROVENANCE),
                Quad(node, PRED_CLASS_LVL, _lit_int(classification), GRAPH_PROVENANCE),
                Quad(node, PRED_INGEST_AT, _lit_dt(now_iso), GRAPH_PROVENANCE),
            ]
            for q in prov_quads:
                self._store.add(q)

    def get_entity(self, entity_id: str) -> dict[str, Any] | None:
        """Retrieve an entity by ID. Returns None if not found."""
        node = _entity_node(entity_id)
        result: dict[str, Any] = {}

        with self._lock:
            quads = list(self._store.quads_for_pattern(
                node, None, None, GRAPH_KNOWLEDGE
            ))

        if not quads:
            return None

        for quad in quads:
            pred_str = quad.predicate.value
            if pred_str == PRED_TYPE.value:
                continue  # skip rdf:type
            if pred_str.startswith("urn:aevum:field:"):
                key = pred_str[len("urn:aevum:field:"):]
                obj = quad.object
                if isinstance(obj, (NamedNode, Literal)):
                    raw = obj.value
                    try:
                        result[key] = json.loads(raw)
                    except (json.JSONDecodeError, ValueError):
                        result[key] = raw

        return result if result else None

    def get_entity_classification(self, entity_id: str) -> int:
        """Return the classification level of an entity (default 0)."""
        node = _entity_node(entity_id)
        with self._lock:
            quads = list(self._store.quads_for_pattern(
                node, PRED_CLASS_LVL, None, GRAPH_PROVENANCE
            ))
        if not quads:
            return 0
        obj = quads[0].object
        if not isinstance(obj, (NamedNode, Literal)):
            return 0
        try:
            return int(obj.value)
        except ValueError:
            return 0

    def query_entities(
        self,
        subject_ids: list[str],
        classification_max: int = 0,
    ) -> dict[str, dict[str, Any]]:
        """
        Retrieve entities for the given subject IDs.
        Excludes entities classified above classification_max (Barrier 2).
        """
        result: dict[str, dict[str, Any]] = {}
        for entity_id in subject_ids:
            entity_class = self.get_entity_classification(entity_id)
            if entity_class > classification_max:
                continue  # Barrier 2: classification ceiling
            entity_data = self.get_entity(entity_id)
            if entity_data is not None:
                result[entity_id] = entity_data
        return result

    def sparql_select(
        self,
        query: str,
        default_graph: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute a SPARQL SELECT query and return results as a list of dicts.

        Not part of the GraphStore Protocol. Useful for ad-hoc traversal
        within complications or diagnostics. Not exposed as a public HTTP endpoint.
        """
        kwargs: dict[str, Any] = {}
        if default_graph:
            kwargs["default_graph"] = NamedNode(default_graph)
        with self._lock:
            solutions = self._store.query(query, **kwargs)
        rows: list[dict[str, Any]] = []
        if not isinstance(solutions, QuerySolutions):
            return rows
        for sol in solutions:
            row: dict[str, Any] = {}
            for var in sol.variables():
                term = sol[var]
                if term is not None and isinstance(term, (NamedNode, Literal)):
                    row[str(var)] = term.value
            rows.append(row)
        return rows

    def entity_count(self) -> int:
        """Return number of distinct entities in urn:aevum:knowledge."""
        with self._lock:
            quads = list(self._store.quads_for_pattern(
                None, PRED_TYPE, TYPE_ENTITY, GRAPH_KNOWLEDGE
            ))
        return len(quads)

    def clear_knowledge_graph(self) -> None:
        """
        Clear all entities from urn:aevum:knowledge and urn:aevum:provenance.
        For testing only — not available via any public API.
        """
        with self._lock:
            self._store.clear_graph(GRAPH_KNOWLEDGE)
            self._store.clear_graph(GRAPH_PROVENANCE)

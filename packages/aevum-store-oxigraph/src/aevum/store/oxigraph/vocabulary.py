"""
Standard relationship vocabulary for the Aevum knowledge graph.

These predicates are used when storing entities and their relationships.
They are not exposed as a user-facing SPARQL endpoint (Non-Goal per spec 3.4).
"""

from __future__ import annotations

from pyoxigraph import NamedNode

# Aevum namespace
AEVUM = "https://aevum.build/vocab/"

# Core predicates
PRED_TYPE       = NamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
PRED_LABEL      = NamedNode("http://www.w3.org/2000/01/rdf-schema#label")
PRED_CONTENT    = NamedNode(f"{AEVUM}content")
PRED_SUBJECT_ID = NamedNode(f"{AEVUM}subjectId")
PRED_SOURCE_ID  = NamedNode(f"{AEVUM}sourceId")
PRED_AUDIT_ID   = NamedNode(f"{AEVUM}auditId")
PRED_CLASS_LVL  = NamedNode(f"{AEVUM}classificationLevel")
PRED_INGEST_AT  = NamedNode(f"{AEVUM}ingestedAt")

# Entity types
TYPE_ENTITY     = NamedNode(f"{AEVUM}Entity")

# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
EU AI Act Article 12 audit pack export.

Article 12 requires high-risk AI systems to maintain logs enabling:
  - Post-market monitoring
  - Investigation of incidents
  - Assessment of conformity

The audit pack is a JSON-LD document using the PROV-O vocabulary
(W3C Provenance Ontology) to describe the session's activities,
entities (facts, context bundles), and agents (users, AI system).

The audit pack is read-only — it is derived from the append-only
sigchain and cannot be modified.

Usage:
  from aevum.core.audit.audit_pack import AuditPackExporter
  exporter = AuditPackExporter(db_path=Path("~/.aevum/aevum.db"))
  pack = exporter.export(session_id="sess-abc")
  # pack is a dict serializable to JSON-LD
  import json
  print(json.dumps(pack, indent=2))
"""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


# PROV-O namespace
PROV = "http://www.w3.org/ns/prov#"
XSD = "http://www.w3.org/2001/XMLSchema#"
AEVUM_NS = "https://aevum.build/ontology#"
AEVUM_SESSION = "https://aevum.build/session/"
AEVUM_AGENT_NS = "https://aevum.build/agent/"


JSONLD_CONTEXT: dict[str, Any] = {
    "prov": PROV,
    "xsd": XSD,
    "aevum": AEVUM_NS,
    "prov:startedAtTime": {"@type": "xsd:dateTime"},
    "prov:endedAtTime": {"@type": "xsd:dateTime"},
    "prov:generatedAtTime": {"@type": "xsd:dateTime"},
}


class AuditPackError(Exception):
    """Raised when audit pack cannot be generated."""


class AuditPackExporter:
    """
    Exports Article 12 audit packs from the Aevum session store.

    The export reads from SQLite (append-only, sigchain-protected) and
    produces a JSON-LD document. The document cannot be modified — it
    is a read-only view of immutable audit data.
    """

    def __init__(self, db_path: Path) -> None:
        if not db_path.exists():
            raise AuditPackError(f"Aevum database not found: {db_path}")
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def export(self, session_id: str) -> dict[str, Any]:
        """
        Export a complete Article 12 audit pack for a session.

        Returns a JSON-LD dict with PROV-O structure.
        Raises AuditPackError if session not found.
        """
        session = self._load_session(session_id)
        events = self._load_events(session_id)
        generated_at = datetime.now(UTC).isoformat()

        graph: list[dict[str, Any]] = []

        # 1. The AI system as a prov:SoftwareAgent
        graph.append({
            "@id": f"{AEVUM_NS}AevumKernel",
            "@type": ["prov:SoftwareAgent", "prov:Agent"],
            "prov:label": "Aevum Governed Context Kernel",
            f"{AEVUM_NS}version": "2.0",
        })

        # 2. The human principal as a prov:Person
        principal_id = f"{AEVUM_AGENT_NS}{session['principal']}"
        graph.append({
            "@id": principal_id,
            "@type": ["prov:Person", "prov:Agent"],
            "prov:label": session["principal"],
        })

        # 3. The session as a prov:Activity
        session_uri = f"{AEVUM_SESSION}{session_id}"
        session_node: dict[str, Any] = {
            "@id": session_uri,
            "@type": "prov:Activity",
            "prov:startedAtTime": session["started_at"],
            "prov:endedAtTime": session["closed_at"],
            "prov:wasAssociatedWith": [
                {"@id": principal_id},
                {"@id": f"{AEVUM_NS}AevumKernel"},
            ],
            f"{AEVUM_NS}purpose": session["purpose"],
            f"{AEVUM_NS}commitType": session["commit_type"],
            f"{AEVUM_NS}eventCount": session["event_count"],
            f"{AEVUM_NS}merkleRoot": session["merkle_root"],
        }
        if session["sigchain_entry_id"]:
            session_node[f"{AEVUM_NS}sigchainEntry"] = session["sigchain_entry_id"]
        graph.append(session_node)

        # 4. Each session event as a prov:Entity
        for ev in events:
            event_uri = f"{AEVUM_SESSION}{session_id}/event/{ev['sequence']}"
            graph.append({
                "@id": event_uri,
                "@type": "prov:Entity",
                "prov:wasGeneratedBy": {"@id": session_uri},
                "prov:generatedAtTime": ev["occurred_at"],
                f"{AEVUM_NS}eventType": ev["event_type"],
                f"{AEVUM_NS}sequence": ev["sequence"],
                f"{AEVUM_NS}inputHash": ev["input_hash"],
                f"{AEVUM_NS}outputHash": ev["output_hash"],
                f"{AEVUM_NS}latencyMs": ev["latency_ms"],
            })

        # 5. Article 12 metadata block
        article12: dict[str, Any] = {
            "@id": f"{session_uri}/article12",
            "@type": f"{AEVUM_NS}Article12Record",
            "prov:generatedAtTime": generated_at,
            f"{AEVUM_NS}aiSystemId": "aevum-kernel-v2",
            f"{AEVUM_NS}sessionId": session_id,
            f"{AEVUM_NS}principalId": session["principal"],
            f"{AEVUM_NS}purpose": session["purpose"],
            f"{AEVUM_NS}startedAt": session["started_at"],
            f"{AEVUM_NS}endedAt": session["closed_at"],
            f"{AEVUM_NS}commitType": session["commit_type"],
            f"{AEVUM_NS}totalEvents": session["event_count"],
            f"{AEVUM_NS}merkleRoot": session["merkle_root"],
            f"{AEVUM_NS}auditIntegrity": "sigchain-dual-signed",
        }
        graph.append(article12)

        return {
            "@context": JSONLD_CONTEXT,
            "@graph": graph,
            "_meta": {
                "export_format": "aevum-article12-v2",
                "generated_at": generated_at,
                "session_id": session_id,
                "event_count": len(events),
                "prov_o_version": "2013-04-30",
                "eu_ai_act_article": "12",
            },
        }

    def export_json(self, session_id: str, indent: int = 2) -> str:
        """Export audit pack as a JSON string."""
        pack = self.export(session_id)
        return json.dumps(pack, indent=indent, ensure_ascii=False)

    def _load_session(self, session_id: str) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT session_id, commit_type, principal, purpose, "
            "started_at, closed_at, event_count, fact_count, "
            "checkpoint_count, merkle_root, sigchain_entry_id "
            "FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            raise AuditPackError(f"Session not found: {session_id!r}")
        return row

    def _load_events(self, session_id: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT event_id, session_id, sequence, event_type, "
            "occurred_at, input_hash, output_hash, latency_ms "
            "FROM session_events WHERE session_id = ? ORDER BY sequence",
            (session_id,),
        ).fetchall()

    def close(self) -> None:
        self._conn.close()

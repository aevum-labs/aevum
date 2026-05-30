# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
EU AI Act Article 12 audit pack exporter.

Article 12 of the EU AI Act (2024/1689) requires providers of high-risk AI systems to
maintain logs enabling traceability and post-hoc accountability. Specifically, Art. 12(1)
requires logs that enable: identification of the system (a), the persons responsible (b),
the time period of operation (c), the input data used (d, as hashes), and the output (e).

The audit pack satisfies these requirements by producing a JSON-LD document using the
W3C PROV-O vocabulary (W3C Provenance Ontology, 2013). PROV-O is an RDF ontology for
representing provenance information — it describes what happened (Activities), who did it
(Agents), and what was produced (Entities). Using a standardised ontology means any
PROV-O-aware tool can query the audit pack without understanding Aevum-specific schema.

Five graph nodes in every audit pack (in order):
  1. prov:SoftwareAgent — the Aevum kernel (the AI system, Art. 12(1)(a))
  2. prov:Person         — the human principal (responsible person, Art. 12(1)(b))
  3. prov:Activity       — the session (time period + purpose, Art. 12(1)(b,c))
  4. prov:Entity (×N)    — each session event (input/output hashes, Art. 12(1)(d,e))
  5. Article12Record     — structured compliance metadata block

The named graphs (Spec Section 10.2) that feed this pack:
  urn:aevum:knowledge   — working graph (entity facts; NOT exported directly)
  urn:aevum:provenance  — immutable audit (sigchain entries; feeds events)
  urn:aevum:consent     — consent ledger (grant/revocation records; not in pack)
These three URIs are frozen invariants — any renaming would break existing audit packs.

The audit pack is read-only: it is derived from the append-only sigchain and SQLite session
store. It cannot be modified after export. Export during an active session gives a partial
view; export after session.close() gives the complete sealed record.

Usage:
  from aevum.core.audit.audit_pack import AuditPackExporter
  exporter = AuditPackExporter(db_path=Path("~/.aevum/aevum.db"))
  pack = exporter.export(session_id="sess-abc")
  import json; print(json.dumps(pack, indent=2))
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
    """Exports EU AI Act Article 12 audit packs as W3C PROV-O JSON-LD documents.

    Reads from the SQLite session store (append-only, sigchain-protected) and produces a
    JSON-LD document. The document is a read-only view of immutable audit data — exporting
    the same session_id twice always produces the same output (modulo generated_at timestamp).

    An investigator receiving an audit pack can verify integrity by re-computing the Merkle
    root over the session events, cross-checking the sigchain entry, and validating the
    Ed25519 signature on the session record — all without trusting the operator's claims.
    """

    def __init__(self, db_path: Path) -> None:
        if not db_path.exists():
            raise AuditPackError(f"Aevum database not found: {db_path}")
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def export(self, session_id: str) -> dict[str, Any]:
        """Export a complete EU AI Act Article 12 audit pack for a session.

        Produces a JSON-LD document with five W3C PROV-O graph nodes (see module docstring).
        The @context maps prov: and xsd: prefixes so any PROV-O tool can parse the document
        without an Aevum-specific schema.

        Args:
            session_id: The session to export. Must exist in the SQLite sessions table.

        Returns:
            Dict serializable to JSON-LD with @context, @graph, and _meta sections.

        Raises:
            AuditPackError: If session_id is not found in the database.
        """
        session = self._load_session(session_id)
        events = self._load_events(session_id)
        generated_at = datetime.now(UTC).isoformat()

        graph: list[dict[str, Any]] = []

        # Node 1: prov:SoftwareAgent — the AI system itself (Art. 12(1)(a): identification of system).
        # prov:SoftwareAgent is the W3C PROV-O type for automated software actors.
        graph.append({
            "@id": f"{AEVUM_NS}AevumKernel",
            "@type": ["prov:SoftwareAgent", "prov:Agent"],
            "prov:label": "Aevum Governed Context Kernel",
            f"{AEVUM_NS}version": "2.0",
        })

        # Node 2: prov:Person — the human principal responsible for this session
        # (Art. 12(1)(b): identification of persons responsible). prov:wasAssociatedWith
        # on the Activity node links the principal to the session activity.
        principal_id = f"{AEVUM_AGENT_NS}{session['principal']}"
        graph.append({
            "@id": principal_id,
            "@type": ["prov:Person", "prov:Agent"],
            "prov:label": session["principal"],
        })

        # Node 3: prov:Activity — the session (Art. 12(1)(b,c): time period and purpose).
        # prov:startedAtTime / prov:endedAtTime satisfy the "time period of operation"
        # requirement. prov:wasAssociatedWith links to both the principal and the AI system.
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

        # Nodes 4…N: prov:Entity — one per session event (Art. 12(1)(d,e): input data used
        # and outputs produced). inputHash and outputHash satisfy the "input data" requirement
        # without storing the raw data itself — an investigator can verify hash matches against
        # the original data, but the pack does not expose PII or model outputs in plaintext.
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

        # Node 5: Article12Record — structured compliance metadata block. This is an Aevum
        # extension to PROV-O that collects the Article 12 mandatory fields in one place,
        # making it easy for a compliance tool to extract them without traversing the graph.
        # aiSystemId, sessionId, principalId, purpose, startedAt, endedAt satisfy Art. 12(1)(a-c).
        # merkleRoot and auditIntegrity reference the cryptographic proof of integrity.
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
        row: sqlite3.Row | None = self._conn.execute(
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

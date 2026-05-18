// ============================================================
// GDPR ARTICLE 17 — RAW PII BARRIER
//
// Forbid ingest of payloads that contain raw personal data.
//
// Rationale: the episodic ledger is append-only (Barrier 4). Storing
// raw PII in sigchain payloads creates an irresolvable tension with
// GDPR Article 17 (right to erasure). The supported integration pattern
// stores only a hash pointer + key ID on-chain; raw data lives off-chain
// in an erasable store and is protected by per-subject crypto-shredding.
//
// See docs/compliance/gdpr-article-17.md for the full integration pattern.
//
// Callers of ingest() (relate_graph_write) MUST set context.contains_raw_pii
// at their integration boundary. Absence of the flag is treated as false.
// ============================================================

forbid (
    principal,
    action == Action::"relate_graph_write",
    resource
) when {
    context has contains_raw_pii &&
    context.contains_raw_pii == true
};

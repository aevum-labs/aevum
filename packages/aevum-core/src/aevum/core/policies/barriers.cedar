// ============================================================
// AEVUM UNCONDITIONAL BARRIERS
// Five Cedar forbid policies — non-bypassable by any permit.
// These form the immutable security core of the kernel.
//
// Cedar semantics: forbid ALWAYS overrides permit.
// The only escape is the `unless` clause within the forbid itself.
// ============================================================

// BARRIER 1: Crisis
// Forbid all relate_graph_write operations if crisis content is detected.
// This runs before entity recognition, before any graph write.
// There is no escape — if has_crisis_content is true, the write is blocked.
forbid(
    principal,
    action == Action::"relate_graph_write",
    resource
) when {
    context has has_crisis_content &&
    context.has_crisis_content == true
};

// BARRIER 3: Consent
// Forbid navigate (context assembly) without an active, scoped consent grant.
// No data flows to an agent without explicit consent for that purpose.
forbid(
    principal,
    action == Action::"navigate",
    resource
) unless {
    context has has_active_consent &&
    context.has_active_consent == true &&
    context has consent_purpose_matches &&
    context.consent_purpose_matches == true
};

// BARRIER 2: Classification Ceiling
// Forbid any action on data whose classification exceeds the deployment ceiling.
// Levels: 0 = public, 1 = internal, 2 = confidential, 3 = restricted
forbid(
    principal,
    action,
    resource
) when {
    context has data_classification_level &&
    context has deployment_ceiling_level &&
    context.data_classification_level > context.deployment_ceiling_level
};

// BARRIER 4: Audit Seal
// The provenance graph is append-only. No deletions or updates are permitted.
// Ever. By anyone. Including the system itself.
forbid(
    principal,
    action in [
        Action::"delete_audit_event",
        Action::"update_audit_event",
        Action::"truncate_audit_chain",
        Action::"rewrite_audit_chain"
    ],
    resource
);

// BARRIER 5: Provenance
// Every knowledge-graph write must carry provenance (source_id present).
// The kernel enforces this structurally in check_provenance (barriers.py),
// which fires BEFORE the policy stage; this forbid mirrors it here so that no
// permit can grant an unprovenanced write. Defense-in-depth: for valid input
// has_provenance is always true by the time policy runs, so this never changes
// observable behavior — it only bites if the kernel check is ever removed.
forbid(
    principal,
    action == Action::"relate_graph_write",
    resource
) unless {
    context has has_provenance &&
    context.has_provenance == true
};

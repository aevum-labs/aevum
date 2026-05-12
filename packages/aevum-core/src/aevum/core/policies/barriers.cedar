// ============================================================
// AEVUM ABSOLUTE BARRIERS
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

// BARRIER 2: Consent
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

// BARRIER 3: Classification Ceiling
// Forbid any action on data whose classification exceeds the deployment ceiling.
// Levels: 0=UNCLASSIFIED, 1=INTERNAL, 2=CONFIDENTIAL, 3=PHI, 4=SECRET
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

// BARRIER 5: Provenance — Veto as Default
// Irreversible AND consequential actions require explicit human review.
// The forbid fires unless the GOVERN checkpoint has completed human review
// and set human_checkpoint_completed = true in the context.
// The GOVERN implementation sets this AFTER human approval is received.
// It cannot be set to true by application code without going through GOVERN.
forbid(
    principal,
    action == Action::"govern_approve",
    resource
) when {
    context has action_reversible &&
    context.action_reversible == false &&
    context has action_consequential &&
    context.action_consequential == true
} unless {
    context has human_checkpoint_completed &&
    context.human_checkpoint_completed == true
};

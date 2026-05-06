// Reference example only. Legal review required before production use.
// ISO/IEC 42001:2023 — AI Management System
// Annex A.6.2.8: AI system recording of event logs
// The organisation shall determine at which phases of the AI system
// life cycle event log recording is enabled.

// Lifecycle phase logging gates — deployer configures which phases require logging

permit (
    principal in Group::"ai_system_operators",
    action == Action::"ingest",
    resource
)
when {
    // Logging is enabled for this lifecycle phase
    resource.lifecycle_phase in
        ["development", "validation", "production", "decommission"]
};

permit (
    principal in Group::"ai_system_operators",
    action == Action::"commit",
    resource
)
when {
    resource.lifecycle_phase in
        ["development", "validation", "production", "decommission"]
};

// A.6.2.6: AI system monitoring — review action requires human authorisation
permit (
    principal in Group::"human_reviewers",
    action == Action::"review",
    resource
)
when {
    resource.review_type == "human_oversight"
};

// Deny automated review (GOVERN checkpoint must have human in the loop)
forbid (
    principal in Group::"automated_systems",
    action == Action::"review",
    resource
);

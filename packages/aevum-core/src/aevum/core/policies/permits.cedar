// ============================================================
// BASE PERMITS
//
// Default permits for routine operations.
// Barriers above override any permit when conditions are met.
// Adding more specific permits here is how operators customize access.
// ============================================================

// Permit routine RELATE operations (crisis barrier will block if needed)
permit(
    principal,
    action == Action::"relate_graph_write",
    resource == DataGraph::"knowledge"
);

// Permit routine NAVIGATE (consent barrier will block if needed)
permit(
    principal,
    action == Action::"navigate",
    resource
);

// Permit routine REMEMBER (audit seal barrier will block mutations)
permit(
    principal,
    action == Action::"remember_commit",
    resource
);

// Permit routine tool calls (trifecta barrier will block if needed)
permit(
    principal,
    action == Action::"tool_call",
    resource
);

// Permit GOVERN review (not approve — just the review step)
permit(
    principal,
    action == Action::"govern_review",
    resource
);

// Permit GOVERN approve — Barrier 5 (and autonomy policies) will forbid
// this unless human_checkpoint_completed=true in context.
permit(
    principal,
    action == Action::"govern_approve",
    resource
);

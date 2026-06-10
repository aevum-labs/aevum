// ============================================================
// L1-L5 AUTONOMY ENFORCEMENT
//
// L1 — Fully supervised: every action requires human approval
// L2 — Supervised: consequential actions require human approval
// L3 — Semi-autonomous: only irreversible actions require approval
// L4 — Mostly autonomous: only crisis-adjacent actions require approval
// L5 — Fully autonomous: system makes all decisions (rare, restricted)
//
// Context attribute: autonomy_level (integer 1-5)
// ============================================================

// L1: All govern_approve actions require human checkpoint
forbid(
    principal,
    action == Action::"govern_approve",
    resource
) when {
    context has autonomy_level &&
    context.autonomy_level == 1
} unless {
    context has human_checkpoint_completed &&
    context.human_checkpoint_completed == true
};

// L2: Consequential actions require human checkpoint
forbid(
    principal,
    action == Action::"govern_approve",
    resource
) when {
    context has autonomy_level &&
    context.autonomy_level == 2 &&
    context has action_consequential &&
    context.action_consequential == true
} unless {
    context has human_checkpoint_completed &&
    context.human_checkpoint_completed == true
};

// L3: Irreversible AND consequential actions require human checkpoint.
// (Moved here from barriers.cedar, where it was mislabeled "Barrier 5". This is
//  a GOVERN / autonomy human-in-the-loop control — NOT one of the five kernel
//  barriers. Veto-as-default semantics are unchanged: human_checkpoint_completed
//  is set only by the GOVERN implementation after real human review.)
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

// L4: Crisis-adjacent only (covered by Barrier 1)
// L5: No autonomy restrictions beyond the five unconditional barriers

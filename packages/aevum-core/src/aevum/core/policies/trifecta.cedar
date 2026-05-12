// ============================================================
// TRIFECTA ENFORCEMENT
//
// The "lethal trifecta" attack pattern (2025-2026 AI incidents):
//   1. Ingest untrusted content (READS_UNTRUSTED)
//   2. Access private user data (READS_PRIVATE)
//   3. Exfiltrate via a tool call (CAN_EXFILTRATE)
//
// An agent cannot compose all three without an explicit permit
// that crosses all three taint labels simultaneously.
// This policy prevents the composition — not each step individually.
//
// TaintLabel entity type:
//   TaintLabel::"READS_UNTRUSTED"  — tool reads from untrusted source
//   TaintLabel::"READS_PRIVATE"    — tool reads private user data
//   TaintLabel::"CAN_EXFILTRATE"   — tool can send data externally
// ============================================================

// Forbid any tool action that would complete the trifecta.
// The session context tracks which taint labels are active.
// If all three are active simultaneously, block the action.
forbid(
    principal,
    action == Action::"tool_call",
    resource
) when {
    context has taint_reads_untrusted &&
    context.taint_reads_untrusted == true &&
    context has taint_reads_private &&
    context.taint_reads_private == true &&
    context has taint_can_exfiltrate &&
    context.taint_can_exfiltrate == true
};

// Individual taint labels do not block — only the combination.
// (Each individual label is permitted unless all three are present.)

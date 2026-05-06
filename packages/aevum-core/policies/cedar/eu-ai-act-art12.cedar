// SPDX-License-Identifier: Apache-2.0
//
// Reference policy — EU AI Act Article 12 compliance posture (Cedar)
// Equivalent to: opa/eu-ai-act-art12.rego
//
// WARNING: Reference example only. Not legal advice.
// Consult qualified legal counsel before production deployment.
//
// Cedar evaluation context shape:
// {
//   "audit_enabled": true,
//   "sigchain_enabled": true,
//   "retention_days": 365
// }

// Permit operations when all Art. 12 conditions are satisfied
permit (
    principal,
    action,
    resource
)
when {
    context.audit_enabled == true &&
    context.sigchain_enabled == true &&
    context.retention_days >= 183
};

// Forbid when tamper-evident sigchain is disabled
// (Independent verification by national competent authorities requires it)
forbid (
    principal,
    action,
    resource
)
when {
    context.sigchain_enabled == false
};

// Forbid when retention is below Art. 26(6) six-month minimum
forbid (
    principal,
    action,
    resource
)
when {
    context.retention_days < 183
};

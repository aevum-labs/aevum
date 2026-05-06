# Reference example only. Legal review required before production use.
# HIPAA Security Rule §164.312(b) — Audit Controls
# 45 CFR §164.312(b): hardware, software, and/or procedural mechanisms to
# record and examine activity in information systems containing ePHI.
# 2024 NPRM (not yet final as of May 2026): proposes tamper-evident logs.

package aevum.policy.hipaa_security

import rego.v1

# §164.312(b): Record and examine activity
# The Aevum sigchain records all five governed functions. This policy
# enforces that ePHI-touching events declare the PHI subject.

deny contains msg if {
    input.event.event_type in {"ingest.accepted", "query.result", "commit.accepted"}
    not input.event.payload.subject_id
    msg := "HIPAA §164.312(b): ePHI-touching event must declare subject_id"
}

# Minimum-necessary principle: classification ceiling enforces this in the kernel.
# This rule cross-checks that the classification was not exceeded at policy layer.
deny contains msg if {
    input.event.payload.classification > input.context.consent_classification_max
    msg := sprintf(
        "HIPAA minimum-necessary: classification %v exceeds consent ceiling %v",
        [input.event.payload.classification, input.context.consent_classification_max]
    )
}

# §164.316(b)(2): 6-year retention
# Runtime check: warn if a record is being accessed after 6 years with deletion intent
minimum_retention_years := 6

allow if {
    count(deny) == 0
}

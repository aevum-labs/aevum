# Reference example only. Legal review required before production use.
# EU AI Act Article 12 — Record-Keeping for High-Risk AI Systems
# Reg. (EU) 2024/1689; applies to Annex III high-risk systems
# Enforcement deadline: 2 August 2026 (Digital Omnibus delay unresolved)

package aevum.policy.eu_ai_act_art12

import rego.v1

# Art. 12(1): automatic recording of events over the lifetime of the system
# VERIFIED: this rule fires on every event that reaches the policy layer.
# The kernel's Barrier 4 (Audit Immutability) ensures the record is made
# before this rule is evaluated.

# Art. 12(2)(a): logs must support determination of events causing problems
required_fields := {
    "event_id", "event_type", "actor", "episode_id",
    "valid_from", "system_time", "prior_hash",
}

# Deny if required Art. 12 fields are absent
deny contains msg if {
    field := required_fields[_]
    not input.event[field]
    msg := sprintf("EU AI Act Art. 12: missing required field '%v'", [field])
}

# Art. 12(3): biometric identification systems must log additional fields
# Only applies to Annex III point 1(a) systems — flag via event metadata
deny contains msg if {
    input.system.is_biometric_annex_iii_1a == true
    not input.event.payload.biometric_database_id
    msg := "EU AI Act Art. 12(3): biometric_database_id required for Annex III(1)(a)"
}

deny contains msg if {
    input.system.is_biometric_annex_iii_1a == true
    not input.event.payload.input_data_reference
    msg := "EU AI Act Art. 12(3): input_data_reference required for Annex III(1)(a)"
}

# Art. 26(6) / Art. 19(1): retention minimum 6 months
# Policy checks this at query time — actual enforcement is via retention config.
minimum_retention_days := 183

allow if {
    count(deny) == 0
}

# Reference example only. Legal review required before production use.
# NIST SP 800-53 Rev 5 — AU (Audit and Accountability) Family
# Covers FedRAMP Low/Moderate baseline AU controls.

package aevum.policy.nist_800_53_au

import rego.v1

# AU-3: Content of Audit Records — minimum required fields
# Rev 5 AU-3 requires: event type, time, location, source, outcome, identity
au3_required_fields := {
    "event_type",   # type of event
    "valid_from",   # time of event
    "actor",        # identity of subject/user
    "payload",      # outcome (in payload)
}

deny contains msg if {
    field := au3_required_fields[_]
    not input.event[field]
    msg := sprintf("NIST AU-3: missing required audit content field '%v'", [field])
}

# AU-8: Time Stamps — use internal clocks synchronised to authoritative source
deny contains msg if {
    not input.event.system_time
    msg := "NIST AU-8: system_time (HLC) missing from audit record"
}

# AU-9: Protection of Audit Information
# Prior hash links provide chain integrity — AU-9(3) crypto protection.
deny contains msg if {
    not input.event.prior_hash
    msg := "NIST AU-9(3): prior_hash missing — cryptographic chain integrity violated"
}

# AU-10: Non-Repudiation (High baseline)
# Ed25519 signature per event provides non-repudiation.
deny contains msg if {
    input.context.fedramp_baseline == "high"
    not input.event.signature
    msg := "NIST AU-10: signature missing — non-repudiation not satisfied (FedRAMP High)"
}

# AU-12: Audit Record Generation — all five Aevum functions must generate records
# This rule validates event_type is a known Aevum event type
allowed_prefixes := {
    "session.", "ingest.", "query.", "review.", "commit.", "replay.",
    "consent.", "capture.", "transparency.", "chain.",
}

deny contains msg if {
    count([p | p := allowed_prefixes[_]; startswith(input.event.event_type, p)]) == 0
    msg := sprintf("NIST AU-12: unknown event_type prefix in '%v'", [input.event.event_type])
}

allow if {
    count(deny) == 0
}

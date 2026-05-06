# Reference example only. Legal review required before production use.
# NERC CIP-007-6 R4 — Security Event Monitoring
# Applies to AI systems in Bulk Electric System (BES) Cyber Systems
# CIP-007-7 (effective 1 Oct 2024): R3 refined; R4 substantively unchanged
# Crossover: CIS Controls v8.1 Safeguard 8.3 also requires 90-day minimum

package aevum.policy.nerc_cip007

import rego.v1

# R4.1.1: Log successful login, failed login, malicious code detection
nerc_required_event_types := {
    "session.start",         # system startup / login equivalent
    "query.denied",          # failed access attempt
    "ingest.barrier_violation", # malicious-code equivalent trigger
}

# R4.4: 90-day online retention minimum
minimum_retention_days := 90  # CIP-007-6 R4.4 + CIS Controls 8.3

deny contains msg if {
    not input.event.event_type
    msg := "NERC CIP-007-6 R4: event_type missing"
}

deny contains msg if {
    not input.event.system_time
    msg := "NERC CIP-007-6 R4: system_time missing — cannot establish event sequence"
}

allow if {
    count(deny) == 0
}

# Reference example only. Legal review required before production use.
# NYDFS 23 NYCRR 500, Second Amendment (effective 1 November 2023)
# §500.6(a)(1): cybersecurity audit trail — 3-year retention
# §500.6(a)(2): financial reconstruction records — 5-year retention

package aevum.policy.nydfs_part500

import rego.v1

# §500.6(a)(1): detect and respond to Cybersecurity Events
cybersecurity_event_types := {
    "session.start", "consent.revoked", "query.denied",
    "ingest.barrier_violation", "capture.gap",
}

# §500.6(a)(2): complete and accurate reconstruction of financial transactions
# Financial event types that require 5-year retention
financial_event_types := {
    "ingest.accepted", "commit.accepted", "query.result",
    "review.approved", "review.denied",
}

cybersecurity_retention_days := 1095  # 3 years
financial_retention_days     := 1825  # 5 years

# Determine minimum retention for this event
minimum_retention_days(event_type) := financial_retention_days if {
    event_type in financial_event_types
} else := cybersecurity_retention_days if {
    event_type in cybersecurity_event_types
} else := cybersecurity_retention_days  # default to cybersecurity floor

deny contains msg if {
    not input.event.event_type
    msg := "NYDFS §500.6: event_type missing — cannot determine retention class"
}

# §500.14: monitoring — the event stream must be consumable by a SIEM
# This rule validates event_id is present for SIEM correlation
deny contains msg if {
    not input.event.event_id
    msg := "NYDFS §500.14: event_id missing — SIEM correlation will fail"
}

allow if {
    count(deny) == 0
}

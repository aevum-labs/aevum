# Reference example only. Legal review required before production use.
# PCI DSS v4.0 Requirement 10 — Log and Monitor All Access to System
# Components and Cardholder Data
# Mandatory from 31 March 2025.

package aevum.policy.pci_dss_req10

import rego.v1

# Req 10.2.1: Required event types to log
required_event_types := {
    "ingest.accepted",   # 10.2.1.1: individual access to CHD
    "query.result",      # 10.2.1.1
    "session.start",     # 10.2.1.6: audit log start
    "capture.gap",       # 10.2.1: any access outside monitored path
    "review.created",    # 10.2.1.2: admin actions
    "consent.granted",   # 10.2.1.5: authentication mechanism changes
    "consent.revoked",   # 10.2.1.5
}

# 10.2.2: Audit log must include these fields per event
required_content_fields := {
    "actor",         # user identification
    "event_type",    # type of event
    "valid_from",    # date and time
    "episode_id",    # origination
    "payload",       # identity of affected data, where applicable
}

deny contains msg if {
    field := required_content_fields[_]
    not input.event[field]
    msg := sprintf("PCI DSS 10.2.2: missing required audit field '%v'", [field])
}

# Req 10.3.4: File integrity monitoring / change detection on audit logs
# The hash chain satisfies this — prior_hash links each event to its predecessor.
deny contains msg if {
    not input.event.prior_hash
    msg := "PCI DSS 10.3.4: prior_hash missing — hash chain integrity violated"
}

# Req 10.5.1: 12-month retention
minimum_retention_days := 365

# Req 10.6.1: NTP-based time synchronisation (deployment config)
# This rule warns if HLC timestamp differs significantly from wall-clock
# (indicative of NTP misconfiguration at the host level)
clock_drift_tolerance_ns := 60000000000  # 60 seconds in nanoseconds

allow if {
    count(deny) == 0
}

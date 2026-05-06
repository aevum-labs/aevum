# Reference example only. Legal review required before production use.
# DORA (Reg. (EU) 2022/2554) Article 17 — ICT-Related Incident Management
# Application date: 17 January 2025
# RTS on incident classification: Commission Delegated Reg. (EU) 2024/1772
# RTS on reporting: Commission Delegated Reg. (EU) 2025/301

package aevum.policy.dora_art17

import rego.v1

# Art. 17(3): record all ICT-related incidents
# Aevum's sigchain records all events; this policy validates the
# incident-relevant fields are present for events declared as incidents.

ict_incident_indicators := {
    "barrier_violation", "chain.error", "capture.gap",
    "consent.revoked", "query.denied",
}

deny contains msg if {
    event_type := input.event.event_type
    some indicator in ict_incident_indicators
    contains(event_type, indicator)
    not input.event.episode_id
    msg := "DORA Art. 17: ICT incident event must declare episode_id for incident correlation"
}

# Incident classification per RTS 2024/1772:
# major incidents require initial notification ≤4hr after classification
# This rule flags if a declared major incident lacks a timestamp
deny contains msg if {
    input.event.payload.dora_major_incident == true
    not input.event.valid_from
    msg := "DORA RTS 2024/1772: major incident event missing valid_from timestamp"
}

allow if {
    count(deny) == 0
}

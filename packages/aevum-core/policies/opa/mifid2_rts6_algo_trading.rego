# Reference example only. Legal review required before production use.
# MiFID II Article 17 + Commission Delegated Reg. (EU) 2017/589 (RTS 6)
# Algorithmic trading organisational requirements
# NOTE: HLC does NOT satisfy RTS 25 UTC traceability — see ADR-002.
# Deployers using Aevum for algo-trading audit MUST add NTP/PTP wall-clock
# attestation alongside HLC ordering.

package aevum.policy.mifid2_rts6

import rego.v1

# RTS 6 Art. 4: real-time alerts — not enforced at policy layer (SIEM)
# RTS 6 Art. 5: algorithmic trading system self-assessment annually
# RTS 6 Art. 8: business continuity — audit trail must survive failure

# Algorithm inventory: every algorithmic event must declare the algorithm ID
deny contains msg if {
    input.event.event_type in {"ingest.accepted", "commit.accepted"}
    input.context.mifid_algo_trading == true
    not input.event.payload.algorithm_id
    msg := "MiFID II RTS 6: algo-trading events must declare algorithm_id"
}

# RTS 25 clock — UTC traceability warning
warn contains msg if {
    input.context.mifid_algo_trading == true
    not input.system.utc_traceable_clock_confirmed
    msg := "MiFID II RTS 25 WARNING: UTC-traceable clock synchronisation not confirmed. HLC alone does not satisfy RTS 25."
}

allow if {
    count(deny) == 0
}

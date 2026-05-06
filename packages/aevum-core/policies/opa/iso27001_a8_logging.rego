# Reference example only. Legal review required before production use.
# ISO/IEC 27001:2022 Annex A
# A.8.15 Logging — record of activities, exceptions, faults, information security events
# A.8.16 Monitoring — detect anomalous behaviour (monitoring itself is external)
# A.8.17 Clock synchronisation — single authoritative time source

package aevum.policy.iso27001_a8

import rego.v1

# A.8.15: Ten enumerated event categories
# Aevum's event_type namespace covers: user access, admin, security events,
# failures, changes to system objects, and system start/stop.

# Minimum log content per A.8.15
deny contains msg if {
    not input.event.actor
    msg := "ISO/IEC 27001 A.8.15: user identification missing from log record"
}

deny contains msg if {
    not input.event.valid_from
    msg := "ISO/IEC 27001 A.8.15: timestamp missing from log record"
}

# A.8.17: Single authoritative time source
# The HLC provides monotonic ordering. This rule checks NTP sync is declared.
deny contains msg if {
    input.context.iso27001_a817_check == true
    not input.system.ntp_sync_confirmed
    msg := "ISO/IEC 27001 A.8.17: NTP synchronisation not confirmed in deployment config"
}

allow if {
    count(deny) == 0
}

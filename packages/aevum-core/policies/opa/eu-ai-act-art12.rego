# SPDX-License-Identifier: Apache-2.0
#
# Reference policy — EU AI Act Article 12 compliance posture
# Regulation: EU AI Act Article 12 (Regulation (EU) 2024/1689)
# Enforcement: August 2, 2026 for high-risk AI systems (Annex III)
#
# WARNING: Reference example only. Not legal advice.
# Consult qualified legal counsel before production deployment.
#
# Expected input shape:
# {
#   "session": {
#     "audit_enabled": true,
#     "sigchain_enabled": true,
#     "retention_days": 365
#   },
#   "event": {
#     "actor": "billing-agent",
#     "payload_hash": "sha3-256:abc..."
#   }
# }

package aevum.policies.eu_ai_act.art12

import rego.v1

# Art. 12(1): automatic recording of events must be enabled
# Art. 26(6): minimum six months retention (183 days)
# Art. 12 (implied): tamper-evident storage required for
#   independent verification by national competent authorities

default allow := false

allow if {
    count(deny_reasons) == 0
}

deny_reasons contains "audit_logging_not_enabled" if {
    not input.session.audit_enabled
}

deny_reasons contains "tamper_evident_sigchain_required" if {
    not input.session.sigchain_enabled
}

deny_reasons contains "retention_period_insufficient" if {
    # Art. 26(6): minimum six months (183 days)
    input.session.retention_days < 183
}

deny_reasons contains "actor_identity_required" if {
    not input.event.actor
}

deny_reasons contains "payload_integrity_hash_missing" if {
    not input.event.payload_hash
}

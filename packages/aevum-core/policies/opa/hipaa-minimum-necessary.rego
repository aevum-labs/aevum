# SPDX-License-Identifier: Apache-2.0
#
# Reference policy — HIPAA Minimum Necessary Standard
# Regulation: 45 CFR § 164.502(b)
#
# WARNING: Reference example only. Not legal advice.
# Consult qualified legal counsel before production deployment.
#
# Expected input shape:
# {
#   "event": {
#     "actor": "billing-agent",
#     "purpose": "billing-inquiry",
#     "subject_ids": ["user-42"]
#   },
#   "consent_grant": {
#     "classification_max": 1
#   }
# }

package aevum.policies.hipaa.minimum_necessary

import rego.v1

# HIPAA-permitted disclosure purposes (illustrative — not exhaustive)
# Actual permitted purposes depend on your covered entity agreements
permitted_purposes := {
    "treatment",
    "payment",
    "healthcare-operations",
    "care-coordination",
    "billing-inquiry",
    "clinical-review",
    "public-health-reporting",
    "research-with-waiver",
}

default minimum_necessary := false

minimum_necessary if {
    input.event.actor != ""
    permitted_purposes[input.event.purpose]
    not wildcard_access
}

# Wildcard access = querying all subjects (empty subject_ids list)
wildcard_access if {
    count(input.event.subject_ids) == 0
}

violations contains "purpose_not_permitted" if {
    not permitted_purposes[input.event.purpose]
}

violations contains "actor_missing" if {
    not input.event.actor
}

violations contains "wildcard_subject_access_prohibited" if {
    wildcard_access
}

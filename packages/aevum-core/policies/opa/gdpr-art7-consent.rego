# SPDX-License-Identifier: Apache-2.0
#
# Reference policy — GDPR Article 7 consent conditions
# Regulation: GDPR Article 7 (Regulation (EU) 2016/679)
#
# WARNING: Reference example only. Not legal advice.
# Consult qualified legal counsel before production deployment.
#
# Expected input shape:
# {
#   "consent_grant": {
#     "subject_id": "user-42",
#     "grantee_id": "billing-agent",
#     "purpose": "billing-inquiry",
#     "granted_at": "2026-01-01T00:00:00Z",
#     "expires_at": "2027-01-01T00:00:00Z"
#   }
# }

package aevum.policies.gdpr.art7

import rego.v1

# Art. 7(1): consent must be freely given, specific, informed, unambiguous
# Art. 7(3): withdrawal must be as easy as giving consent
#             (Aevum's OR-Set revocation model satisfies this requirement)

# Generic purpose strings that do not satisfy Art. 7(1) specificity
forbidden_purposes := {
    "any", "all purposes", "general", "all", "everything", ""
}

default consent_valid := false

consent_valid if {
    count(missing_fields) == 0
    not forbidden_purposes[lower(input.consent_grant.purpose)]
}

missing_fields contains "subject_id" if {
    not input.consent_grant.subject_id
}

missing_fields contains "grantee_id" if {
    not input.consent_grant.grantee_id
}

missing_fields contains "purpose_missing_or_generic" if {
    forbidden_purposes[lower(input.consent_grant.purpose)]
}

missing_fields contains "granted_at" if {
    not input.consent_grant.granted_at
}

missing_fields contains "expires_at" if {
    # Explicit expiry supports Art. 7(3) withdrawal requirement
    not input.consent_grant.expires_at
}

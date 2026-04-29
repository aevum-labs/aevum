# Aevum infrastructure policy
# Evaluated by OPA sidecar at: POST /v1/data/aevum/authz/allow
#
# This policy controls actor-level access. Consent decisions (which subjects
# have granted consent for which operations) are handled by Cedar inside
# aevum-core and are not duplicated here.
#
# Extend this policy to add role-based access, time-of-day restrictions,
# environment-aware rules, or rate-limiting triggers.

package aevum.authz

import future.keywords.if
import future.keywords.in

# Default: deny all. Requests must match an explicit permit rule.
default allow := false

# Permit authenticated actors to call any of the five governed functions.
# Replace this with your organisation's access control requirements.
allow if {
    input.principal != ""
    input.action in {"ingest", "query", "review", "commit", "replay"}
}

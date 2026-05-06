# Reference example only. Legal review required before production use.
# FDA 21 CFR Part 11 — Electronic Records and Electronic Signatures
# §11.10(e): secure, computer-generated, time-stamped audit trails that
# independently record the date and time of operator entries and actions
# that create, modify, or delete electronic records.

package aevum.policy.fda_21cfr_part11

import rego.v1

# §11.10(e): audit trail must be computer-generated (not user-authored)
# Satisfied by kernel design: users cannot write directly to the sigchain.

# §11.10(e): "independently record" — requires signing key outside operator scope
# This rule checks the session.start key_provenance declaration.
deny contains msg if {
    input.session.payload.key_provenance == "in-process"
    input.context.regulated_deployment == true
    msg := "FDA 21 CFR §11.10(e): in-process signer does not satisfy 'independently record' for regulated deployments. Use VaultTransitSigner or equivalent."
}

# §11.10(e): time-stamped
deny contains msg if {
    not input.event.valid_from
    msg := "FDA 21 CFR §11.10(e): event missing valid_from timestamp"
}

deny contains msg if {
    not input.event.system_time
    msg := "FDA 21 CFR §11.10(e): event missing system_time (HLC) timestamp"
}

# §11.10(c): generate accurate and complete copies of records
# Satisfied by sigchain export + reference verifier.

# §11.10(k): use of controls to ensure authenticity and integrity
# Satisfied by Ed25519 signature per event.

allow if {
    count(deny) == 0
}

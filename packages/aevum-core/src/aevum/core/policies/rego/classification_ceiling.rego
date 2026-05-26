# PARITY: This policy must produce identical permit/deny decisions
# to the Cedar policy in packages/aevum-core/src/aevum/core/policies/barriers.cedar
# (Barrier 3 — Classification Ceiling).
# If the Cedar policy changes, update this Rego immediately.
# Run: uv run pytest tests/test_policy_parity.py to verify parity.
package aevum.classification_ceiling

# Permit when data classification does not exceed the ceiling.
# classification and ceiling are integers: 0=public, 1=internal, 2=confidential, 3=restricted

default allow := false

allow if {
    input.context.classification <= input.context.ceiling
}

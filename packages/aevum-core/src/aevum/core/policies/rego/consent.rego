# PARITY: This policy must produce identical permit/deny decisions
# to the Cedar policy in packages/aevum-core/src/aevum/core/policies/barriers.cedar
# (Barrier 2 — Consent) and the _CEDAR_POLICY in bridge.py.
# If the Cedar policy changes, update this Rego immediately.
# Run: uv run pytest tests/test_policy_parity.py to verify parity.
package aevum.consent

# Mirrors the Cedar consent policy in bridge.py _CEDAR_POLICY.
# Permit when: grant active, purpose specific, classification within ceiling.

default allow := false

allow if {
    input.context.grant_active == true
    input.context.purpose_specific == true
    input.context.classification_ok == true
}

# Explicit denials (fast-path) — match bridge.py evaluate_consent() logic
deny if { input.context.grant_active == false }
deny if { input.context.classification_ok == false }
deny if { input.context.purpose_specific == false }

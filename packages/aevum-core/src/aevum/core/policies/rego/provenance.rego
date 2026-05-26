# PARITY: This policy must produce identical permit/deny decisions
# to the Cedar policy in packages/aevum-core/src/aevum/core/policies/barriers.cedar
# (Barrier 5 — Provenance) and check_provenance() in barriers.py.
# If the Cedar policy changes, update this Rego immediately.
# Run: uv run pytest tests/test_policy_parity.py to verify parity.
package aevum.provenance

# Permit when the event has a verifiable prior_hash (not zero-hash).
# The zero hash is the genesis sentinel — all other events must chain.

_ZERO_HASH := "0000000000000000000000000000000000000000000000000000000000000000"

default allow := false

# Genesis event (sequence == 0): prior_hash == zero-hash is valid
allow if {
    input.context.sequence == 0
}

# Non-genesis: prior_hash must be non-empty and not the zero-hash
allow if {
    input.context.sequence > 0
    input.context.prior_hash != ""
    input.context.prior_hash != _ZERO_HASH
}

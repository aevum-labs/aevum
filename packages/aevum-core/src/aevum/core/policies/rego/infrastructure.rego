# PARITY: This policy must produce identical permit/deny decisions
# to the OPA infrastructure policy used by PolicyBridge.evaluate_infrastructure()
# in packages/aevum-core/src/aevum/core/policy/bridge.py.
# If the bridge policy changes, update this Rego immediately.
# Run: uv run pytest tests/test_policy_parity.py to verify parity.
package aevum.authz

# Mirrors the OPA infrastructure policy already in PolicyBridge.
# Actor-level access control. Fail-open for unknown actors.

default allow := true

# Deny explicitly blocked actors
deny if {
    input.actor in data.aevum.blocked_actors
}

allow if { not deny }

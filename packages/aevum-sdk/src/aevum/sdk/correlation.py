"""
aevum.sdk.correlation — Multi-agent episode correlation utilities.

Provides helpers for propagating episode_id across agent boundaries
using W3C Trace Context (traceparent header) and constructing
cross-chain causal references (cross_chain_ref payload field).

ADR-008 implementation. See docs/adrs/adr-008-multi-agent-correlation.md.

These are pure utility functions — no Engine, no Sigchain, no I/O.
They can be called in any context without side effects.

W3C Trace Context format:
    traceparent: {version}-{trace-id}-{parent-id}-{flags}
    version:     2 hex chars (always "00")
    trace-id:    32 hex chars (128 bits) — maps to episode_id
    parent-id:   16 hex chars (64 bits)  — maps to span_id
    flags:       2 hex chars (usually "01" = sampled)

Example:
    traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    episode_id:  "4bf92f3577b34da6a3ce929d0e0e4736"
    span_id:     "00f067aa0ba902b7"
"""

from __future__ import annotations

import hashlib
import json
import os
import re

# W3C Trace Context traceparent pattern
# version-trace_id-parent_id-flags
_TRACEPARENT_RE = re.compile(
    r"^([0-9a-f]{2})"        # version
    r"-([0-9a-f]{32})"       # trace-id (32 hex = 128 bits)
    r"-([0-9a-f]{16})"       # parent-id (16 hex = 64 bits)
    r"-([0-9a-f]{2})$"       # flags
)


def extract_episode_id_from_traceparent(header: str) -> str | None:
    """
    Extract the episode_id from an incoming W3C traceparent header.

    The trace-id component (32 hex chars) is used as the episode_id,
    enabling all events in a multi-agent workflow to share the same
    episode_id regardless of which agent produced them.

    Returns None if the header is absent, malformed, or uses an
    unsupported version (not "00").

    Usage (receiving an A2A call):
        episode_id = extract_episode_id_from_traceparent(
            request.headers.get("traceparent", "")
        )
        engine.ingest(..., episode_id=episode_id or str(uuid.uuid4()))

    Args:
        header: The raw traceparent header value, or empty string.

    Returns:
        32-char lowercase hex trace-id string, or None.
    """
    if not header:
        return None

    m = _TRACEPARENT_RE.match(header.strip().lower())
    if not m:
        return None

    version, trace_id, _parent_id, _flags = m.groups()

    # Version "ff" is reserved; "00" is the only currently specified version.
    # Accept any non-ff version for forward compatibility.
    if version == "ff":
        return None

    # All-zero trace-id is invalid per W3C spec
    if trace_id == "0" * 32:
        return None

    return trace_id


def inject_traceparent(
    episode_id: str,
    parent_span_id: str | None = None,
    flags: str = "01",
) -> str:
    """
    Build a W3C traceparent header for an outgoing A2A call.

    Propagates the current agent's episode_id to downstream agents,
    so they can correlate their audit events to the same episode.

    The episode_id is used as the trace-id component. A new parent-id
    is generated if not provided.

    Usage (making an A2A call):
        headers = {
            "traceparent": inject_traceparent(episode_id),
            "Content-Type": "application/json",
        }

    Args:
        episode_id:     The current episode's ID (must be 32 hex chars,
                        or any string that will be padded/hashed to 32 hex).
        parent_span_id: Optional 16-hex-char span ID. If None, generated
                        from os.urandom(8).
        flags:          2-hex-char flags byte. "01" = sampled (default).
                        "00" = not sampled (suppresses downstream tracing).

    Returns:
        A valid W3C traceparent header string.

    Raises:
        ValueError if flags is not exactly 2 hex chars.
    """
    if not re.match(r"^[0-9a-f]{2}$", flags.lower()):
        raise ValueError(
            f"flags must be exactly 2 lowercase hex chars, got {flags!r}"
        )

    # Normalise episode_id to 32 hex chars
    trace_id = _normalise_to_trace_id(episode_id)

    # Generate parent-id if not provided
    if parent_span_id is None:
        parent_span_id = os.urandom(8).hex()
    else:
        parent_span_id = parent_span_id.lower()
        if not re.match(r"^[0-9a-f]{16}$", parent_span_id):
            raise ValueError(
                f"parent_span_id must be exactly 16 lowercase hex chars, "
                f"got {parent_span_id!r}"
            )

    return f"00-{trace_id}-{parent_span_id}-{flags.lower()}"


def build_cross_chain_ref(
    event: dict[str, object],
    trust_domain: str,
    agent_id: str,
) -> dict[str, object]:
    """
    Build a cross_chain_ref payload dict from an event in another agent's chain.

    The cross_chain_ref is placed in an AuditEvent's payload to record
    an explicit causal link to an event in a different agent's sigchain.
    Unlike causation_id (within-chain only), cross_chain_ref spans chains.

    The event_hash allows a verifier to confirm the referenced event exists
    and was not tampered with — provided the verifier has access to the
    other chain (e.g., via aevum-publish Rekor checkpoints).

    Usage:
        # When Agent B receives a task from Agent A:
        ref = build_cross_chain_ref(
            event=agent_a_last_event,  # the event that triggered this task
            trust_domain="spiffe://example.org",
            agent_id="billing-agent",
        )
        engine.ingest(
            data=task_data,
            payload_extra={"cross_chain_ref": ref},  # or however payload is built
            ...
        )

    Args:
        event:        An event dict (as returned by get_ledger_entries()) from
                      the OTHER agent's chain. Must have: episode_id, system_time,
                      sequence, event_id (all standard AuditEvent fields).
        trust_domain: The SPIFFE trust domain of the referenced agent (e.g.
                      "spiffe://example.org"). Use "" if SPIFFE not available.
        agent_id:     A stable identifier for the referenced agent. Can be
                      the SPIFFE SVID path, a hostname, or any stable string.

    Returns:
        A dict suitable for use as the cross_chain_ref payload field:
        {
            "trust_domain": str,
            "agent_id": str,
            "episode_id": str,
            "system_time": int,
            "event_hash": str,   # SHA3-256 hex of the signing fields
        }
    """
    event_hash = _compute_event_hash(event)
    return {
        "trust_domain": trust_domain,
        "agent_id": agent_id,
        "episode_id": event.get("episode_id", ""),
        "system_time": event.get("system_time", 0),
        "event_hash": event_hash,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

# Signing fields — must match aevum-signing-v1.md exactly
_SIGNING_FIELDS = (
    "actor",
    "causation_id",
    "correlation_id",
    "episode_id",
    "event_id",
    "event_type",
    "payload_hash",
    "prior_hash",
    "schema_version",
    "signer_key_id",
    "span_id",
    "system_time",
    "trace_id",
    "valid_from",
    "valid_to",
)


def _compute_event_hash(event: dict[str, object]) -> str:
    """
    Compute the SHA3-256 hex digest of an event's signing fields.

    This matches hash_event_for_chain() in aevum-signing-v1.md:
    SHA3-256 of the JCS-canonical signing-fields object.

    Used in cross_chain_ref to allow verifiers to confirm the referenced
    event exists and matches the claimed content.
    """
    signing_obj = {field: event.get(field) for field in _SIGNING_FIELDS}
    canonical = json.dumps(
        signing_obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha3_256(canonical).hexdigest()


def _normalise_to_trace_id(episode_id: str) -> str:
    """
    Normalise an episode_id to a 32-hex-char trace-id.

    - If already 32 hex chars: use as-is (lowercase)
    - If a UUID (with hyphens): strip hyphens, use the 32 hex chars
    - Otherwise: take SHA3-256 of the string, use first 32 hex chars
      (lossy but deterministic — the same episode_id always produces
      the same trace-id)
    """
    candidate = episode_id.lower().replace("-", "")
    if re.match(r"^[0-9a-f]{32}$", candidate):
        return candidate

    # Non-hex or wrong length: hash it
    digest = hashlib.sha3_256(episode_id.encode("utf-8")).hexdigest()
    return digest[:32]

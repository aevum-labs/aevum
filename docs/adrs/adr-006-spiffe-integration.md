# ADR-006: SPIFFE/SPIRE integration for cryptographic agent identity

Date: 2026-05-06
Status: Proposed
Deciders: Aevum Labs
Confidence: Medium

## Context and Problem Statement

The `actor` field in AuditEvents is a caller-provided string. It is authenticated
only to the degree that the deployment trusts the caller — there is no
cryptographic binding between `actor = "billing-agent"` and a verified identity
attestation. For multi-agent systems where trust boundaries matter, this is
insufficient.

OWASP ASI03 (Identity and Privilege Abuse) recommends ephemeral credentials
and least-privilege identity. NIST AI RMF GOVERN 4.3 requires accountability
documentation that includes actor identity. EU AI Act Art. 12(2)(b) requires
logs to enable identification of persons responsible for operation — which implies
the `actor` field must be reliable.

SPIFFE (Secure Production Identity Framework for Everyone) provides
cryptographically-attested workload identity via SVIDs (SPIFFE Verifiable
Identity Documents). A JWT-SVID can be fetched from the local SPIFFE Workload
API at Engine startup without any network call to a remote authority at
event-write time — which is critical for low-latency, high-throughput audit.

## Decision Drivers

- EU AI Act Art. 12(2)(b): identify persons responsible for operation
- OWASP ASI03: cryptographic identity, not caller-asserted strings
- NIST AI RMF GOVERN 4.3: accountability documentation
- Performance: identity attestation must not add per-event latency
- Optionality: deployments without SPIRE must still work without code changes

## Considered Options

1. **py-spiffe JWT-SVID at session start (this decision)**
2. OIDC token `sub` claim as actor identity
3. Static agent ID in environment variable
4. No identity — caller-asserted `actor` only (current behaviour)

**Option 1** — Fetch a JWT-SVID from the SPIFFE Workload API at Engine startup.
Record the SPIFFE ID (e.g., `spiffe://example.org/billing-agent`) in:
(a) the `session.start` payload as `agent_spiffe_id`; (b) every subsequent
AuditEvent payload as `actor_spiffe_id`. The full SVID (signed JWT) is recorded
in `session.start` for offline verification. Subsequent events record only the
SPIFFE ID string — not the full SVID — to avoid per-event size overhead.
Library: `py-spiffe` 0.2.3 (PyPI `spiffe`, HewlettPackard/py-spiffe, Apache-2.0),
providing `WorkloadApiClient.fetch_jwt_svid(audience=...)`.

**Option 2** — Use an OIDC access token's `sub` claim as actor identity. Simpler
to deploy (no SPIRE required), but tokens expire and must be refreshed, and the
issuer must be validated. `aevum-oidc` already handles OIDC for user
authentication — conflating agent-to-kernel identity with user authentication
would couple two unrelated concerns.

**Option 3** — Set `AEVUM_AGENT_ID=spiffe://example.org/billing-agent` and
record it as a trusted identity claim. Simple, but entirely caller-asserted —
provides no cryptographic attestation. Worse than Option 1 without SPIRE
installed.

**Option 4** — Current behaviour. Sufficient for single-process deployments where
trust is implicit. Insufficient for multi-agent systems with distinct trust
domains.

## Decision Outcome

Option 1 for deployments with SPIRE. Option 4 as the default
(backwards-compatible) when `aevum-spiffe` is not installed.

The implementation is a new optional package `aevum-spiffe` that registers as a
complication with the Engine via `Engine.install_complication()`. When installed
and approved, it:

1. At `Engine.__init__()` completion, fetches a JWT-SVID from the SPIFFE Workload
   API (default socket: `unix:///tmp/spire-agent/public/api.sock`)
2. Emits a `spiffe.attested` AuditEvent with `agent_spiffe_id` and `agent_svid`
   in the payload (supplemental to `session.start`, which is written before
   complications run)
3. Provides a helper callable that downstream event builders can invoke to add
   `actor_spiffe_id` to their payload dict before passing it to the kernel

The complication does NOT modify the `actor` field — the human-readable actor
string is preserved. The SPIFFE ID is an additional, cryptographically verifiable
identity claim in the payload.

### Authorised Part 2 code scope

- New package: `packages/aevum-spiffe/`
- Import path: `aevum.spiffe`
- Core class: `SpiffeComplication` implementing the complication manifest protocol
- No changes to `aevum-core`, `aevum-server`, `aevum-store-*`, or `aevum-cli`
- No new fields on `AuditEvent` model (`AuditEvent.payload` is an open `dict`)
- The `spiffe.attested` event carries the SVID; the `session.start` event is not
  modified (its payload is assembled before `install_complication()` is called)

### Consequences

**Good:** OWASP ASI03 coverage; backwards-compatible (non-SPIFFE deployments
unaffected); per-event overhead is a string copy only, not a crypto operation;
offline verification of the SVID in `spiffe.attested` confirms identity at
chain-read time.

**Bad:** Requires SPIRE or a compatible SPIFFE Workload API (Vault SPIFFE secrets
engine, KUDO, etc.); `py-spiffe` is HP-maintained, not an official CNCF project —
maintenance-bus risk.

**Residual risk:** (a) **HP maintenance risk**: if HewlettPackard deprecates
`py-spiffe` without a CNCF successor, Aevum must fork or switch; the complication
architecture isolates this — `aevum-core` has no `py-spiffe` import. (b) **SVID
expiry**: JWT-SVIDs have a TTL (typically 1 hour); long-running Engine instances
must refresh via `JwtSource` automatic renewal — `aevum-spiffe` must implement
renewal. (c) **Socket unavailability**: if the Workload API socket is absent at
startup, the complication must fail gracefully (log warning, continue without
SPIFFE ID) rather than preventing Engine startup.

## Library versions

| Library | PyPI name | License | Version |
|---------|-----------|---------|---------|
| py-spiffe | `spiffe` | Apache-2.0 | 0.2.3 (Jan 2026) |
| py-spiffe-tls | `spiffe-tls` | Apache-2.0 | 0.3.1 (Mar 2026) |

## Related ADRs

- ADR-001 (Single sigchain — the chain `spiffe.attested` writes into)
- ADR-004 (Signer interface — analogous optional-external-trust pattern)
- ADR-008 (Multi-agent correlation — `cross_chain_ref.trust_domain` uses SPIFFE ID)

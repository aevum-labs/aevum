# aevum-spiffe

SPIFFE/SPIRE agent identity complication for Aevum.

Provides cryptographically-attested agent identity via JWT-SVIDs from the
SPIFFE Workload API. When `on_approved()` is called, emits a `spiffe.attested`
AuditEvent recording the SPIFFE ID and SVID metadata in the sigchain.

Requires SPIRE or a compatible SPIFFE Workload API (Vault SPIFFE secrets
engine, KUDO, etc.) to be running at attestation time.

```bash
pip install aevum-spiffe[spiffe]
```

```python
from aevum.core import Engine
from aevum.spiffe import SpiffeComplication

engine = Engine()
comp = SpiffeComplication(
    socket_path="unix:///run/spire/sockets/agent.sock",  # optional
    audience=["aevum"],                                   # optional
)
engine.install_complication(comp)
engine.approve_complication("aevum-spiffe")
comp.on_approved(engine)   # emits spiffe.attested into the sigchain
```

The chain now contains a signed `spiffe.attested` event:

```json
{
  "event_type": "spiffe.attested",
  "actor": "aevum-spiffe",
  "payload": {
    "spiffe_id": "spiffe://example.org/billing-agent",
    "trust_domain": "example.org",
    "audience": ["aevum"],
    "svid_type": "jwt",
    "source": "workload-api",
    "socket": "unix:///run/spire/sockets/agent.sock",
    "expiry": "2026-05-06T15:00:00+00:00"
  }
}
```

## Lifecycle note

The Aevum Engine does not call lifecycle hooks automatically at approval time.
After `engine.approve_complication("aevum-spiffe")`, callers must invoke
`comp.on_approved(engine)` explicitly to trigger attestation. This is the
correct pattern for all complications that need to act at approval time.

## Downstream use

Other complications can read the attested SPIFFE ID:

```python
spiffe_comp = engine.get_active_complication_by_capability("spiffe-identity")
spiffe_id = spiffe_comp.get_actor_spiffe_id() if spiffe_comp else None
payload = {"actor_spiffe_id": spiffe_id, ...}
```

## Without SPIRE

If the SPIFFE socket is unavailable or py-spiffe is not installed,
`on_approved()` logs a warning and continues without attestation.
Engine startup is never blocked.

## Trust boundary

The SPIFFE ID in the `spiffe.attested` event is cryptographically attested
by SPIRE's attestation plugins. It is NOT caller-asserted (unlike the `actor`
field). An auditor can verify the attestation by checking the SVID's parent
trust chain against the SPIFFE trust bundle.

The JWT token itself is NOT stored in the AuditEvent — it expires (typically
1 hour) and is large. Only the SPIFFE ID string and metadata are recorded.

## See also

- [ADR-006: SPIFFE integration](../../docs/adrs/adr-006-spiffe-integration.md)
- [py-spiffe](https://github.com/HewlettPackard/py-spiffe)
- [SPIFFE specification](https://spiffe.io)

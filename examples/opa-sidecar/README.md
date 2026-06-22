# OPA sidecar example

Runnable deployment showing Aevum's policy layer with both engines active:
Cedar in-process for entity ABAC, and an OPA sidecar for content/infrastructure
policy. See [`docs/spec/09-policy.md`](../../docs/spec/09-policy.md) for the
architecture this demonstrates.

## Run it

```bash
cd examples/opa-sidecar
docker compose up
```

- Aevum server: http://localhost:8000
- OPA policy server: http://localhost:8181

`docker-compose.yml` wires `AEVUM_OPA_URL` to the OPA sidecar. `policy/authz.rego`
holds the actor-level access policy OPA evaluates on every request; Cedar
(inside `aevum-core`) continues to handle consent decisions independently.
Both engines must permit a request for it to proceed.

# Aevum Reference Policy Bundles

Example OPA (Rego) and Cedar policies demonstrating how Aevum's stable
enforcement primitives can be combined with swappable policy definitions.

This is the architectural answer to regulatory churn: Aevum's five barriers
and sigchain do not change when a new regulation lands. The *policies* below
do. Updating a `.rego` or `.cedar` file requires no code change.

## ⚠️ Important disclaimer

These files are **reference examples only**. They illustrate the
architectural pattern — they are not legal compliance advice and have not
been reviewed by qualified legal counsel. Production compliance programs
must be developed with appropriate legal and regulatory expertise.

## Files

| File | Regulation | Standard |
|---|---|---|
| `opa/eu-ai-act-art12.rego` | EU AI Act Article 12 | Record-keeping posture |
| `opa/gdpr-art7-consent.rego` | GDPR Article 7 | Consent conditions |
| `opa/hipaa-minimum-necessary.rego` | 45 CFR § 164.502(b) | Minimum necessary |
| `cedar/eu-ai-act-art12.cedar` | EU AI Act Article 12 | Cedar equivalent |

## Usage with OPA

```bash
opa eval -d policies/opa/eu-ai-act-art12.rego \
         -i input.json \
         "data.aevum.policies.eu_ai_act.art12.allow"
```

## Usage with Cedar

Cedar policies are evaluated by the aevum-core PolicyBridge when
`policy_engine: cedar` is configured. Place `.cedar` files in your
policy bundle directory.

## Architecture note

Aevum's five absolute barriers fire regardless of policy. Policies add
*additional* constraints; they cannot disable barriers.

# Aevum FOQA De-Identification Specification

Version: 0.1
Date: 2026-05-25
Modeled on: FAA AC 120-82 (April 2004)
Status: Active

---

## 1. Purpose

This specification defines the de-identification requirements for Aevum
FOQA (Flight Operational Quality Assurance equivalent) data before it
leaves operator premises toward any analytics backend or regulator.

Aevum's FOQA layer aggregates AI agent operational data for safety analysis,
analogous to how aviation FOQA programs aggregate flight data to identify
trends without identifying specific crews or flights. The institutional
design from FAA AC 120-82 is preserved: a designated gatekeeper holds the
linking key that allows de-identified data to be re-linked to specific sessions.

---

## 2. The Gatekeeper Role

The gatekeeper role is defined by analogy to FAA AC 120-82 Section 5.

**Definition:** The gatekeeper is the individual designated by the operator
who holds the `gatekeeper_key` that allows pseudonymized FOQA data to be
associated with a specific agent session or agent identity.

**Structural requirements:**
- The gatekeeper MUST be held outside of management reporting chains. The
  gatekeeper cannot be the same person who deploys, manages, or directs
  the AI agents whose data is being collected.
- The `gatekeeper_key` MUST be stored in a hardware security module (HSM),
  HashiCorp Vault, AWS KMS, or equivalent secret manager.
- Access to the `gatekeeper_key` MUST be logged and audited separately from
  the FOQA data itself.
- The `gatekeeper_key` is NOT the same as the Aevum Ed25519 signing key.
- The `gatekeeper_key` MUST NOT be logged, transmitted in plaintext, or
  committed to version control.

**Re-linking authority:** The gatekeeper is the only individual who may
re-link pseudonymized session data to a specific session or agent, and only
for legitimate safety investigation purposes. Re-linking for performance
management, disciplinary action, or commercial purposes is prohibited.

---

## 3. Fields Stripped Before Export

The following fields are stripped from all FOQA export data. They must never
appear in aggregate telemetry, metrics, or reports sent outside operator premises.

| Field | Reason |
|---|---|
| `prompt_text` | Raw prompt content; potentially identifies individuals or contains PII |
| `response_text` | Raw model output; potentially identifies individuals or contains PII |
| `user_id` | Direct user identifier (GDPR Art. 4 personal data) |
| `user_email` | Direct user identifier |
| `user_name` | Direct user identifier |
| `ip_address` | Network identifier; indirect personal data (GDPR) |
| `raw_input` | Unprocessed input; may contain PII |
| `raw_output` | Unprocessed output; may contain PII |
| `session_id` (exact) | Replaced with pseudonym; exact ID enables re-identification |
| `agent_id` (exact) | Replaced with pseudonym; exact ID enables re-identification |

Additionally, any field whose key contains the strings "user", "email", "name",
"ip", "phone", or "address" (case-insensitive) is treated as potentially
identifying and stripped from attribute dictionaries before export.

---

## 4. Pseudonymization Method

All identifiers (session_id, agent_id) are pseudonymized before any data
leaves the per-session ExceedanceDetector and enters the FOQABridge.

**Algorithm:** HMAC-SHA256

```
pseudonym = "anon-" + HMAC-SHA256(identifier, gatekeeper_key).hexdigest()[:16]
```

**Properties:**
- **Deterministic:** The same identifier always produces the same pseudonym
  under a given key. This allows counting distinct sessions without storing
  raw identifiers.
- **Irreversible without the key:** HMAC-SHA256 is a one-way function. An
  attacker without the `gatekeeper_key` cannot recover the original identifier
  from the pseudonym.
- **Key-dependent:** Different keys produce different pseudonyms for the same
  identifier. Rotating the key breaks all existing pseudonym mappings.

**Key generation:**

```sh
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

Set the result as `AEVUM_GATEKEEPER_KEY_HEX` in your secure secret store.
Never store this value in application configuration files or environment files
committed to version control.

---

## 5. Re-Linking Procedure

The gatekeeper can re-link a pseudonymized identifier to its original value
by searching the known identifier space:

1. Obtain the `gatekeeper_key` from the HSM/Vault (audit this access).
2. For a given pseudonym `"anon-XXXX"`:
   - Iterate over candidate identifiers from the session registry.
   - Compute `HMAC-SHA256(candidate, gatekeeper_key).hexdigest()[:16]`.
   - If the result equals `XXXX`, the candidate is the original identifier.
3. Log the re-linking operation with: timestamp, re-linker identity, pseudonym,
   recovered identifier, and stated purpose.
4. Restrict the recovered identifier to the safety investigation. Do not
   propagate it to management or commercial systems.

---

## 6. What Aggregate Data MAY Be Exported (De-Identified)

The following data categories may be exported to operator analytics dashboards
or regulator-facing aggregate reports after de-identification:

- **Exceedance counts by type** (`aevum.exceedance.count` metric): How many
  EX-01 through EX-15 events occurred, broken down by exceedance_id and severity.
- **Session counts** (`aevum.session.count`): Total number of agent sessions
  observed by the FOQA bridge.
- **Severity distribution:** Aggregate counts by severity level (LOW/MEDIUM/HIGH/CRITICAL).
- **Temporal trends:** Exceedance counts over time windows (hour, day, week),
  without session-level detail.

---

## 7. What MUST NOT Be Exported (Even De-Identified)

The following data categories must not be exported outside operator premises,
even in de-identified form:

- **Individual session-level exceedance events:** Only aggregate counts are
  exported. The full ExceedanceEvent (including pseudonymized session_id) stays
  on-premises.
- **Any prompt or response text:** Including hashes of prompt text that could
  serve as de-facto identifiers.
- **Model weights or fine-tuning data:** Not FOQA-relevant and potentially
  proprietary.
- **Any field that would allow re-identification without the gatekeeper_key:**
  This includes high-cardinality attributes (even pseudonymized) that can be
  correlated with external session timing data.

**Note on pseudonymized session_id in metrics:** A pseudonymized session_id
in an OTel metric is intentionally NOT emitted, even in filtered form. A
high-cardinality metric attribute (one value per session) can be correlated
with external session timing data to re-identify sessions without the
gatekeeper_key. Aggregates only means: count, not "which sessions."

---

## 8. Regulatory Mapping

| Regulation | Requirement | How FOQA De-ID Satisfies It |
|---|---|---|
| EU AI Act Art. 72 | Post-market monitoring for high-risk AI systems | Aggregate exceedance metrics satisfy the monitoring requirement without exposing individual session data |
| GDPR Art. 5(1)(e) | Storage limitation — personal data retained only as long as necessary | De-identified aggregate data is no longer personal data (GDPR Recital 26) and can be retained longer than the raw session data |
| GDPR Art. 4 | Definition of personal data | Pseudonymized data with a retained key is still personal data; data without any re-linking capability is not. The gatekeeper model keeps the key controlled. |
| FAA AC 120-82 | FOQA gatekeeper role — voluntary safety reporting protection | The gatekeeper model directly mirrors AC 120-82's institutional design |
| 49 U.S.C. § 40123 | Whistleblower protection for voluntary safety data | No direct AI equivalent yet. Advocate for equivalent protections at NIST AI Safety Institute and EU AI Office. |

---

## 9. Implementation Reference

| Class | Module | Role |
|---|---|---|
| `GatekeeperFilter` | `aevum.otel.gatekeeper` | De-identification via HMAC pseudonymization |
| `ExceedanceDetector` | `aevum.core.exceedance` | Per-session exceedance detection |
| `FOQABridge` | `aevum.otel.foqa_bridge` | OTel aggregate metric emission |

The `GatekeeperFilter` will raise `RuntimeError` without a key — there is no
dev-mode bypass. A de-identification filter that operates without a key provides
no protection and invalidates the FOQA export guarantee.

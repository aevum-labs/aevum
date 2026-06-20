# Aevum Signing Specification — v2 (Principal Binding)

*This specification extends [aevum-signing-v1.md](aevum-signing-v1.md) with
`sig_format_version = 2`: three additive, nullable signed fields that bind an
AuditEvent to a verified external credential identity without ever writing
that identity to the chain in the clear. Everything in v1 not explicitly
overridden here — hybrid (ML-DSA-65) signing, the hash-chain/genesis
construction, the Merkle/STH verifiable-log layer, the trust model — is
unchanged and is not repeated.*

---

## Overview

v1 binds every signed event to `actor` — a string naming the role, service
account, or component that caused the event (e.g. `"aevum-demo"`,
`"aevum-core"`). `actor` is useful for accountability within a deployment but
is not, by itself, a verifiable claim about *which external, authenticated
principal* (an OIDC subject, a SPIFFE ID, a DID) was behind that actor at the
time.

P2-IDENTITY-V2 adds an optional second binding, orthogonal to `actor`: a
commitment to a bound **credential identity**, computed so that:

- the raw identity never appears anywhere in the signed event or the chain
  (only an HMAC commitment does — DD1);
- verifying the chain's integrity never requires the commitment key (DD6) —
  the three new fields are opaque signed bytes to the verifier, exactly like
  `payload_hash` is opaque to a verifier without the original payload;
- a single chain may freely span `sig_format_version = 1` then `2` (DD4); the
  version may never *decrease* across a chain, which makes a downgrade or
  splice attack structurally detectable;
- the three new fields are nullable even within a `sig_format_version = 2`
  entry (DD2) — opting into v2 does not require every entry to carry a
  principal binding.

This document defines the v2 signing-field set, the construction of the two
new derived values (`principal_binding`, `principal_commitment`), the
per-entry version-dispatch rule, and the verification procedure changes. The
companion `CommitmentKeyStore` module (DD5, DD8) is documented in its own
docstring (`aevum.core.audit.commitment_key_store`) and summarized here for
context.

---

## Design decisions (DD1–DD8)

| | Decision |
|---|---|
| DD1 | `principal_commitment` is an HMAC over the bound **credential** identity (OIDC `sub` / SPIFFE ID / DID) — never over `actor`. The two name different things: `actor` is a role/service-account label; the credential identity is a specific external, authenticated principal. |
| DD2 | The three new fields are nullable even within a `sig_format_version = 2` entry — a v2 entry with no external credential to bind has all three as `null`. |
| DD3 | `DOMAIN_PREFIX` (`b"aevum-sigchain-v1\x00"`) is unchanged. Version separation is handled entirely by the signed `sig_format_version` field. Stripping the v2 fields to forge a v1 entry (or relabeling a v1 entry as v2) changes the canonical byte representation and breaks the Ed25519 signature — no downgrade/relabel attack is possible without the private key. |
| DD4 | Verification dispatches **per entry** on that entry's own `sig_format_version`. A single chain may legitimately span v1 then v2. `sig_format_version` must never *decrease* across a chain — a decrease is the fingerprint of a downgrade or splice attack and is rejected outright. |
| DD5 | A commitment key is deployment/scope-grained, not per-principal. Destroying a key erases the ability to confirm or re-derive *every* `principal_commitment` computed under it — a coarse, all-or-nothing erasure. Per-principal granularity is a possible future refinement that needs no signed-format change. |
| DD6 | Chain verification (`verify_chain` / `verify_entry`) never calls into `CommitmentKeyStore` and takes no commitment-key parameter. `principal_commitment` is opaque signed bytes to the verifier; only identity-*matching* (confirming which external credential produced a given commitment) needs the key, and that is a separate operation from chain verification. |
| DD7 | `principal_binding` is built by **allow-list** extraction, never a deny-list: only `iss`, `aud`, `jti`, `iat`, `exp`, and `cnf.jkt` may survive. The raw subject (`sub`) and any bearer-token-shaped claim are structurally excluded regardless of what the caller passes in — there is no key under which a bearer token or raw `sub` can appear in the blob. |
| DD8 | `CommitmentKeyStore`'s vocabulary (`scope` / `principal` / `commitment_key_id`) is deliberately disjoint from `ConsentLedger`'s vocabulary (`subject`). They look structurally similar (SQLite, `secure_delete=ON`, crypto-shred on destroy) but name different concepts — see `KNOWN_UNKNOWNS.md` for the two-"subject" distinction. |

---

## Signing Fields (v2)

A `sig_format_version = 2` entry signs the same 19 fields as v1
(see [aevum-signing-v1.md § Signing Fields](aevum-signing-v1.md#signing-fields))
**plus 3 additional fields, appended in this order**:

```
... (the 19 v1 fields, unchanged) ...
principal_binding
principal_commitment
principal_commitment_key_id
```

RFC 8785 (JCS) sorts object keys by Unicode code point at canonicalization
time, so the *appended order* above does not affect the resulting bytes —
it is documented for readability only. What matters is which keys are
*present*: a `sig_format_version = 1` entry's signing-fields dict has exactly
19 keys; a `sig_format_version = 2` entry's has exactly 22. This difference
in key membership, not just value, is what makes relabeling a v1 entry as v2
(or vice versa) break the signature (DD3) — RFC 8785 canonicalizes the two
key sets to different bytes even before any value changes.

A `sig_format_version = 1` entry never includes the 3 new fields in its
signing-fields dict, even if (hypothetically) non-null values were present on
the dataclass — but `new_event()` only ever sets them to non-null when it
also sets `sig_format_version = 2`, so this case does not arise from normal
construction. It is reachable only via direct dataclass tampering, and
`verify_chain` rejects it (see "Verification Procedure" below).

### New field encodings

| Field | Type in JSON entry | Encoding in signing fields | Present (non-null) when |
|---|---|---|---|
| `principal_binding` | string \| null | string \| null, as-is | `sig_format_version == 2` AND the caller supplied `principal_claims` |
| `principal_commitment` | string \| null | string \| null, as-is | `sig_format_version == 2` AND the caller supplied `principal_identity` + a commitment key |
| `principal_commitment_key_id` | string \| null | string \| null, as-is | `sig_format_version == 2` AND the caller supplied `commitment_key_id` (the v2 opt-in switch) |

`principal_commitment_key_id` is the opt-in switch: supplying it alone (with
no `principal_identity` / `principal_claims`) is sufficient to produce a
`sig_format_version = 2` entry with the other two fields null (DD2). Supplying
`principal_identity` without `commitment_key_id` is a caller error
(`ValueError` — see `Sigchain.new_event`); a chain may not assert a principal
commitment without first opting into v2.

---

## `principal_binding` construction (DD7)

```python
from aevum.core.audit.event import build_principal_binding_blob

blob = build_principal_binding_blob(claims)
```

`claims` is a mapping of already-verified credential claims (e.g. the decoded
body of a validated OIDC ID token). The function:

1. Extracts **only** the keys in the allow-list
   `{"iss", "aud", "jti", "iat", "exp", "cnf"}` — any other key in `claims`,
   including `sub`, `access_token`, `authorization`, `refresh_token`, or
   anything else, is dropped unconditionally. This is allow-list extraction,
   not redaction: there is no code path by which a non-allow-listed key
   reaches the output, regardless of what the caller passes in.
2. If `cnf` is present and is itself a mapping, restricts it further to
   `{"jkt"}` only (RFC 7800 confirmation claim, RFC 7638 JWK thumbprint) —
   the raw proof-of-possession key (`jwk`, `jwe`, `cnf.x5t#S256`, etc.) is
   dropped even when present under the allow-listed `cnf` key.
3. RFC 8785-canonicalizes the extracted dict.
4. Returns `base64url(canonical_bytes)` with padding stripped (`rstrip("=")`)
   — the same encoding convention used for `signature` and `principal_commitment`.

`principal_binding` is `None` when the caller passes no `principal_claims` at
all, or passes claims containing none of the allow-listed keys (extraction of
an empty dict still produces a non-null blob of `"e30"` — base64url of `{}` —
so callers that want a null binding must omit `principal_claims` entirely,
not pass `{}`).

---

## `principal_commitment` construction (DD1, DD6)

```python
from aevum.core.audit.event import compute_principal_commitment

commitment = compute_principal_commitment(commitment_key, principal_identity)
# = base64url(HMAC-SHA256(commitment_key, principal_identity.encode("utf-8"))), no padding
```

- `commitment_key` is 32 bytes, held by a `CommitmentKeyStore` (or any
  32-byte secret — the function itself does not depend on the store).
- `principal_identity` is the bound **credential** identity string (e.g.
  `"urn:example:oidc:sub:alice"`) — never the plaintext `actor` field (DD1).
- The HMAC key never appears in the output; only an investigator who
  separately holds `commitment_key` (out of band, via `CommitmentKeyStore`)
  can confirm that a *specific* candidate identity produced a given
  `principal_commitment`, by recomputing the HMAC and comparing. This is a
  one-way commitment, not an encryption — there is no decryption path back
  to `principal_identity` from `principal_commitment` alone.
- Chain verification (DD6) never calls this function and never needs
  `commitment_key`. The three new fields are integrity-protected (mutating
  any of them breaks the Ed25519 signature, like every other signing field)
  but semantically opaque to the verifier — exactly as `payload_hash` is
  integrity-protected but the verifier needs the original `payload` to
  interpret it.

---

## Per-entry version dispatch and the non-decreasing invariant (DD4)

`Sigchain.new_event()` decides `sig_format_version` per call:

- `2` if `commitment_key_id` is supplied (with or without `principal_identity`
  / `principal_claims` — DD2);
- `1` otherwise.

Nothing prevents a caller from invoking `new_event()` with
`commitment_key_id` on entry N and without it on entry N+1 within the same
`Sigchain` object — `Sigchain` does not track "have I ever opted into v2."
`verify_chain` is what enforces the invariant, as a **pre-pass** before any
per-entry signature check:

1. Every entry's `sig_format_version` must be in `{1, 2}` — any other value
   (including `None`) is rejected immediately, no fallback.
2. Walking the chain in order, `sig_format_version` must never be lower than
   the previous entry's. A chain `[1, 1, 2, 2]` is valid; `[2, 1]` or
   `[1, 2, 1]` is rejected at the index where the decrease occurs, with the
   reason `"sig_format_version decreased from X to Y — downgrade/splice attack"`.

This check runs against the *declared* field on each entry, independent of
the per-entry signature check that follows it — even an entry whose
signature would otherwise verify is rejected if it violates the
non-decreasing rule. This is what makes a spliced-in or reordered v1 entry
detectable even if an attacker has a legitimately-signed v1 entry signed
under the same key: the *position* in the chain, not just the entry's own
signature, is part of what is being verified.

The same two-pass pre-check (version-set membership, then non-decreasing)
is reimplemented independently in `aevum.verify._core.verify_chain` — see
`packages/aevum-verify/tests/test_identity_binding_v2.py` for adversarial
coverage from the independent-verifier side.

---

## Digest Construction (v2 delta)

Steps 1–6 of [v1 § Digest Construction](aevum-signing-v1.md#digest-construction)
apply unchanged, with one addition to Step 1: when `sig_format_version == 2`,
the signing object includes the 3 additional fields (set to `null` when the
entry has no principal binding at all — DD2; never omitted).

### Worked example

A `sig_format_version = 2` entry with a full principal binding
(`actor = "aevum-demo"`, bound credential identity
`"urn:example:oidc:sub:alice"`, commitment key `0x11 * 32`):

**Signing object** (22 keys; shown in insertion order for readability — RFC
8785 sorts by Unicode code point before hashing):

```json
{
  "event_id": "019ee2a8-416e-7f42-888f-8772501b4e39",
  "episode_id": "019ee2a8-416e-73a7-89f3-0cf7c6548a65",
  "sequence": 1,
  "event_type": "agent.decision",
  "schema_version": "1.0",
  "valid_from": "2026-06-20T01:32:18.158469+00:00",
  "valid_to": null,
  "system_time": "116779852638322688",
  "causation_id": null,
  "correlation_id": null,
  "actor": "aevum-demo",
  "trace_id": null,
  "span_id": null,
  "payload_hash": "d29ad0cc0208c50c2c70e1eaed7e627c5450e5673091a4f52328b3744b5ca41a",
  "prior_hash": "391f6bd6d761cb9af9e924d015a6fc18e9d236c965c3e5deda1145a25e11cf5e",
  "signer_key_id": "adb78823-6e53-4916-9219-b69f91ca0c52",
  "key_scheme": "ed25519",
  "sig_format_version": 2,
  "hash_alg": "sha3-256",
  "principal_binding": "eyJhdWQiOiJzdmMiLCJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsImp0aSI6Imp0aS0wMDEifQ",
  "principal_commitment": "OJLgwXWcI_Nte9MmWSmLrZ32LnhMIHKhKXKginr8PUw",
  "principal_commitment_key_id": "f7680422-a672-4966-a7ac-8d6db7f93007"
}
```

The original claims passed by the caller were
`{"iss": "https://idp.example.com", "aud": "svc", "jti": "jti-001", "sub": "urn:example:oidc:sub:alice"}`.
Decoding `principal_binding` (base64url) yields the RFC 8785-canonical JSON
`{"aud":"svc","iss":"https://idp.example.com","jti":"jti-001"}` — note `sub`
is absent (DD7); only the allow-listed keys survived.

**Message representative** (`DOMAIN_PREFIX + rfc8785.dumps(signing_obj)`,
shown truncated):

```
b'aevum-sigchain-v1\x00{"actor":"aevum-demo","causation_id":null,"correlation_id":nul...'
```

**Digest** (`sha3_256(representative)`, hex):

```
5877e5d73b8d933f25c21f4b73a2090ba5b12a73ed4a2f9b935e66efa5c6531d
```

**Signature** (base64url, no padding):

```
2DOBqCNhl2tVcrlaJ2GOJluRBkNuHzcQsNvkLuTApvSXLfXJntodWJHQFHoj2rFWlpGHtwE5WRYcIInSEeQnDQ
```

This digest is simultaneously the Ed25519 signed digest and (when there is a
next entry) the chain-hash input for that next entry's `prior_hash` — the
compute-once property holds for v2 entries exactly as it does for v1.

---

## Verification Procedure (v2 delta)

Extends [v1 § Verification Procedure](aevum-signing-v1.md#verification-procedure).
Steps not listed here are unchanged.

Replace v1 step 2 ("every entry must have `sig_format_version == 1`") with:

> 2. Pre-check (DD4): every entry's `sig_format_version` must be in `{1, 2}`
>    — reject any other value (including `None`), no fallback. Walking the
>    chain in declared order, `sig_format_version` must never decrease
>    relative to the previous entry; a decrease is rejected as a
>    downgrade/splice attack.

Insert into v1 step 4a ("construct the signing object"):

> If the entry's own `sig_format_version == 2`, the signing object includes
> `principal_binding`, `principal_commitment`, and `principal_commitment_key_id`
> (each `null` if the entry has no principal binding). If `sig_format_version
> == 1`, these three fields are absent from the signing object entirely — not
> present with a `null` value, *absent as keys*.

No other verification step changes. In particular:

- Step 4f (hybrid ML-DSA-65 check) is unchanged and orthogonal to
  `sig_format_version` — a chain may be both hybrid (`key_scheme =
  "ed25519+ml-dsa-65"`) and v2 (principal-bound) simultaneously; the two
  axes are independent.
- The verifier never needs a commitment key (DD6) — it has no parameter for
  one, and confirming a chain's integrity is a strictly separate operation
  from confirming which credential a given `principal_commitment` represents.

---

## `CommitmentKeyStore` (DD5, DD6, DD8) — summary

`aevum.core.audit.commitment_key_store.CommitmentKeyStore` holds the
HMAC-SHA256 secrets used to compute `principal_commitment`. It is modeled
structurally on `ConsentLedger` (SQLite-backed, `PRAGMA secure_delete=ON`,
crypto-shred on destroy) but uses a deliberately disjoint vocabulary —
`scope` / `principal` / `commitment_key_id`, never "subject" — because
`ConsentLedger`'s "subject" means the GDPR data subject, and this store's
"principal" means the bound credential identity of an actor (see
`KNOWN_UNKNOWNS.md` for the full two-"subject" distinction).

Public surface:

- `create_key(scope, commitment_key_id=None, key_bytes=None) -> str` —
  key-material resolution priority: explicit `key_bytes` argument >
  `AEVUM_COMMITMENT_KEY` env var (hex) > `os.urandom(32)`.
- `get_key(commitment_key_id) -> bytes | None`
- `scope_for(commitment_key_id) -> str | None`
- `commitment_for(commitment_key_id, principal) -> str | None` — convenience
  wrapper around `compute_principal_commitment`.
- `destroy(commitment_key_id, *, ledger, actor, ...) -> AuditEvent` — erases
  the key (secure-delete) and appends a `commitment_key.destroyed` event to
  the given ledger via the *existing* `ledger.append()` mechanism (no new
  persistence path). `commitment_key.destroyed` is a kernel-reserved event
  type (`commit.py` `_RESERVED_PREFIXES`); application code cannot forge it.

Erasure is **coarse** (DD5): one key typically covers a whole deployment
scope, so destroying it erases the ability to confirm or re-derive *every*
`principal_commitment` computed under that key, not a single principal's.
After `destroy()`, `get_key()` / `scope_for()` / `commitment_for()` all
return `None` for that `commitment_key_id` — destroyed is indistinguishable
from never-existed, matching the design of `ConsentLedger.shred()`.

The signed chain entries that reference a destroyed `commitment_key_id` are
untouched — the episodic ledger is append-only (Frozen Invariant 5). Only
the ability to *interpret* their `principal_commitment` field via that key is
lost; `verify_chain` continues to verify those entries successfully (DD6),
because it never needed the key in the first place.

---

## Chain homogeneity is unaffected

v1's `key_scheme` homogeneity check (all entries share one `key_scheme`) is
orthogonal to `sig_format_version` and is unaffected by this specification.
A chain may mix `sig_format_version` 1 and 2 (DD4) while holding `key_scheme`
constant throughout; it may not mix `key_scheme` values regardless of
`sig_format_version`.

---

## Sample chain

`demo/public/sample-chain-v2.json` (paired with
`demo/public/sample-chain-v2-pub.hex`) is a synthetic, fully-signed,
"verify-it-yourself" chain spanning `sig_format_version` 1 then 2,
regenerated by `scripts/gen_sample_chain_v2.py`. It contains no real data —
every payload is flagged `"synthetic": true`, and every `principal_identity`
/ `principal_claims` value is synthetic. The Ed25519 signing key and the
commitment key used to generate it are both ephemeral and discarded after
generation; only the Ed25519 **public** key is published, since chain
verification never needs the commitment key (DD6). `tests/test_sample_chain_v2_verifies.py`
guards that this sample continues to verify with `aevum-verify`.

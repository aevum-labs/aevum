# RFC 3161 Timestamp Longevity and Re-Anchoring

This document resolves two parked durability decisions for the RFC 3161
timestamp attestations attached to sigchain entries and Signed Tree Heads
(STHs): the long-term validity risk of TSA signing certificates over a
multi-year retention window, and the re-anchoring procedure operators should
follow before that risk materializes.

---

## Background

Every sigchain entry and STH may carry an RFC 3161 `tsa_token`: the raw
DER-encoded `TimeStampResponse` returned by a Time-Stamping Authority,
stored verbatim as hex (`aevum.core.tsa.TSAClient`, `aevum.core.audit.merkle`).
The token is independent third-party evidence that the timestamped data
existed before a specific time — it does not depend on the operator's
system clock.

The TSA signs that response with its own signing certificate. Like any
X.509 certificate, the TSA's signing certificate has a validity window and
will eventually expire (or could be revoked). This is a known limitation of
RFC 3161 on its own: a verifier checking the token's signature *after* the
TSA's signing certificate has expired cannot, by the certificate's validity
period alone, distinguish "signed while the cert was valid, and the cert
has since lawfully expired" from "signed with a no-longer-trustworthy key."
RFC 3161 has no built-in mechanism to extend trust in a timestamp past the
signing certificate's lifetime — that is the explicit problem space of
long-term validation (LTV) standards such as RFC 4998 (Evidence Record
Syntax) and ETSI EN 319 422.

## Why this matters for Aevum

SEC Rule 17a-4 and similar broker-dealer recordkeeping regimes impose
multi-year retention (commonly cited as ~6–7 years) on records that may
carry RFC 3161 attestations. A TSA signing certificate's validity period is
very unlikely to span the full retention window. Left unaddressed, a
sigchain entry timestamped early in its retention life could hold a
`tsa_token` whose signing certificate has expired well before the record is
allowed to be discarded.

## Aevum's position

**The write-time RFC 3161 timestamp is best-effort and advisory, not the
sole evidentiary anchor.** This is already true by construction:

- `TSAClient.timestamp()` is non-blocking and circuit-broken
  (`packages/aevum-core/src/aevum/core/tsa.py`) — a sigchain entry or STH
  with `tsa_token=None` is still cryptographically valid (Ed25519 +
  ML-DSA-65 hybrid signature). The TSA token adds an *external* time
  attestation on top of that; it is not required for chain integrity.
- The TSA's signing-certificate lifetime bounds how long the token alone
  can be relied on as a *fresh* trusted-time claim. Aevum does not treat a
  single TSA token as permanently self-sufficient evidence — it is one
  input that should be refreshed (re-anchored) within the cert's validity
  window, not a one-time stamp good for the full retention period.
- The hybrid signature (Ed25519 + ML-DSA-65) over the chain remains the
  durable integrity guarantee across the full retention window; the TSA
  token's role is the narrower "trusted external clock" claim required by
  HIPAA §164.312(b)-style audit-control language and FDA 21 CFR Part 11.

## Cert-chain storage status

`TSAClient.timestamp()` stores the **complete, unparsed DER-encoded
`TimeStampResponse`** as `token_bytes` (`tsa.py:74-96`), persisted verbatim
as the hex `tsa_token` field on the sigchain entry / STH. An RFC 3161
`TimeStampResp` is a CMS `SignedData` structure with an optional
`certificates` field; when (as is typical for the default public TSAs —
Sigstore, DigiCert) the TSA includes its signing certificate (and often the
intermediate chain) in that field, those certificates travel with the
token byte-for-byte, because Aevum never strips or re-encodes the response.
`aevum.verify._core.verify_sth_tsa_full` already inspects this:
`has_embedded_certs = len(response.signed_data.certificates) > 0`, and
builds a chain-of-trust verification anchored to an operator-supplied
`tsa_root_cert`.

**PRESENT, with a gap flagged.** The chain is present inside the opaque
token blob *if and only if the TSA chose to embed it* — Aevum does not
independently fetch, verify, or persist the TSA's certificate chain at
write time, and there is no tracking of the TSA's own signing-certificate
expiry date to trigger re-anchoring proactively. Today, re-anchoring is a
manual operational procedure (below), not an automated one.

**Flagged as a small future code item:** add a `tsa_cert_expiry` check at
write time (parse the embedded signing cert's `notAfter` from the response,
surface it to operators — e.g. via a log warning or a metric — when it
falls inside the configured retention window) so re-anchoring can be
scheduled before the certificate expires rather than discovered missing
during a future audit. This is observability/tooling, not a chain-format
change.

## Re-anchoring procedure

Re-anchoring re-establishes a *fresh* trusted-time attestation over the same
canonical data before the previous attestation's TSA certificate expires.
It does not modify, supersede, or invalidate the original token — both are
kept, consistent with the append-only ledger.

1. **Identify entries/STHs at risk.** Decode each `tsa_token`'s embedded
   signing certificate (or the configured TSA's known certificate, if the
   token has none embedded) and check `notAfter`. Flag any token whose
   certificate will expire before the record's retention end date.

2. **Compute the current Merkle root.** Use `MerkleLog` over the full
   (or relevant range of) events to get the current `root_hash` — the same
   root that the original STH attested to, or the current root if the log
   has grown since.

3. **Request a fresh RFC 3161 timestamp over that root** from a
   **currently valid** TSA (`TSAClient.timestamp(root_bytes)`), using
   either the original TSA (if its cert is still valid for a while) or a
   different configured TSA (`AEVUM_TSA_URL`).

4. **Mint a new `SignedTreeHead`** (`MerkleLog.signed_tree_head(...,
   tsa_client=...)`) carrying the new `tsa_token`. This produces a new,
   independently hybrid-signed (Ed25519 + ML-DSA-65) STH whose own
   `root_hash` is unchanged but whose `timestamp` and `tsa_token` are fresh.

5. **Store the new STH's full response bytes**, including whatever
   certificate chain the new TSA embedded, alongside the original — never
   in place of it. Both STHs (old and new) remain queryable; the new one is
   the current re-anchoring point for offline/LTV validation going forward.

6. **Repeat before each subsequent TSA certificate's expiry.** Re-anchoring
   is a recurring operational task, not a one-time fix — schedule it on the
   shorter of (a) the TSA cert's remaining validity, or (b) a fixed review
   cadence (e.g. annually), whichever comes first.

This is the standard "timestamp renewal" pattern used by long-term archival
systems that predate formal LTV standards: a chain of timestamps, each
applied while the previous one's signing certificate was still valid (or
shortly after, while the expired cert is still usable for *historical*
validation against the data it covered), is sufficient to carry trust
forward indefinitely without requiring every verifier to trust a single
certificate's full multi-year span.

## RFC 4998 / Evidence Record Syntax — parked

RFC 4998 (Evidence Record Syntax, ERS) and its ETSI counterpart
(EN 319 422) formalize the re-anchoring pattern above into a standard,
machine-verifiable "evidence record" that chains successive timestamps and
hash-tree archive structures. Adopting ERS would give Aevum a standards-body
format for the re-anchoring chain instead of an Aevum-specific convention
(STH-over-STH).

**This is intentionally parked, not adopted.** ERS-format interoperability
is not implemented; it would require adopting RFC 4998 Evidence Record
Syntax. The manual procedure above satisfies the underlying durability
requirement (a fresh, verifiable external timestamp before the prior one's
trust window narrows) without committing to ERS's wire format. Handing an
Aevum-anchored record to a third-party long-term archival service that
expects RFC 4998 input is not currently supported.

## Related

- `packages/aevum-core/src/aevum/core/tsa.py` — `TSAClient`, `TSAToken`
- `packages/aevum-core/src/aevum/core/audit/merkle.py` — `SignedTreeHead`,
  `verify_sth_tsa`
- `packages/aevum-verify/src/aevum/verify/_core.py` — `verify_sth_tsa_full`
  (embedded-cert chain validation against a pinned root)
- `docs/deployment/key-rotation.md` — the analogous procedure for signing
  key rotation (event-bridge pattern this re-anchoring procedure mirrors)
- `KNOWN_UNKNOWNS.md` — D1/D2 tracking entries

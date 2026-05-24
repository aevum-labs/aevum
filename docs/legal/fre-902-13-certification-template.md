# FRE 902(13) Certification Template — Aevum Receipts

## Purpose
This template enables an Aevum deployer to make Aevum receipts
self-authenticating in US federal court under FRE 902(13) (Records Generated
by an Electronic Process or System) and FRE 803(6) (Business Records Hearsay
Exception).

## Qualified Person Certification

I, [NAME], [TITLE] at [ORGANIZATION], hereby certify:

1. I am familiar with the Aevum governance kernel deployed by [ORGANIZATION]
   and the process by which it generates audit receipts.

2. The attached Aevum receipts (file hash: [SHA-256 of receipt bundle]) were
   generated automatically by the Aevum governance kernel, version [X.Y.Z],
   operating in [ORGANIZATION]'s production environment.

3. The receipts were generated as a regular practice of [ORGANIZATION]'s
   AI governance program, at the time of each recorded agent action.

4. The digital identification process used is as follows:
   - Each receipt is a COSE_Sign1 structure (RFC 9052) containing an
     Ed25519 digital signature (RFC 8032) over the SHA3-256 hash
     (FIPS 202) of the receipt payload in CBOR encoding (RFC 8949).
   - The signature can be verified by any party using the Aevum issuer
     public key published at [URL] (SHA-256 fingerprint: [fingerprint]).
   - Tampering with the receipt payload invalidates the Ed25519 signature,
     which is detectable by any party running `aevum verify-receipt <receipt_file>`.

5. The Merkle inclusion proof (if present) confirms that this receipt was
   registered in the Rekor v2 transparency log at log index [INDEX],
   which provides independent third-party corroboration of the receipt's
   existence and content at the recorded time.

Signed: _____________________ Date: _____________

## Notes
- FRE Advisory Committee Note to 902(13): "The rule is flexible enough to
  allow certifications... including comparison of hash value."
- Ed25519 signatures provide non-repudiation equivalent to or stronger than
  the hash-comparison process explicitly endorsed in the Advisory Committee notes.
- For eIDAS-equivalent non-repudiation under EU law: consult with a qualified
  trust service provider to obtain a qualified electronic signature over the
  same receipt bundle.

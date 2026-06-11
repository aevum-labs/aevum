# Signing Architecture Map — v0.8.0 line

**Branch:** `claude/signing-architecture-map-z91vyz`  
**Scope:** Investigation only — no code changed.  
**Purpose:** Ground-truth map for P2b implementation handoff (signer unification).

---

## Gate Report

```
P2b-PREFLIGHT — GATE REPORT
H1 (dual_signer only in tests; prod Sigchain Ed25519-only)  = CONFIRMED (empirical + static)
H2 (kernel DualSigner → SQLite, not sigchain)               = CONFIRMED (empirical + static)
H3 (session→sigchain append dead)                           = CONFIRMED (empirical + static)
H4 (≥3 independent random-keyed signers)                    = CONFIRMED (3 confirmed; 4th possible)
Q1 canonical chain                                          = Engine._sigchain (InMemoryLedger or persistent backend)
Q2 does hybrid reach canonical chain in production?         = NO — Ed25519-only in canonical chain; ML-DSA-65 confined to SQLite
Q3 signer inventory table                                   = attached (Section 3)
Q5 intended (per ADRs) vs actual gap                        = Kernel's DualSigner disconnected from canonical Sigchain
Recommendation for the unified target                       = Kernel owns one DualSigner; drives one canonical Sigchain; verify_chain is the single verification path
SIGNING_ARCHITECTURE_MAP.md                                 = this document
```

---

## 1. Hypothesis Verdicts

### H1 — `Sigchain(dual_signer=...)` only in tests; Engine's Sigchain Ed25519-only in production

**CONFIRMED.** File:line evidence:

**Production path — Ed25519 only:**
- `engine.py:108` — `self._sigchain = sigchain or Sigchain()` — no `dual_signer` argument passed
- `audit/sigchain.py:156` — `else: self._signer = InProcessSigner()` — default branch taken
- `audit/sigchain.py:160` — `self._dual_signer = dual_signer` — stored as `None`
- `audit/sigchain.py:238` — `scheme = "ed25519+ml-dsa-65" if self._dual_signer is not None else "ed25519"` → `"ed25519"`

**Empirically confirmed (boot + commit, dev mode):**
```
Engine._sigchain signer type:   InProcessSigner
Engine._sigchain._dual_signer:  None
Ledger entry key_scheme:        ed25519
Ledger entry mldsa65_sig:       None
Engine.verify_sigchain():       True
```

**`Sigchain(dual_signer=...)` appears only in tests:**
- `tests/test_phase1_sigchain.py:42` — `Sigchain(dual_signer=dual_signer, tsa_client=...)`
- `tests/test_phase1_sigchain.py:52` — `Sigchain(dual_signer=dual_signer)`
- `tests/test_phase1_sigchain.py:76` — `Sigchain(dual_signer=dual_signer, tsa_client=...)`
- `tests/test_phase1_sigchain.py:85` — `Sigchain(dual_signer=dual_signer, tsa_client=...)`
- `tests/test_p2a_sig_format_versioning.py:181` — `Sigchain(dual_signer=DualSigner.generate())`

No production or library code ever passes `dual_signer=` to `Sigchain()`.

---

### H2 — Kernel holds DualSigner but no Sigchain; dual-sig goes to SQLite not Sigchain

**CONFIRMED.** File:line evidence:

**Kernel holds only three things — no sigchain:**
- `kernel.py:43–51` — `__init__` stores `_principles`, `_signer`, `_tsa_client` only
- `kernel.py:53–63` — properties: `principles`, `signer`, `tsa_client` — no `sigchain` property
- Empirically confirmed: `Kernel` attribute set = `['_principles', '_signer', '_tsa_client', 'local', 'principles', 'signer', 'tsa_client']`

**Session uses Kernel's DualSigner to sign the session record payload:**
- `session.py:182–188` — `dual_sig = self.kernel.signer.sign(payload)` — calls `DualSigner.sign(bytes)` → `DualSignature`
- `payload` is `json.dumps(record.to_dict(), ...)` — the full Merkle-root session record (session.py:178–180)

**Dual-sig written to SQLite, not Sigchain:**
- `session.py:218–285` — `_write_session_record()` writes `ed25519_sig`, `mldsa65_sig`, `ed25519_pub`, `mldsa65_pub` to SQLite `sessions` table
- `session.py:256` — `sigchain_entry_id = None` at INSERT time — field always NULL (never populated)
- The SQLite schema confirms dual-sig columns (session.py:40–58):
  ```sql
  ed25519_sig  TEXT,
  mldsa65_sig  TEXT,
  ed25519_pub  TEXT,
  mldsa65_pub  TEXT,
  tsa_token    TEXT,
  sigchain_entry_id INTEGER   -- always NULL
  ```

**Kernel's DualSigner is constructed at boot with disk-persisted keys:**
- `kernel.py:96–107` — `DualSigner.load(keys_dir)` if key files exist, else `DualSigner.generate()` + `save()`
- Keys persist across reboots (unlike InProcessSigner which regenerates each time)
- `signing.py:169–173` — generates Ed25519 + ML-DSA-65 keypair (requires liboqs)

---

### H3 — `Session._append_to_sigchain` is a dead path

**CONFIRMED.** File:line evidence:

**The guard condition:**
- `session.py:302` — `if hasattr(self.kernel, "_sigchain") or hasattr(self.kernel, "sigchain"):`

**Both `hasattr` calls return `False` because Kernel has neither attribute:**
- `kernel.py:43–63` — Kernel's `__init__` and properties: no `_sigchain` or `sigchain`

**Empirically confirmed:**
```
hasattr(kernel, '_sigchain'): False
hasattr(kernel, 'sigchain'):  False
Guard passes (would append to sigchain): False
=> _append_to_sigchain is DEAD: True
```

**The method is called (not dead at the call site):**
- `session.py:203` — `self._append_to_sigchain(record, dual_sig, tsa_hex)` — IS called on every REMEMBER
- But its inner `sigchain.new_event(...)` block is unreachable for any current Kernel instance

**Consequence:** `session.committed` events are never written to any Sigchain. The `sigchain_entry_id` column in SQLite is always `NULL` (session.py:256). The Merkle root and dual-sig for each session are in SQLite only, not in the canonical chain.

---

### H4 — ≥3 independent signer instances with independent random keys

**CONFIRMED — 3 confirmed, 1 additional conditional.**

| # | Instance | Type | Key origin | Comment |
|---|---|---|---|---|
| 1 | `Engine._sigchain._signer` | `InProcessSigner` | `Ed25519PrivateKey.generate()` at `Engine.__init__` | Fresh random key per process start; lost on restart |
| 2 | `Kernel._signer` | `DualSigner` | `DualSigner.load(keys_dir)` or `DualSigner.generate()` at `Kernel.local()` | Disk-persisted keypair; survives restarts |
| 3 | `AmbientContextEncoder._signer` (from `from_env()`) | `InProcessSigner` | `Ed25519PrivateKey.generate()` at `AmbientContextEncoder.from_env()` | Fresh random key per `from_env()` call; independent of engine |
| 4 | `Sigchain._receipt_encoder._signer` (if configured) | `InProcessSigner` | `Ed25519PrivateKey.generate()` inside `ReceiptEncoder` | Only present when `receipt_encoder=` passed to Sigchain |

**Empirically confirmed — signer 1 and 3 are distinct:**
```
Engine sigchain signer key_id:        5e30f1e5-c7b4-48a6-bf26-0252a24accfc
AmbientContextEncoder signer key_id:  8cf0d1c8-6b84-44de-8eaf-4989021e8224
Keys are distinct (different pub bytes): True
```

**No key material is shared** between any of these instances. Each `InProcessSigner()` call hits `Ed25519PrivateKey.generate()` (audit/signer.py:100), which uses the OS CSPRNG. `DualSigner.generate()` hits `nacl.signing.SigningKey.generate()` and `oqs.Signature.generate_keypair()` independently (signing.py:169–172).

---

## 2. Questions Answered

### Q1 — Which chain is canonical?

**The Engine's `Sigchain` (`engine._sigchain`) is the canonical audit chain.**

Boot path to canonical chain:
```
Engine.__init__()
  → engine._sigchain = Sigchain()           # audit/sigchain.py:156 — InProcessSigner
  → engine._ledger   = InMemoryLedger(sigchain)  # engine.py:109
                        ↕ (or OxigraphLedger / PostgresLedger for production)
All five functions (ingest/query/review/commit/replay)
  → _ingest/_query/_review/_commit/_replay
  → ledger.append(event_type, payload, actor)    # InMemoryLedger.append()
  → sigchain.new_event(...)                      # audit/sigchain.py:200
  → AuditEvent (hash-chained, Ed25519-signed)
```

**Verification path:**
- `engine.verify_sigchain()` (engine.py:644–645)
- → `self._sigchain.verify_chain(self._ledger.all_events())` (audit/sigchain.py:389–506)
- Checks: prior_hash chain, payload_hash, Ed25519 signature for every entry

**External auditor access:**
- For `InMemoryLedger`: ephemeral — lost on restart. An auditor must query a running process or export entries before shutdown.
- For Oxigraph/Postgres backends: the sigchain events are persisted and can be exported. `engine.get_ledger_entries()` returns all events as dicts.
- The COSE_Sign1 receipts in SQLite (`receipts` table) are a secondary, independently verifiable artifact — but the primary canonical chain is the `Sigchain`.

**SQLite `sessions` table is NOT the canonical chain.** It is a secondary store of session-level summaries with dual-signatures. It is richer in some ways (Merkle root, ML-DSA-65 sig) but is not the hash-chained event-level audit record.

---

### Q2 — Does hybrid reach the canonical chain in production?

**NO.**

The canonical chain (`engine._sigchain`) is **Ed25519-only** in all production and library code. Every `AuditEvent` in the chain has:
- `key_scheme = "ed25519"`
- `mldsa65_sig = None`
- `mldsa65_pub = None`

ML-DSA-65 signatures exist only in:
1. SQLite `sessions` table — `mldsa65_sig`, `mldsa65_pub` columns (from `Kernel.signer.sign(session_record_payload)`)
2. Test code — `Sigchain(dual_signer=DualSigner.generate())` in unit tests

The ADR-012 hybrid posture is **not wired into the canonical chain**. The Kernel's DualSigner is isolated in the session-summary path and never reaches `Sigchain.new_event()`.

---

### Q3 — Signer inventory table

| Signer instance | Type | Key origin | What bytes it signs | Output stored in | Verifier |
|---|---|---|---|---|---|
| `Engine._sigchain._signer` | `InProcessSigner` | Fresh random Ed25519 per `Engine()` call (`Ed25519PrivateKey.generate()` at signer.py:100) | `SHA3-256(JCS(signing_fields))` for each `AuditEvent` (audit/sigchain.py:267) | `AuditEvent.signature` field in `InMemoryLedger` / Oxigraph / Postgres sigchain entries | `Sigchain.verify_chain()` via `engine.verify_sigchain()` (engine.py:644) |
| `Kernel._signer` | `DualSigner` (Ed25519 + ML-DSA-65) | Disk-persisted in `~/.aevum/keys/` — loaded at `Kernel.local()` (kernel.py:97–99) or generated fresh (kernel.py:101–107) | Session record JSON (Merkle root summary) — `json.dumps(record.to_dict())` (session.py:178–180) | SQLite `sessions` table: `ed25519_sig`, `mldsa65_sig`, `ed25519_pub`, `mldsa65_pub` columns (session.py:232–235) | `DualSigner.verify()` — **no automated verifier wired**; must be called manually |
| `AmbientContextEncoder._signer` (from `from_env()`) | `InProcessSigner` | Fresh random Ed25519 per `AmbientContextEncoder.from_env()` call (ambient.py:214) | `SHA3-256(COSE Sig_Structure)` of ambient snapshot CBOR (ambient.py:186–188) | COSE_Sign1 blob in SQLite `ambient_receipts.blob` (audit/sigchain.py:581) | COSE_Sign1 receipt verifier — offline, with encoder's public key |
| `Sigchain._receipt_encoder._signer` (optional) | `InProcessSigner` (inside `ReceiptEncoder`) | Fresh random Ed25519 per `ReceiptEncoder()` instantiation | `SHA3-256(COSE Sig_Structure)` for each `AuditEvent` receipt (aevum-publish) | COSE_Sign1 blob in SQLite `receipts.blob` (audit/sigchain.py:347–351) | COSE_Sign1 receipt verifier — offline, with encoder's public key |

**Key observations:**
- Signers 1, 3, and 4 regenerate fresh keys on each process start — they have **no persistent identity across restarts**.
- Signer 2 (Kernel's DualSigner) is the **only signer with persistent key identity** (disk-persisted).
- Signer 1 (canonical chain) is ephemeral — the signing key identity changes with every restart, making cross-session chain verification identity tracking impossible without a key registry.
- Signers 3 and 4 are completely independent of signers 1 and 2 — an auditor must obtain four different public keys to verify the full artifact set.

---

### Q4 — Dead wiring: is `_append_to_sigchain` genuinely dead?

**Yes, genuinely dead** for all current `Kernel` instances. 

Specific evidence:
- Called at: `session.py:203`
- Guard at: `session.py:302` — `if hasattr(self.kernel, "_sigchain") or hasattr(self.kernel, "sigchain"):`
- `Kernel.__init__` (kernel.py:43–51): no `_sigchain` or `sigchain` attribute is ever set
- `Kernel` properties (kernel.py:53–63): only `principles`, `signer`, `tsa_client`

Additional dead wiring:
- The `sigchain_entry_id` column in SQLite `sessions` table (session.py:256) is always `None` — it was designed to cross-reference the session commit with a sigchain entry ID, but since the sigchain append never fires, it's permanently `NULL`.
- `Engine._sigchain` is never passed `Kernel.signer` as its `DualSigner`. These are architecturally disconnected.

No test asserts that `kernel.sigchain` exists or that `"session.committed"` appears in the canonical chain. The `dual_signer` tests (H1 evidence) operate on standalone `Sigchain(dual_signer=...)` objects with no Kernel involved.

---

### Q5 — Intended (per ADRs) vs Actual

**Intended architecture (per ADRs):**

| ADR | Intent |
|---|---|
| ADR-001 | One canonical sigchain for all five functions. "A single chain = one verification step, the simplest auditor experience." |
| ADR-004 | Pluggable Signer with InProcessSigner as dev default; production deployments substitute VaultTransitSigner/KMS. The Kernel's signer is the chain's signer. |
| ADR-012 | `Kernel.local()` uses `DualSigner` (hybrid Ed25519 + ML-DSA-65) by default. PQC backend absent → hard failure (`SignerUnavailableError`), not silent fallback. The **canonical chain** should carry both signatures. |

ADR-012 is explicit: "Kernel.local() requires ML-DSA-65 to be available." The implication is that the Kernel's `DualSigner` drives the chain — otherwise there is nothing to fail-close on. The fail-closed behaviour only makes sense if liboqs absence prevents the canonical chain from starting.

**Actual architecture:**

```
Kernel.local()
  → DualSigner (Ed25519 + ML-DSA-65)          ← persisted, correct
  → TSAClient                                  ← correct
  → Kernel._signer = DualSigner               ← stored, but...

Engine.__init__()
  → Sigchain()                                 ← creates its OWN InProcessSigner (Ed25519-only)
  → InMemoryLedger(sigchain)                   ← canonical chain is Ed25519-only
  ← Kernel not involved at all
```

**Gap summary:**

1. **DualSigner is isolated from the canonical chain.** The Kernel's DualSigner signs only session-level summary records into SQLite. The canonical event-by-event sigchain is Ed25519-only. ADR-012's hybrid-by-default intent is not realized in the canonical chain.

2. **Engine and Kernel are architecturally disconnected.** Engine creates its own `Sigchain` with its own `InProcessSigner`. Kernel creates its own `DualSigner`. Nothing wires them together. The missing bridge would be: `Engine(sigchain=Sigchain(dual_signer=kernel.signer))`.

3. **`Session._append_to_sigchain` was intended to be the bridge** — but it guards on `hasattr(kernel, "_sigchain")` which was never set. This is the skeleton of the right design (Kernel → Sigchain → canonical chain) but the required attribute was never added to `Kernel`.

4. **Three independent ephemeral signing keys.** The Engine's sigchain signer, the AmbientContextEncoder's signer, and the ReceiptEncoder's signer are all fresh random keys per process start. An auditor reconstructing a post-incident timeline faces four different signing keys (one persistent, three ephemeral), with no key registry or cross-reference.

5. **`sigchain_entry_id` is always NULL.** This column was clearly designed to cross-link a SQLite session row with its canonical sigchain entry, but it's permanently unset because `_append_to_sigchain` is dead.

---

## 3. Data Flow: Canonical Path vs Secondary Paths

### Canonical path (what the chain actually looks like in production)

```
boot
  Engine.__init__()
  ├── Sigchain() ─────────────── InProcessSigner (fresh Ed25519, ephemeral)
  │     _dual_signer = None     ← no hybrid
  │     _tsa_client = None      ← no RFC 3161 unless passed explicitly
  └── InMemoryLedger(sigchain)

operation (any of the 5 functions)
  → engine.ingest / query / review / commit / replay
  → ledger.append(event_type, payload, actor)
  → sigchain.new_event(...)
    ├── Increment sequence
    ├── SHA3-256(JCS(signing_fields)) → Ed25519 sign → AuditEvent.signature
    ├── key_scheme = "ed25519"
    ├── mldsa65_sig = None  (dual_signer is None)
    └── AuditEvent stored in InMemoryLedger._events

verification
  engine.verify_sigchain()
  → sigchain.verify_chain(all_events)
  → for each event: check prior_hash, payload_hash, Ed25519 sig
  → ML-DSA-65 NOT checked (no dual_signer present)
```

### Secondary path A — Session dual-sig to SQLite

```
async with Session(actor, kernel=kernel, db_path=path) as s:
    engine.ingest(..., session=s)    ← records RELATE event in s._events
    engine.query(..., session=s)     ← records NAVIGATE event in s._events

__aexit__ → Session._remember()
  1. Compute Merkle root over s._events
  2. Build SessionRecord (Merkle root + metadata)
  3. Serialize to JCS JSON → payload bytes
  4. kernel.signer.sign(payload) → DualSignature (Ed25519 + ML-DSA-65)
  5. kernel.tsa_client.timestamp(payload) → RFC 3161 token
  6. _write_session_record() → SQLite sessions table:
       merkle_root, ed25519_sig, mldsa65_sig, ed25519_pub, mldsa65_pub, tsa_token
       sigchain_entry_id = NULL  ← always
  7. _append_to_sigchain() → DEAD PATH (hasattr guard fails)
     → no 'session.committed' event in canonical chain
```

### Secondary path B — Ambient context (if configured)

```
sigchain.capture_ambient_context(trigger, session_id, ...)
  → AmbientContextEncoder.encode(snapshot)
    → AmbientContextEncoder._signer.sign(SHA3-256(COSE_Sig_Structure))
       (InProcessSigner — fresh ephemeral Ed25519, unrelated to canonical chain)
    → COSE_Sign1 bytes
  → SqliteReceiptStore.put_ambient(snapshot_id, blob, ...)
     → SQLite ambient_receipts table
  → returns snapshot (not linked to canonical chain events)
```

### Secondary path C — COSE_Sign1 receipts (if receipt_encoder configured)

```
sigchain.new_event(...)
  → AuditEvent created (Ed25519-signed, canonical)
  → receipt_encoder.encode(AevumReceipt.from_sigchain_event(event))
     → ReceiptEncoder._signer.sign(SHA3-256(COSE_Sig_Structure))
        (InProcessSigner — fourth independent ephemeral key)
     → COSE_Sign1 bytes
  → SqliteReceiptStore.put(receipt_hash, blob, entry_hash=event.payload_hash)
  → escalate_if_triggered() if needed
```

---

## 4. Recommendation: Unified Target for P2b/P2c

**Problem statement in one sentence:** The Kernel holds the right signer (DualSigner, hybrid, persistent) but the canonical chain uses the wrong one (InProcessSigner, Ed25519-only, ephemeral) — these two have never been wired together.

### Unified target

**Kernel owns one signer of posture P; it drives the one canonical Sigchain; `verify_chain` is the single verification path.**

Specifically:

1. **`Kernel` holds the canonical `Sigchain`.** Add `_sigchain: Sigchain` to `Kernel.__init__` (constructed from its `DualSigner`). `Kernel.local()` builds `Sigchain(dual_signer=self._signer, tsa_client=self._tsa_client)`.

2. **`Engine` accepts its `Sigchain` from `Kernel`.** Rather than `Engine` constructing its own `Sigchain()`, callers pass `Engine(sigchain=kernel._sigchain)` (or `Engine(kernel=kernel)`). This wires the Kernel's DualSigner into every `sigchain.new_event()` call.

3. **All canonical chain entries carry both Ed25519 + ML-DSA-65 signatures.** After the wire-up, `AuditEvent.key_scheme` becomes `"ed25519+ml-dsa-65"` for all production events, and `verify_chain()` checks both algorithms.

4. **`Session._append_to_sigchain` becomes live.** Once `Kernel._sigchain` exists, the `hasattr` guard passes and `"session.committed"` events land in the canonical chain. `sigchain_entry_id` in SQLite gets populated.

5. **Signer identity is stable and singular.** One `DualSigner` (Kernel's, disk-persisted) signs all canonical events. An auditor holds one public key set (Ed25519 + ML-DSA-65) for the entire chain across process restarts.

6. **AmbientContextEncoder and ReceiptEncoder use Kernel's Ed25519 key.** Instead of spawning independent `InProcessSigner()` instances, these can be constructed with the Kernel's signer (or its Ed25519 component wrapped as a `Signer`). This reduces the public key surface from 4 keys to 1.

### What NOT to change in P2b

- `DualSigner` API (signing.py) — already correct
- `Sigchain.new_event()` dual-sig path — already correct, just needs `dual_signer` populated
- `Session._remember()` dual-sign logic — keep as secondary (SQLite session record); the canonical chain entry via `_append_to_sigchain` will now also carry the same dual-sig
- `verify_chain()` — already handles `"ed25519+ml-dsa-65"` key scheme (audit/sigchain.py:486–501)
- ADR-012 fail-closed behaviour — already in `DualSigner.generate()` (signing.py:163–168); will naturally propagate once Kernel's DualSigner drives `Engine.__init__`

### P2b implementation order (suggested)

1. Add `_sigchain` attribute to `Kernel` — constructed from `Kernel._signer` (DualSigner)
2. Thread `kernel._sigchain` into `Engine` constructor (or add `Kernel.open_engine()` factory)
3. Fix `Session._append_to_sigchain` guard — either add `kernel.sigchain` property or remove the `hasattr` check and access `kernel._sigchain` directly
4. Populate `sigchain_entry_id` in SQLite from the returned `AuditEvent.sequence`
5. Update `Engine.verify_sigchain()` docstring to note both algorithms are now checked
6. Collapse AmbientContextEncoder and ReceiptEncoder to use Kernel's signer (optional, can be P2c)

---

## 5. Evidence appendix

### Key file:line index

| Claim | File | Lines |
|---|---|---|
| Engine creates Sigchain with no dual_signer | `packages/aevum-core/src/aevum/core/engine.py` | 108 |
| Sigchain defaults to InProcessSigner | `packages/aevum-core/src/aevum/core/audit/sigchain.py` | 147–156 |
| Sigchain._dual_signer stored (None in production) | `packages/aevum-core/src/aevum/core/audit/sigchain.py` | 160 |
| key_scheme set by dual_signer presence | `packages/aevum-core/src/aevum/core/audit/sigchain.py` | 238 |
| dual_sig only applied if _dual_signer not None | `packages/aevum-core/src/aevum/core/audit/sigchain.py` | 278 |
| Kernel.__init__ stores only 3 fields | `packages/aevum-core/src/aevum/core/kernel.py` | 43–51 |
| Kernel properties: no sigchain | `packages/aevum-core/src/aevum/core/kernel.py` | 53–63 |
| Kernel.local() generates DualSigner | `packages/aevum-core/src/aevum/core/kernel.py` | 96–107 |
| Session._remember uses kernel.signer | `packages/aevum-core/src/aevum/core/session.py` | 184–188 |
| Dual-sig written to SQLite | `packages/aevum-core/src/aevum/core/session.py` | 232–235 |
| sigchain_entry_id always None | `packages/aevum-core/src/aevum/core/session.py` | 256 |
| _append_to_sigchain dead guard | `packages/aevum-core/src/aevum/core/session.py` | 302–303 |
| AmbientContextEncoder fresh InProcessSigner | `packages/aevum-core/src/aevum/core/ambient.py` | 209–214 |
| InProcessSigner generates fresh Ed25519 | `packages/aevum-core/src/aevum/core/audit/signer.py` | 99–101 |
| DualSigner.sign returns DualSignature | `packages/aevum-core/src/aevum/core/signing.py` | 217–247 |
| Sigchain(dual_signer=...) in tests only | `packages/aevum-core/tests/test_phase1_sigchain.py` | 42, 52, 76, 85 |
| Sigchain(dual_signer=...) in tests only | `packages/aevum-core/tests/test_p2a_sig_format_versioning.py` | 181 |
| verify_chain handles ed25519+ml-dsa-65 | `packages/aevum-core/src/aevum/core/audit/sigchain.py` | 486–501 |
| Engine.verify_sigchain | `packages/aevum-core/src/aevum/core/engine.py` | 644–645 |

### Empirical run output (abridged)

```
=== ENGINE SIGCHAIN ===
Engine._sigchain signer type:   InProcessSigner
Engine._sigchain._dual_signer:  None
Engine._sigchain.key_provenance: in-process

Ledger entries after commit: 2
  session.start    key_scheme=ed25519    mldsa65_sig=None
  test.event       key_scheme=ed25519    mldsa65_sig=None

Engine.verify_sigchain(): True

=== KERNEL ATTRIBUTES (mock DualSigner) ===
Kernel attribute set: ['_principles', '_signer', '_tsa_client', 'local', 'principles', 'signer', 'tsa_client']
hasattr(kernel, '_sigchain'): False
hasattr(kernel, 'sigchain'):  False
Guard passes (would append to sigchain): False
=> _append_to_sigchain is DEAD: True

=== SIGNER INDEPENDENCE ===
Engine sigchain signer key_id:        5e30f1e5-c7b4-48a6-bf26-0252a24accfc
AmbientContextEncoder signer key_id:  8cf0d1c8-6b84-44de-8eaf-4989021e8224
Keys are distinct (different pub bytes): True
```

Note: liboqs (ML-DSA-65) is not available in this CI environment. The `DualSigner` path was verified via static analysis and mock testing. The `Sigchain` and `InProcessSigner` paths are empirically confirmed. The `Kernel.local()` boot with liboqs requires a native liboqs build — behaviour is code-verified at `signing.py:163–168` (fail-closed when liboqs absent in v0.8.0).

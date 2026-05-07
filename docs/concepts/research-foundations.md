# Research Foundations

Aevum is built on established science, open standards, and
published research. This page documents the sources that
informed each major architectural decision.

The synthesis — the five functions, the barrier hierarchy,
the complication model, the governed membrane, and the
sigchain design — is original to Aevum. None of these
sources describe Aevum or anything equivalent to it. What
they provide is the scientific and engineering foundation
that each individual decision stands on.

We credit these works because intellectual honesty demands
it, and because users of a governance system deserve to
know that its design choices are grounded, not arbitrary.

---

## Cognitive Science and Memory

### Power-Law Forgetting — Edge Weight Decay

The knowledge graph uses power-law decay for edge weights
rather than exponential decay. This decision is grounded
in two converging bodies of research.

**Jost's Law** (Jost, 1897) observed that older memories
are forgotten more slowly than newer ones of equal current
strength — a phenomenon exponential decay cannot model but
power-law decay naturally captures.

**Wixted, J.T. (2004).** *The psychology and neuroscience
of forgetting.* Annual Review of Psychology, 55, 235–269.
This review established that retention across nearly every
studied domain follows a power function, not an exponential,
and that the power-law is one of the most reliable findings
in memory science. Aevum's decay function
`weight × (1 + days)^(-d)` implements this directly.
Sensitive edges use a steeper exponent (× 1.4) following
the principle that emotionally significant material exhibits
different decay dynamics.

### BFS Depth Limit — Why Depth 2

Graph traversal in Aevum stops at depth 2 by default.
Going deeper produces noise, not signal.

**Balota, D.A. & Lorch, R.F. (1986).** *Depth of automatic
spreading activation: Mediated priming effects in
pronunciation but not in lexical decision.* Journal of
Experimental Psychology: Learning, Memory, and Cognition,
12(3), 336–345.
This study confirmed that automatic spreading activation
in human semantic memory effectively operates at one to
two steps. Depth 3 associations produce negligible
facilitation. The BFS depth limit in Aevum is not an
engineering convenience — it mirrors the empirically
established reach of human associative memory.

### Fan Effect — Activation Dilution at Branching Nodes

Highly connected nodes receive an activation penalty
proportional to their degree. This is the fan effect
from ACT-R.

**Anderson, J.R. (1983).** *The Architecture of Cognition.*
Harvard University Press.
ACT-R (Adaptive Control of Thought — Rational) established
that retrieval time and activation strength degrade as the
number of associations from a concept increases. A concept
connected to many others is harder to retrieve precisely
because activation spreads across more paths. Aevum applies
this as an explicit penalty at high-degree nodes during
traversal.

### Complementary Learning Systems — Dual Memory Model

The separation between fast episodic storage (the sigchain)
and slow semantic storage (the knowledge graph) reflects
the Complementary Learning Systems (CLS) theory of human
memory organisation.

**McClelland, J.L., McNaughton, B.L., & O'Reilly, R.C.
(1995).** *Why there are complementary learning systems in
the hippocampus and neocortex: Insights from the successes
and failures of connectionist models of learning and
memory.* Psychological Review, 102(3), 419–457.
CLS theory describes a fast-learning hippocampal system
for specific episodes and a slow-learning neocortical
system for statistical regularities. Aevum separates these
concerns deliberately: the episodic ledger records specific
events with full fidelity; the knowledge graph accumulates
weighted semantic relationships over time.

---

## Graph Theory and Information Retrieval

### Personalized PageRank — Context Traversal

Aevum uses Personalized PageRank (PPR) for graph traversal
rather than simple BFS or cosine similarity.

**Page, L., Brin, S., Motwani, R., & Winograd, T. (1999).**
*The PageRank citation ranking: Bringing order to the web.*
Stanford InfoLab Technical Report.
PPR seeds the random walk from the query concept rather
than the full graph, producing a relevance ranking that
naturally decays with graph distance while respecting the
full topology. For sparse, typed knowledge graphs, PPR
consistently outperforms flat similarity retrieval on
precision at small k.

### PPMI — Concept Importance Scoring

**Church, K.W. & Hanks, P. (1990).** *Word association
norms, mutual information, and lexicography.*
Computational Linguistics, 16(1), 22–29.
PPMI identifies concepts that are meaningfully associated
above what chance predicts rather than merely frequent.
Aevum applies PPMI as an IDF-like importance weight during
context assembly, suppressing high-frequency but
low-information concepts.

---

## Cryptography and Audit Integrity

### Ed25519 — Signing

Every AuditEvent in the sigchain is signed with Ed25519.

**Bernstein, D.J., Duif, N., Lange, T., Schwabe, P., &
Yang, B.Y. (2011).** *High-speed high-security signatures.*
Journal of Cryptographic Engineering, 2(2), 77–89.
**RFC 8032** — *Edwards-Curve Digital Signature Algorithm
(EdDSA).* IETF, 2017.
Ed25519 was chosen over ECDSA P-256 for its resistance to
implementation side-channel attacks, fixed-size 64-byte
signatures, and deterministic signing (no per-signature
randomness required).

### SHA-3 (SHA3-256) — Hash Chaining

**NIST FIPS 202** — *SHA-3 Standard: Permutation-Based
Hash and Extendable-Output Functions.* NIST, 2015.
SHA3-256 (Keccak) was standardised as a complement to
SHA-2 with a fundamentally different internal construction
(sponge function), providing security against structural
attacks that could theoretically affect SHA-2 family
members.

### TOCTOU Vulnerabilities in Agent Systems

The Context Witness (Phase 12a) was designed in response
to published research on a specific class of vulnerability.

**Lermen, S. et al. (2025).** *Mind the Gap: Time-of-Check
to Time-of-Use Vulnerabilities in LLM-Enabled Agents.*
arXiv:2508.17155.
This paper formally defined and benchmarked TOCTOU
vulnerabilities in LLM agent pipelines. Aevum's witness
mechanism directly addresses the State Integrity Monitoring
defense described in this work.

**OpenPort Protocol Specification (2026).** arXiv:2602.20196.
The witness design follows the State Witness profile:
a minimal non-secret snapshot of relevant resource state,
bound to the request at preflight, revalidated at execution
time with fail-closed semantics.

### Optimistic Concurrency — ETag Pattern

**RFC 9110** — *HTTP Semantics.* IETF, 2022.
Rather than holding a database lock for the duration of
human review, Aevum captures a fingerprint at read time
and uses it as a precondition at commit time — the
ETag/If-Match pattern from HTTP concurrent editing.

---

## Agent Security Research

### Memory Poisoning — Barrier 3 and Policy-Mediated Writes

**OWASP Top 10 for Large Language Model Applications
(2025).** Open Web Application Security Project.
**OWASP Agentic AI Security Top 10, ASI06: Memory and
Context Poisoning (2025).** Open Web Application Security
Project.
ASI06 defines memory poisoning as the injection of
malicious or misleading content into an agent's persistent
memory stores. The Aevum governed membrane (Barrier 3:
consent enforcement, Barrier 5: provenance chain) ensures
no data enters the knowledge graph without a valid consent
grant and full chain of custody.

### Agent Autonomy Levels

**Levels of Autonomy in AI Systems.** DeepMind Safety
Research.
The L1–L5 taxonomy distinguishes operator-controlled (L1)
from fully autonomous (L5) agent behavior. Aevum enforces
the declared level through policy rules: an agent at L3
cannot self-approve actions that require L1 authorization.

---

## Open Standards

| Standard | Body | Role in Aevum |
|---|---|---|
| OWL 2 | W3C (2012) | Knowledge graph ontology |
| SPARQL 1.1 | W3C (2013) | Graph query language |
| SHACL | W3C (2017) | Constraint validation |
| R2RML | W3C (2012) | Database-to-RDF mapping |
| BFO 2.0 / ISO/IEC 21838-2:2021 | ISO | Top-level ontology |
| RFC 9457 | IETF (2023) | HTTP error format |
| RFC 8032 / Ed25519 | IETF (2017) | Event signing |
| NIST FIPS 202 / SHA-3 | NIST (2015) | Hash chaining |
| UUID v7 | IETF draft | Time-ordered identifiers |
| OpenID Connect 1.0 | OpenID Foundation | Identity federation |
| MCP (Model Context Protocol) | Anthropic | Agent tool interface |

### Why SHACL over ShEx

W3C Recommendation status, native SPARQL extensibility,
and superior tooling support across the RDF ecosystem.
ShEx is a community specification without equivalent
tooling depth.

### Why BFO 2.0

The only top-level ontology published as an ISO standard,
adopted by over 650 projects, and mandated by the US
Department of Defense (January 2024).

---

## Regulatory Frameworks

Aevum does not claim compliance — it produces the evidence
that compliance work requires.

| Framework | Relevance |
|---|---|
| EU AI Act (2024), Article 12 | Sigchain provides tamper-evident technical documentation of every AI decision |
| ISO/IEC 42001:2023 | Complication lifecycle and governance controls |
| GDPR, Article 17 | Consent revocation is immediate; erasure is recorded |
| SOC 2 Type II, PI1.2 | Provenance chain and classification ceiling |
| HIPAA | Classification ceiling at level 3 prevents unauthorized access |

---

## CRDTs — Consent Ledger

**Shapiro, M., Preguiça, N., Baquero, C., & Zawirski, M.
(2011).** *Conflict-free Replicated Data Types.* SSS 2011,
LNCS 6976, 386–400.
The OR-Set CRDT allows adds and removes to commute —
concurrent revocations and grants always converge to the
same state regardless of the order they are applied,
making the consent ledger safe for multi-node federation
without a central coordinator.

---

## A Note on Synthesis

None of the works cited above describe anything like Aevum.
Wixted describes forgetting curves; he does not describe a
governed AI context kernel. The OpenPort Protocol describes
a governance specification; it does not describe a Python
implementation with a sigchain and complication framework.

The synthesis — combining these independently published
findings and standards into a coherent architecture for
governed AI context — is the original work. This page
exists to make the inputs to that synthesis transparent,
not to diminish it.

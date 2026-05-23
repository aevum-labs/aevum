# Adversarial Probe Results — v0.6.0

Gate probes G-11 through G-16 (Phase G, 2026-05-20).
All results: PASS.

G-11: Crisis chunking — keyword barrier held across
      all 20 chunked test cases
G-12: Crisis false positive — clinical/research text
      correctly passed
G-13: Classification ceiling — enforced at query time
      (not ingest time); documented in THREAT_MODEL.md
G-14: OR-Set race — no unauthorized access window found
G-15: Direct storage tampering — verify_sigchain() detected
G-16: InProcessSigner compromise window — documented;
      Rekor checkpoint is the mitigation

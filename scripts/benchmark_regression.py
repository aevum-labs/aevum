# SPDX-License-Identifier: Apache-2.0
"""
Weekly performance regression check for Aevum's core signing operations.
Compares measured p50 against the Session 1A baseline (0.029ms).
Regression threshold: p50 > 1.5ms (50x baseline) signals a real regression.
A 50x threshold accommodates CI hardware variance (GitHub-hosted runners
vary significantly) while catching genuine regressions (e.g., a slow
cryptographic library version).
"""

import hashlib
import sys
import time

BASELINE_P50_MS = 0.029        # Session 1A measured baseline
REGRESSION_THRESHOLD_MS = 1.5  # 50x baseline: hardware-variance safe
WARMUP_ITERATIONS = 200
MEASURE_ITERATIONS = 2000


def benchmark_ed25519_sign() -> dict:
    try:
        import cbor2
        from nacl.signing import SigningKey
    except ImportError as e:
        print(f"SKIP: missing dependency ({e})")
        return {"skipped": True}

    sk = SigningKey.generate()
    payload = (
        b'{"action":"tool_call","agent":"bench-agent",'
        b'"prior_hash":"' + b"a" * 64 + b'"}'
    )

    def one_op() -> None:
        h = hashlib.sha3_256(payload).digest()
        hdr = cbor2.dumps({1: -8, 4: b"aevum-key-v1"})
        sk.sign(hdr + h)

    # Warmup
    for _ in range(WARMUP_ITERATIONS):
        one_op()

    # Measure
    samples = []
    for _ in range(MEASURE_ITERATIONS):
        t0 = time.perf_counter()
        one_op()
        samples.append((time.perf_counter() - t0) * 1000)

    samples.sort()
    return {
        "p50": samples[len(samples) // 2],
        "p99": samples[int(len(samples) * 0.99)],
        "iterations": MEASURE_ITERATIONS,
    }


if __name__ == "__main__":
    print("=== Aevum Benchmark Regression Check ===")
    print(f"Baseline p50:  {BASELINE_P50_MS:.3f}ms")
    print(f"Threshold p50: {REGRESSION_THRESHOLD_MS:.3f}ms")

    result = benchmark_ed25519_sign()

    if result.get("skipped"):
        print("Result: SKIP (dependencies not available)")
        sys.exit(0)

    p50 = result["p50"]
    p99 = result["p99"]
    print(f"Measured p50:  {p50:.3f}ms")
    print(f"Measured p99:  {p99:.3f}ms")

    if p50 > REGRESSION_THRESHOLD_MS:
        print(f"REGRESSION: p50 {p50:.3f}ms exceeds threshold {REGRESSION_THRESHOLD_MS:.3f}ms")
        print("Action required: investigate signing performance before next release.")
        sys.exit(1)
    else:
        print(f"OK: p50 {p50:.3f}ms is within threshold")
        sys.exit(0)

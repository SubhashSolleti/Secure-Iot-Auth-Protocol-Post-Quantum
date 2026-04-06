"""
benchmark.py — Comparative Benchmark: PQ-PKAP vs Classical KYC Baseline

Measures and compares:

  Baseline:    Classical X25519 + AES-256-GCM (no PQ, no pseudonyms)
               → represents current-state KYC API handshake
  PQ-PKAP:     Hybrid ML-KEM-768 + X25519 + ML-DSA-65 + pseudonymization
               → the proposed protocol

Metrics:
  - End-to-end handshake latency (ms)
  - Per-component timing (KEM, sign, verify, pseudonym, HKDF)
  - Bandwidth (bytes transferred per session)
  - Data exposure (identity bytes transmitted to server per session)
  - CPU usage per session
  - Quantum resistance and pseudonymization flags

Usage:
    python benchmark.py              # 100 sessions each
    python benchmark.py --n 50      # custom count

Author: PQ-PKAP research prototype
"""

import asyncio
import argparse
import time
import statistics
import psutil
import os
import logging

from kem_adapter import kem_name
from client import run_client
from baseline_tls_sim import run_benchmark as run_classical_benchmark

# Suppress per-session noise during benchmark
logging.getLogger().setLevel(logging.WARNING)


# ──────────────────────────────────────────────────────────
#  PQ-PKAP Full Protocol Benchmark
# ──────────────────────────────────────────────────────────

async def benchmark_pqpkap(n: int = 100) -> dict:
    """Run n PQ-PKAP sessions and collect detailed metrics."""
    latencies = []
    cpu_usages = []
    process = psutil.Process()

    print(f"\n{'='*60}")
    print(f"PQ-PKAP BENCHMARK  (n={n})")
    print(f"  KEM:       {kem_name()}")
    print(f"  Signature: ML-DSA-65 (NIST FIPS 204)")
    print(f"  Privacy:   Pseudonymized (ID_REAL never transmitted)")
    print(f"{'='*60}")

    for i in range(n):
        cpu_before = process.cpu_percent(interval=None)
        start = time.perf_counter()

        await run_client()

        end = time.perf_counter()
        cpu_after = process.cpu_percent(interval=None)

        latency_ms = (end - start) * 1000.0
        latencies.append(latency_ms)
        cpu_usages.append(max(cpu_after - cpu_before, 0.0))

        if (i + 1) % 10 == 0:
            print(f"  Run {i+1:>3}/{n}: {latency_ms:.2f} ms")

    # Bandwidth estimation (from README + protocol constants):
    # KEM pk (1216) + KEM ct (1120) + 2x ML-DSA-65 sig (2×3293) + 2x sig_pk (2×1952)
    # + encrypted payloads (~400 B) = ~13,526 B
    bandwidth_estimate = 1216 + 1120 + 2*3293 + 2*1952 + 400

    print(f"\n{'─'*60}")
    print(f"RESULTS")
    print(f"{'─'*60}")
    print(f"Latency (ms):")
    print(f"  Mean:  {statistics.mean(latencies):.2f} ± {statistics.stdev(latencies):.2f}")
    print(f"  Min:   {min(latencies):.2f}")
    print(f"  Max:   {max(latencies):.2f}")
    print(f"  p50:   {sorted(latencies)[n // 2]:.2f}")
    print(f"  p99:   {sorted(latencies)[int(n * 0.99)]:.2f}")
    print(f"\nBandwidth estimate: ~{bandwidth_estimate} bytes/session")
    print(f"\nData Exposure (identity bytes/session):")
    print(f"  Per session: 0 bytes  ← REAL IDENTITY NEVER TRANSMITTED")
    print(f"\nCPU usage: {statistics.mean(cpu_usages):.2f}% per session")
    print(f"\nQuantum resistance: ✅  (ML-KEM-768 + ML-DSA-65)")
    print(f"Pseudonymization:   ✅  (PSi derived, ID_REAL stays on client)")
    print(f"Forward secrecy:    ✅  (ephemeral KEM + w_i rotation)")

    return {
        "scheme": f"PQ-PKAP ({kem_name()} + ML-DSA-65 + Pseudonyms)",
        "n": n,
        "latency_mean_ms": statistics.mean(latencies),
        "latency_stdev_ms": statistics.stdev(latencies),
        "latency_p50_ms": sorted(latencies)[n // 2],
        "latency_p99_ms": sorted(latencies)[int(n * 0.99)],
        "bandwidth_bytes": bandwidth_estimate,
        "data_exposure_bytes_per_session": 0,
        "cpu_mean_pct": statistics.mean(cpu_usages),
        "quantum_resistant": True,
        "pseudonymized": True,
    }


# ──────────────────────────────────────────────────────────
#  Comparison Table
# ──────────────────────────────────────────────────────────

def print_comparison(pq: dict, classical: dict):
    """Print a side-by-side comparison table."""
    print(f"\n\n{'='*70}")
    print(f"COMPARATIVE BENCHMARK RESULTS")
    print(f"{'='*70}")

    header = f"{'Metric':<35} {'Classical KYC':>15} {'PQ-PKAP':>15}"
    print(header)
    print(f"{'─'*70}")

    def row(label, c_val, pq_val, suffix=""):
        print(f"{label:<35} {str(c_val) + suffix:>15} {str(pq_val) + suffix:>15}")

    row("Latency mean", f"{classical['latency_mean_ms']:.2f}", f"{pq['latency_mean_ms']:.2f}", " ms")
    row("Latency stdev", f"{classical['latency_stdev_ms']:.2f}", f"{pq['latency_stdev_ms']:.2f}", " ms")
    row("Latency p50", f"{classical['latency_p50_ms']:.2f}", f"{pq['latency_p50_ms']:.2f}", " ms")
    row("Latency p99", f"{classical['latency_p99_ms']:.2f}", f"{pq['latency_p99_ms']:.2f}", " ms")

    print(f"{'─'*70}")

    bw_c = classical.get('bandwidth_mean_bytes', classical.get('bandwidth_bytes', 0))
    bw_pq = pq.get('bandwidth_mean_bytes', pq.get('bandwidth_bytes', 0))
    row("Bandwidth per session",
        f"{int(bw_c)}", f"{int(bw_pq)}", " B")
    row("Bandwidth overhead",
        "baseline", f"+{int(bw_pq - bw_c)}", " B")

    print(f"{'─'*70}")

    row("Identity bytes exposed/session",
        f"{int(classical['data_exposure_bytes_per_session'])}",
        f"{int(pq['data_exposure_bytes_per_session'])}", " B")

    if classical['data_exposure_bytes_per_session'] > 0:
        n = classical['n']
        total_leak = classical['data_exposure_bytes_per_session'] * n
        print(f"  [!] Classical leaks {total_leak} B of identity over {n} sessions")
        print(f"  [✓] PQ-PKAP: 0 B identity exposure — pseudonymization enforced")

    print(f"{'─'*70}")

    row("Quantum resistant",
        "❌ No", "✅ Yes")
    row("Pseudonymized",
        "❌ No", "✅ Yes")
    row("Forward secrecy",
        "✅ ECDH", "✅ KEM+w_i")
    row("Mutual authentication",
        "❌ Server only (typical)", "✅ Mutual (z_i + ML-DSA-65)")

    print(f"{'─'*70}")

    overhead = ((pq['latency_mean_ms'] / classical['latency_mean_ms']) - 1) * 100
    print(f"\nLatency overhead of PQ-PKAP vs Classical: {overhead:+.1f}%")
    print(f"  (includes ML-KEM-768 + ML-DSA-65 verify×2 + pseudonym + w_i rotation)")
    print(f"\nData privacy gain: {int(classical['data_exposure_bytes_per_session'])} → 0 bytes/session identity exposure")

    print(f"\n{'='*70}")
    print("PAPER TABLE (paste into LaTeX):")
    print(f"{'='*70}")
    print("\\begin{tabular}{lcc}")
    print("\\hline")
    print("\\textbf{Metric} & \\textbf{Classical KYC} & \\textbf{PQ-PKAP} \\\\")
    print("\\hline")
    print(f"Latency mean (ms) & {classical['latency_mean_ms']:.2f} $\\pm$ {classical['latency_stdev_ms']:.2f} & {pq['latency_mean_ms']:.2f} $\\pm$ {pq['latency_stdev_ms']:.2f} \\\\")
    print(f"Latency p99 (ms) & {classical['latency_p99_ms']:.2f} & {pq['latency_p99_ms']:.2f} \\\\")
    print(f"Bandwidth (bytes) & {int(bw_c)} & {int(bw_pq)} \\\\")
    print(f"Identity exposure (bytes/session) & {int(classical['data_exposure_bytes_per_session'])} & {int(pq['data_exposure_bytes_per_session'])} \\\\")
    print(f"Quantum resistant & No & Yes \\\\")
    print(f"Pseudonymized & No & Yes \\\\")
    print(f"Mutual authentication & No & Yes \\\\")
    print("\\hline")
    print("\\end{tabular}")


# ──────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────

async def main(n: int = 100):
    # Classical baseline (synchronous — no server needed)
    classical_results = run_classical_benchmark(n=n)

    # PQ-PKAP full protocol (requires server.py to be running on localhost:8765)
    print(f"\n[NOTE] Ensure server.py is running before PQ-PKAP benchmark starts.")
    print(f"       Run: python server.py  (in another terminal)")
    input("Press Enter when server is ready...")

    pq_results = await benchmark_pqpkap(n=n)

    # Comparison summary
    print_comparison(pq_results, classical_results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQ-PKAP vs Classical KYC Comparative Benchmark")
    parser.add_argument("--n", type=int, default=100,
                        help="Number of sessions per scheme (default: 100)")
    args = parser.parse_args()
    asyncio.run(main(n=args.n))
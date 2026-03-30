import asyncio
import time
import logging
import statistics
import psutil
from kem_adapter import kem_name
from client import run_client

# Suppress per-session logging during benchmark to reduce noise
logging.getLogger().setLevel(logging.WARNING)


async def benchmark(n=100):
    latencies = []
    cpu_usages = []

    for i in range(n):
        process = psutil.Process()
        cpu_before = process.cpu_percent()
        start = time.perf_counter()

        await run_client()

        end = time.perf_counter()
        cpu_after = process.cpu_percent()

        latencies.append((end - start) * 1000)
        cpu_usages.append(cpu_after - cpu_before)

        print(f"Run {i+1}/{n}: {latencies[-1]:.2f} ms")

    print(f"\n{'='*50}")
    print(f"BENCHMARK RESULTS  (n={n})")
    print(f"{'='*50}")
    print(f"KEM:      {kem_name()}")
    print(f"Latency:  {statistics.mean(latencies):.2f} ± {statistics.stdev(latencies):.2f} ms")
    print(f"  Min:    {min(latencies):.2f} ms")
    print(f"  Max:    {max(latencies):.2f} ms")
    print(f"  p50:    {sorted(latencies)[n//2]:.2f} ms")
    print(f"  p99:    {sorted(latencies)[int(n*0.99)]:.2f} ms")
    print(f"CPU:      {statistics.mean(cpu_usages):.2f}% per run")


if __name__ == "__main__":
    asyncio.run(benchmark(100))
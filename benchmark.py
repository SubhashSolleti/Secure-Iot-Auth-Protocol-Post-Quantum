import asyncio
import time
import statistics
import psutil
from client import run_client

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

    print(f"\n=== BENCHMARK RESULTS (n={n}) ===")
    print(f"Latency:  {statistics.mean(latencies):.2f} ± {statistics.stdev(latencies):.2f} ms")
    print(f"CPU:      {statistics.mean(cpu_usages):.2f}% per run")
    print(f"KEM:      ML-KEM-768 (NIST FIPS 203)")

if __name__ == "__main__":
    asyncio.run(benchmark(100))
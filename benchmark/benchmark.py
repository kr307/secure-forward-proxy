"""
Secure Forward Proxy - Concurrency & Latency Benchmark Suite
Simulates concurrent clients routing HTTP & CONNECT requests through the proxy.
Measures requests/sec throughput, latency percentiles (p50, p95, p99), and connection stability.
"""

import argparse
import asyncio
import statistics
import time
from typing import List, Tuple
import aiohttp


async def mock_target_server(port: int = 9999):
    """Spins up a local zero-latency HTTP target server for benchmarking proxy overhead."""
    from aiohttp import web

    async def handle_ping(request):
        return web.Response(text="PONG_OK", content_type="text/plain")

    app = web.Application()
    app.router.add_get("/", handle_ping)
    app.router.add_get("/test", handle_ping)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    return runner


async def worker(
    proxy_url: str,
    target_url: str,
    requests_per_worker: int,
    latencies: List[float],
    status_counts: dict
):
    conn = aiohttp.TCPConnector(limit=0, force_close=True)
    async with aiohttp.ClientSession(connector=conn) as session:
        for _ in range(requests_per_worker):
            start = time.perf_counter()
            try:
                async with session.get(target_url, proxy=proxy_url, timeout=aiohttp.ClientTimeout(total=5.0)) as resp:
                    await resp.read()
                    duration_ms = (time.perf_counter() - start) * 1000.0
                    latencies.append(duration_ms)
                    code = resp.status
                    status_counts[code] = status_counts.get(code, 0) + 1
            except Exception as e:
                status_counts["ERROR"] = status_counts.get("ERROR", 0) + 1


async def run_benchmark(
    concurrency: int = 50,
    total_requests: int = 500,
    proxy_url: str = "http://127.0.0.1:8080",
    test_mode: str = "blocked"
):
    print(f"\n=================================================================")
    print(f"       AEGIS GATE PROXY PERFORMANCE BENCHMARK")
    print(f"=================================================================")
    print(f"  Concurrency Level:      {concurrency} simultaneous workers")
    print(f"  Total Requests:         {total_requests}")
    print(f"  Benchmark Target Mode:  {test_mode.upper()}")
    print(f"  Forward Proxy:          {proxy_url}")
    print(f"-----------------------------------------------------------------")

    target_runner = None
    if test_mode == "allowed":
        # Launch local mock upstream server on port 9999
        print("  Starting mock upstream target server on 127.0.0.1:9999...")
        target_runner = await mock_target_server(9999)
        target_url = "http://127.0.0.1:9999/test"
    else:
        # Test blocking speed against a blacklisted domain (e.g. facebook.com)
        target_url = "http://facebook.com/"

    latencies: List[float] = []
    status_counts: dict = {}
    reqs_per_worker = max(1, total_requests // concurrency)
    actual_total = reqs_per_worker * concurrency

    print(f"  Firing {actual_total} requests across {concurrency} async workers...")
    start_time = time.perf_counter()

    tasks = [
        worker(proxy_url, target_url, reqs_per_worker, latencies, status_counts)
        for _ in range(concurrency)
    ]
    await asyncio.gather(*tasks)

    total_time = time.perf_counter() - start_time
    rps = actual_total / total_time if total_time > 0 else 0

    if target_runner:
        await target_runner.cleanup()

    # Calculations
    latencies.sort()
    count = len(latencies)
    avg_lat = statistics.mean(latencies) if latencies else 0.0
    p50 = statistics.median(latencies) if latencies else 0.0
    p90 = latencies[int(count * 0.90)] if count > 0 else 0.0
    p95 = latencies[int(count * 0.95)] if count > 0 else 0.0
    p99 = latencies[int(count * 0.99)] if count > 0 else 0.0
    min_lat = latencies[0] if latencies else 0.0
    max_lat = latencies[-1] if latencies else 0.0

    print(f"\n-----------------------------------------------------------------")
    print(f"                       BENCHMARK RESULTS")
    print(f"-----------------------------------------------------------------")
    print(f"  Time taken for tests:   {total_time:.3f} seconds")
    print(f"  Complete requests:      {count} / {actual_total}")
    print(f"  Throughput:             {rps:.2f} requests/sec")
    print(f"-----------------------------------------------------------------")
    print(f"  Latency Percentiles (ms):")
    print(f"    Min:                  {min_lat:.2f} ms")
    print(f"    50% (Median):         {p50:.2f} ms")
    print(f"    90%:                  {p90:.2f} ms")
    print(f"    95%:                  {p95:.2f} ms")
    print(f"    99%:                  {p99:.2f} ms")
    print(f"    Max:                  {max_lat:.2f} ms")
    print(f"    Average:              {avg_lat:.2f} ms")
    print(f"-----------------------------------------------------------------")
    print(f"  HTTP Status Codes:")
    for code, num in sorted(status_counts.items(), key=lambda x: str(x[0])):
        print(f"    Status {code}:           {num}")
    print(f"=================================================================\n")


def main():
    parser = argparse.ArgumentParser(description="Proxy Concurrency Benchmark")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Number of concurrent clients")
    parser.add_argument("-n", "--requests", type=int, default=500, help="Total requests to dispatch")
    parser.add_argument("--proxy", default="http://127.0.0.1:8080", help="Proxy endpoint")
    parser.add_argument("--mode", choices=["blocked", "allowed"], default="blocked", help="Benchmark blocked or allowed pipeline")
    args = parser.parse_args()

    asyncio.run(run_benchmark(args.concurrency, args.requests, args.proxy, args.mode))


if __name__ == "__main__":
    main()

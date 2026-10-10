"""
Secure Forward Proxy - Concurrency & Latency Benchmark Suite
Simulates concurrent clients routing HTTP & CONNECT requests through the proxy.
Measures both the Policy Rejection Path (blocked targets) and the Upstream Forwarding Path (allowed targets).
"""

import argparse
import asyncio
import statistics
import time
from typing import Dict, List, Tuple
import aiohttp


async def mock_target_server(port: int = 9999):
    """Spins up a local zero-latency HTTP target server for benchmarking proxy forwarding overhead."""
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


async def run_single_benchmark(
    concurrency: int,
    total_requests: int,
    proxy_url: str,
    test_mode: str
) -> Dict[str, float]:
    target_runner = None
    if test_mode == "allowed":
        target_runner = await mock_target_server(9999)
        target_url = "http://127.0.0.1:9999/test"
    else:
        # Matches blacklisted category (social-media)
        target_url = "http://facebook.com/"

    latencies: List[float] = []
    status_counts: dict = {}
    reqs_per_worker = max(1, total_requests // concurrency)
    actual_total = reqs_per_worker * concurrency

    start_time = time.perf_counter()
    tasks = [
        worker(proxy_url, target_url, reqs_per_worker, latencies, status_counts)
        for _ in range(concurrency)
    ]
    await asyncio.gather(*tasks)
    total_time = time.perf_counter() - start_time

    if target_runner:
        await target_runner.cleanup()

    latencies.sort()
    count = len(latencies)
    rps = count / total_time if total_time > 0 else 0
    p50 = statistics.median(latencies) if latencies else 0.0
    p90 = latencies[int(count * 0.90)] if count > 0 else 0.0
    p95 = latencies[int(count * 0.95)] if count > 0 else 0.0
    p99 = latencies[int(count * 0.99)] if count > 0 else 0.0

    return {
        "mode": test_mode,
        "completed": count,
        "total": actual_total,
        "duration_sec": total_time,
        "rps": rps,
        "min_ms": latencies[0] if latencies else 0.0,
        "p50_ms": p50,
        "p90_ms": p90,
        "p95_ms": p95,
        "p99_ms": p99,
        "max_ms": latencies[-1] if latencies else 0.0,
        "avg_ms": statistics.mean(latencies) if latencies else 0.0,
        "status_counts": status_counts
    }


async def main_async(concurrency: int, total_requests: int, proxy_url: str, mode: str):
    modes = ["blocked", "allowed"] if mode == "all" else [mode]

    print("\n=================================================================")
    print("       AEGIS GATE PROXY BENCHMARK SUITE")
    print("=================================================================")
    print(f"  Concurrency Level: {concurrency} workers")
    print(f"  Total Requests:    {total_requests} per test mode")
    print(f"  Proxy Endpoint:    {proxy_url}")
    print("-----------------------------------------------------------------")

    results = []
    for m in modes:
        print(f"\n[+] Executing benchmark for: {m.upper()} pipeline...")
        res = await run_single_benchmark(concurrency, total_requests, proxy_url, m)
        results.append(res)

    print("\n=================================================================")
    print("                    COMPARATIVE BENCHMARK RESULTS")
    print("=================================================================")
    print(f"{'Metric':<28} | {'Policy Rejection (Blocked)':<24} | {'Upstream Forward (Allowed)':<24}")
    print("-" * 82)

    by_mode = {r["mode"]: r for r in results}
    b = by_mode.get("blocked", {})
    a = by_mode.get("allowed", {})

    def val(d, key, fmt="{:.2f}"):
        v = d.get(key)
        return fmt.format(v) if v is not None else "N/A"

    print(f"{'Throughput (req/s)':<28} | {val(b, 'rps'):<24} | {val(a, 'rps'):<24}")
    print(f"{'Median Latency p50 (ms)':<28} | {val(b, 'p50_ms'):<24} | {val(a, 'p50_ms'):<24}")
    print(f"{'90th Percentile p90 (ms)':<28} | {val(b, 'p90_ms'):<24} | {val(a, 'p90_ms'):<24}")
    print(f"{'95th Percentile p95 (ms)':<28} | {val(b, 'p95_ms'):<24} | {val(a, 'p95_ms'):<24}")
    print(f"{'99th Percentile p99 (ms)':<28} | {val(b, 'p99_ms'):<24} | {val(a, 'p99_ms'):<24}")
    print(f"{'Average Latency (ms)':<28} | {val(b, 'avg_ms'):<24} | {val(a, 'avg_ms'):<24}")
    print(f"{'Execution Time (sec)':<28} | {val(b, 'duration_sec', '{:.3f}'):<24} | {val(a, 'duration_sec', '{:.3f}'):<24}")
    print("=================================================================\n")


def main():
    parser = argparse.ArgumentParser(description="Proxy Concurrency Benchmark")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="Number of concurrent clients")
    parser.add_argument("-n", "--requests", type=int, default=500, help="Total requests to dispatch")
    parser.add_argument("--proxy", default="http://127.0.0.1:8080", help="Proxy endpoint")
    parser.add_argument("--mode", choices=["all", "blocked", "allowed"], default="all", help="Benchmark mode")
    args = parser.parse_args()

    asyncio.run(main_async(args.concurrency, args.requests, args.proxy, args.mode))


if __name__ == "__main__":
    main()

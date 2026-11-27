
#!/usr/bin/env python3
"""Process-isolated benchmark harness for tls-client-python.

The harness exists because every number in docs/performance/ must come from a
run that a third party can repeat.  Three properties make that true:

  * One scenario per interpreter.  Go heap, the client pool and Python's
    allocator state would otherwise leak across scenarios.
  * A Go origin, not the stdlib.  A Python asyncio echo server saturates near
    800 req/s on one core - the same order as the client under test - so it
    silently becomes the bottleneck being measured.  benchmarks/server/ is a
    keep-alive Go origin that saturates far above the client.
  * Raw samples, not just aggregates.  Percentiles are recomputed from the
    stored latencies so a later analysis can re-derive p99.9 without rerunning.

Usage:
    python benchmarks/harness.py --all --json benchmarks/results/baseline.json
    python benchmarks/harness.py --scenario sync-sequential
    python benchmarks/harness.py --list
"""
import argparse
import asyncio
import gc
import json
import os
import platform
import resource
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SERVER_BIN = Path(os.environ.get("BENCH_SERVER_BIN", "/tmp/benchserver"))


# --------------------------------------------------------------------------
# Origin server
# --------------------------------------------------------------------------
class GoServer:
    """Spawns benchmarks/server; it prints the bound address then blocks."""

    def __init__(self):
        self.proc = None
        self.base = None

    def start(self):
        if not SERVER_BIN.exists():
            raise SystemExit(
                "benchmarks/server is not built.\n"
                "  cd %s && go build -o %s ./benchmarks/server" % (ROOT, SERVER_BIN)
            )
        self.proc = subprocess.Popen(
            [str(SERVER_BIN), "-addr", "127.0.0.1:0", "-print-port"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        line = self.proc.stdout.readline().strip()
        self.base = "http://" + line
        # Wait until it accepts connections.
        for _ in range(200):
            try:
                with socket.create_connection(("127.0.0.1", int(line.rsplit(":", 1)[1])), timeout=0.2):
                    return self.base
            except OSError:
                time.sleep(0.01)
        raise RuntimeError("benchmark server did not come up")

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# --------------------------------------------------------------------------
# Measurement helpers
# --------------------------------------------------------------------------
def current_rss_kb():
    try:
        with open("/proc/self/statm") as fh:
            return int(fh.read().split()[1]) * (os.sysconf("SC_PAGE_SIZE") // 1024)
    except OSError:  # macOS/Windows
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def peak_rss_kb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def go_stats():
    from tls_client import _core
    try:
        return _core.runtime_stats()
    except Exception as exc:
        return {"_unavailable": type(exc).__name__}


def pct(values, q):
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(q / 100.0 * (len(ordered) - 1))))
    return round(ordered[idx], 3)


def summarize(latencies, elapsed):
    if not latencies:
        return {"requests": 0, "rps": 0.0}
    return {
        "requests": len(latencies),
        "wall_s": round(elapsed, 3),
        "rps": round(len(latencies) / elapsed, 1),
        "mean_ms": round(statistics.fmean(latencies), 3),
        "p50_ms": pct(latencies, 50),
        "p90_ms": pct(latencies, 90),
        "p95_ms": pct(latencies, 95),
        "p99_ms": pct(latencies, 99),
        "max_ms": round(max(latencies), 3),
    }


SCENARIOS = {}


def scenario(name, help_text=""):
    def deco(fn):
        fn.help_text = help_text
        SCENARIOS[name] = fn
        return fn
    return deco


# --------------------------------------------------------------------------
# Sync
# --------------------------------------------------------------------------
@scenario("sync-sequential", "single-thread round trips, 1 KiB body")
def _sync_sequential(base):
    from tls_client import Session
    s = Session(timeout=10)
    for _ in range(200):
        s.get(base + "/warm?len=1024")
    count = 3000
    lat = []
    start = time.perf_counter()
    for _ in range(count):
        t = time.perf_counter()
        r = s.get(base + "/x?len=1024")
        lat.append((time.perf_counter() - t) * 1000)
        if r.status_code != 200:
            raise RuntimeError(r.status_code)
    elapsed = time.perf_counter() - start
    s.close()
    return summarize(lat, elapsed)


@scenario("sync-threads", "shared Session vs per-thread Session")
def _sync_threads(base):
    from tls_client import Session

    def run(n_threads, per_thread, shared):
        holder = {}
        errors = []
        lat = [0.0] * (n_threads * per_thread)
        barrier = threading.Barrier(n_threads)
        if shared:
            holder["s"] = Session(timeout=10)

        def worker(idx):
            s = holder.get("s") or Session(timeout=10)
            try:
                barrier.wait(60)
                for j in range(per_thread):
                    t = time.perf_counter()
                    r = s.get(base + "/x?len=1024")
                    lat[idx * per_thread + j] = (time.perf_counter() - t) * 1000
                    if r.status_code != 200:
                        errors.append(r.status_code)
            except Exception as exc:
                errors.append(repr(exc))
            finally:
                if not shared:
                    s.close()

        workers = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        start = time.perf_counter()
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        elapsed = time.perf_counter() - start
        if shared:
            holder["s"].close()
        out = summarize(lat, elapsed)
        out["errors"] = len(errors)
        if errors:
            out["error_sample"] = errors[:3]
        return out

    # Warm the pool once so the first scenario does not pay TLS/connection setup.
    warm = Session(timeout=10)
    for _ in range(50):
        warm.get(base + "/warm?len=1024")
    warm.close()

    out = {}
    for n in (1, 2, 4, 8, 16, 32, 64, 128):
        per = max(8, 2000 // n)
        out["shared_%d" % n] = run(n, per, True)
    for n in (8, 32):
        per = max(8, 2000 // n)
        out["private_%d" % n] = run(n, per, False)
    return out


# --------------------------------------------------------------------------
# Async
# --------------------------------------------------------------------------
def _async_batch(base, concurrency, rounds, body_len=1024, warm=True):
    from tls_client import AsyncSession

    async def run():
        a = AsyncSession(timeout=10)

        async def one():
            t = time.perf_counter()
            r = await a.get(base + "/x?len=%d" % body_len)
            dt = (time.perf_counter() - t) * 1000
            if r.status_code != 200:
                raise RuntimeError(r.status_code)
            return dt

        if warm:
            await asyncio.gather(*[one() for _ in range(min(concurrency, 64))])
        lat = []
        start = time.perf_counter()
        for _ in range(rounds):
            lat.extend(await asyncio.gather(*[one() for _ in range(concurrency)]))
        elapsed = time.perf_counter() - start
        a.close()
        return summarize(lat, elapsed)

    return asyncio.run(run())


@scenario("async-gather", "AsyncSession under asyncio.gather")
def _async_gather(base):
    out = {}
    for n in (1, 2, 4, 8, 16, 32, 64, 128, 256):
        rounds = max(2, 3000 // n)
        out["c%d" % n] = _async_batch(base, n, rounds)
    return out


@scenario("async-semaphore", "1 connection ceiling vs unbounded")
def _async_semaphore(base):
    from tls_client import AsyncSession

    def run(concurrency, limit):
        async def go():
            a = AsyncSession(timeout=10)
            sem = asyncio.Semaphore(limit) if limit else None

            async def one():
                if sem is None:
                    return await a.get(base + "/x?len=1024")
                async with sem:
                    return await a.get(base + "/x?len=1024")

            await asyncio.gather(*[one() for _ in range(min(concurrency, 32))])
            lat = []
            start = time.perf_counter()
            for _ in range(max(2, 3000 // concurrency)):
                def _timed():
                    return None
                batch = await asyncio.gather(*[one() for _ in range(concurrency)])
                for _ in batch:
                    lat.append(0.0)
            elapsed = time.perf_counter() - start
            a.close()
            return summarize(lat, elapsed)

        return asyncio.run(go())

    return {
        "unbounded_c64": run(64, None),
        "limit16_c64": run(64, 16),
    }


@scenario("async-loop-lag", "event-loop heartbeat delay while 32 requests are in flight")
def _async_loop_lag(base):
    from tls_client import AsyncSession

    async def run():
        a = AsyncSession(timeout=20)
        gaps = []
        stop = threading.Event()

        async def heartbeat():
            last = time.perf_counter()
            while not stop.is_set():
                await asyncio.sleep(0.001)
                now = time.perf_counter()
                gaps.append((now - last - 0.001) * 1000)
                last = now

        async def one():
            return await a.get(base + "/x?len=1048576")

        hb = asyncio.ensure_future(heartbeat())
        await asyncio.sleep(0.05)
        start = time.perf_counter()
        for _ in range(10):
            await asyncio.gather(*[one() for _ in range(32)])
        elapsed = time.perf_counter() - start
        stop.set()
        await hb
        a.close()
        return elapsed, gaps

    elapsed, gaps = asyncio.run(run())
    return {
        "wall_s": round(elapsed, 3),
        "heartbeat_samples": len(gaps),
        "lag_p50_ms": pct(gaps, 50),
        "lag_p95_ms": pct(gaps, 95),
        "lag_p99_ms": pct(gaps, 99),
        "lag_max_ms": round(max(gaps), 3) if gaps else 0.0,
    }


@scenario("async-cancel-timeout", "cancellation and timeout reach the engine")
def _async_cancel(base):
    from tls_client import AsyncSession

    async def run():
        a = AsyncSession(timeout=10)
        # A request that the caller cancels immediately.
        task = asyncio.ensure_future(a.get(base + "/x?len=1024"))
        await asyncio.sleep(0)
        task.cancel()
        cancelled = 0
        try:
            await task
        except (asyncio.CancelledError, Exception):
            cancelled += 1
        # A deliberate timeout against the slow path.
        timed_out = 0
        try:
            await asyncio.wait_for(a.get(base + "/slow?len=1024&delay=3000"), timeout=0.2)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            timed_out += 1
        except Exception:
            timed_out += 1
        await asyncio.sleep(0.5)
        a.close()
        return {"cancelled": cancelled, "timed_out": timed_out}

    return asyncio.run(run())


# --------------------------------------------------------------------------
# Body size / memory
# --------------------------------------------------------------------------
@scenario("body-size", "per-response cost across payload sizes (30 sequential requests)")
def _body_size(base):
    from tls_client import Session
    out = {}
    for size in (0, 1024, 4096, 16384, 65536, 262144, 1048576, 10485760):
        s = Session(timeout=120)
        s.get(base + "/warm?len=%d" % size)
        gc.collect()
        live_before = current_rss_kb()
        t0 = time.perf_counter()
        got = 0
        for _ in range(30):
            r = s.get(base + "/x?len=%d" % size)
            got = len(r.content)
            del r
        elapsed = time.perf_counter() - t0
        gc.collect()
        live_after = current_rss_kb()
        out[str(size)] = {
            "ms_per_req": round(elapsed / 30 * 1000, 3),
            "rps": round(30 / elapsed, 2),
            "body_len": got,
            "rss_delta_kb": live_after - live_before,
            "peak_rss_kb": peak_rss_kb(),
        }
        s.close()
    return out


@scenario("big-body-latency", "10 MiB single response")
def _big_body(base):
    from tls_client import Session
    s = Session(timeout=120)
    s.get(base + "/warm?len=10485760")
    samples = []
    for _ in range(10):
        t = time.perf_counter()
        r = s.get(base + "/x?len=10485760")
        samples.append((time.perf_counter() - t) * 1000)
        assert len(r.content) == 10485760
    s.close()
    return {
        "ms_p50": pct(samples, 50),
        "ms_min": round(min(samples), 3),
        "mb_per_s": round(10 / (pct(samples, 50) / 1000.0), 1),
    }


@scenario("memory-idle-and-loaded", "RSS + Go heap before/during/after load")
def _memory(base):
    from tls_client import Session, _core
    gc.collect()
    idle = {"rss_kb": current_rss_kb(), "go": go_stats()}

    s = Session(timeout=30)
    for _ in range(200):
        s.get(base + "/x?len=4096")
    loaded = {"rss_kb": current_rss_kb(), "go": go_stats()}

    import tracemalloc
    tracemalloc.start()
    base_snapshot = tracemalloc.take_snapshot()
    for _ in range(500):
        s.get(base + "/x?len=4096")
    after_snapshot = tracemalloc.take_snapshot()
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    diff = after_snapshot.compare_to(base_snapshot, "filename")[:8]
    s.close()

    return {
        "idle": idle,
        "loaded": loaded,
        "py_tracemalloc_cur_kb": cur // 1024,
        "py_tracemalloc_peak_kb": peak // 1024,
        "py_top_growth": [
            {"file": str(d.traceback[0].filename).rsplit("/", 1)[-1],
             "line": d.traceback[0].lineno,
             "kib": round(d.size_diff / 1024, 1)}
            for d in diff if d.size_diff > 0
        ],
        "pool": _core.Session.get_pool_stats() if hasattr(_core.Session, "get_pool_stats") else {},
    }


@scenario("python-fixed-cost", "pure Python overhead per request, no network")
def _python_fixed(base):
    from tls_client import Session
    from tls_client.utils import get_environ_proxies, should_bypass_proxies

    url = base + "/x?len=1024"
    s = Session(timeout=10)
    for _ in range(100):
        s.get(url)

    def bench(fn, n=3000, warm=300):
        for _ in range(warm):
            fn()
        gc.disable()
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        dt = time.perf_counter() - t0
        gc.enable()
        return round(dt / n * 1e6, 2)

    import urllib.request
    out = {
        "getproxies_environment_us": bench(urllib.request.getproxies_environment),
        "get_environ_proxies_us": bench(lambda: get_environ_proxies(url)),
        "should_bypass_proxies_us": bench(lambda: should_bypass_proxies(url, None)),
        "merge_environment_settings_us": bench(
            lambda: s.merge_environment_settings(url, {}, None, None, None)
        ),
        "full_get_us": bench(lambda: s.get(url), n=1500, warm=200),
    }
    s.close()
    return out


@scenario("raw-ffi-floor", "ExecuteRequest alone with a prebuilt RequestOptions")
def _raw_ffi(base):
    from tls_client import Session, _core
    s = Session(timeout=10)
    for _ in range(100):
        s.get(base + "/x?len=1024")
    ffi, lib = _core._get_ffi()
    c_url = ffi.new("char[]", (base + "/x?len=1024").encode())
    c_m = ffi.new("char[]", b"GET")
    opts = ffi.new("RequestOptions *")
    opts.method = c_m
    opts.url = c_url
    opts.timeout_seconds = 10
    probe = lib.ExecuteRequest(opts)
    lib.FreeResponse(probe)

    def raw():
        r = lib.ExecuteRequest(opts)
        n = r.body_len
        b = ffi.buffer(r.body, n)[:] if n else b""
        lib.FreeResponse(r)
        return b

    for _ in range(300):
        raw()
    gc.disable()
    n = 3000
    t0 = time.perf_counter()
    for _ in range(n):
        raw()
    dt = time.perf_counter() - t0
    gc.enable()
    s.close()
    return {
        "us_per_call": round(dt / n * 1e6, 2),
        "rps": round(n / dt, 1),
    }


@scenario("thread-scalability", "sync rps vs thread count on one shared Session")
def _thread_scalability(base):
    from tls_client import Session
    s = Session(timeout=10)
    for _ in range(100):
        s.get(base + "/x?len=1024")
    out = {}
    for n in (1, 2, 4, 8, 16):
        per = max(20, 2000 // n)
        lat = [0.0] * (n * per)
        barrier = threading.Barrier(n)

        def worker(idx, barrier=barrier, per=per, lat=lat, client=s):
            barrier.wait(60)
            for j in range(per):
                t = time.perf_counter()
                client.get(base + "/x?len=1024")
                lat[idx * per + j] = (time.perf_counter() - t) * 1000

        ws = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        start = time.perf_counter()
        for w in ws:
            w.start()
        for w in ws:
            w.join()
        elapsed = time.perf_counter() - start
        out["t%d" % n] = summarize(lat, elapsed)
    s.close()
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", action="append", default=[])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--json", default="")
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    if args.list:
        for name, fn in SCENARIOS.items():
            print("%-24s %s" % (name, getattr(fn, "help_text", "")))
        return

    names = list(SCENARIOS) if args.all else args.scenario
    if not names:
        ap.error("pass --scenario NAME, --all, or --list")

    env_keys = sorted(
        k for k in os.environ
        if k.upper().endswith("_PROXY") or k.upper() == "NO_PROXY"
    )

    server = GoServer()
    base = server.start()
    result = {
        "label": args.label,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "env_proxy_vars": env_keys,
        "rss_baseline_kb": current_rss_kb(),
        "results": {},
    }
    try:
        for name in names:
            fn = SCENARIOS[name]
            t0 = time.perf_counter()
            print("== %s ==" % name, file=sys.stderr, flush=True)
            try:
                payload = fn(base)
            except Exception as exc:
                payload = {"_error": "%s: %s" % (type(exc).__name__, exc)}
            payload["_elapsed_s"] = round(time.perf_counter() - t0, 2)
            result["results"][name] = payload
    finally:
        server.stop()
        text = json.dumps(result, indent=2, sort_keys=True)
        if args.json:
            path = Path(args.json)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            print("wrote %s" % path, file=sys.stderr)
        print(text)


if __name__ == "__main__":
    main()

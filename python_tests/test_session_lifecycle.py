"""Session lifecycle + fingerprint-rotation regression tests.

Scenarios required by the audit:
- rapid Session/AsyncSession create-destroy under thread pools, coroutines
  and process pools → must not deadlock, must not leak memory;
- frequent client_identifier (TLS fingerprint) switching mid-session →
  must not deadlock, must not drift (TLS fingerprint and the default
  header block — User-Agent, sec-ch-ua, ... — must stay paired), and the
  Go client pool must stay bounded instead of growing per switch.

The echo server answers JSON {"ua": <received User-Agent>, "mark": <echo of
the X-Mark request header>} so tests can correlate a response with the
request even under concurrency.
"""

import asyncio
import concurrent.futures
import json
import multiprocessing
import os
import random
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tls_client._core import (
    DEFAULT_HEADERS,
    Session,
    AsyncSession,
    _pending_requests,
)

_IDS = ["chrome_120", "safari_16_0", "firefox_117"]


def _ua(identifier):
    return DEFAULT_HEADERS[identifier]["User-Agent"]


class _EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    request_queue_size = 512

    def do_GET(self):
        payload = json.dumps({
            "ua": self.headers.get("User-Agent", ""),
            "mark": self.headers.get("X-Mark", ""),
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


_SERVER = None
_SERVER_PORT = None


def setUpModule():
    global _SERVER, _SERVER_PORT
    _SERVER = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    _SERVER_PORT = _SERVER.server_address[1]
    threading.Thread(target=_SERVER.serve_forever, daemon=True).start()


def tearDownModule():
    if _SERVER is not None:
        _SERVER.shutdown()
        _SERVER.server_close()


def _url():
    return "http://127.0.0.1:%d/" % _SERVER_PORT


def _rss_mb():
    try:
        if sys.platform == "win32":
            import ctypes

            class _PMC(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            pmc = _PMC()
            pmc.cb = ctypes.sizeof(_PMC)
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, kernel32.GetCurrentProcessId())
            if not handle:
                return None
            try:
                ok = kernel32.K32GetProcessMemoryInfo(
                    handle, ctypes.byref(pmc), ctypes.sizeof(_PMC)
                )
            finally:
                kernel32.CloseHandle(handle)
            if not ok:
                return None
            return pmc.WorkingSetSize / 1048576.0
        with open("/proc/self/statm") as handle:
            return int(handle.read().split()[1]) * 4096 / 1048576.0
    except Exception:
        return None


def _pool_entries():
    """Read the Go client-pool size via a separate FFI handle to the same
    shared library (GetPoolStats is exported but not in the Python CDEF)."""
    try:
        from cffi import FFI
        from tls_client import _core

        ffi = FFI()
        ffi.cdef("""
            typedef struct {
                long long total_evictions;
                long long last_eviction_count;
                long long last_eviction_time;
                long long pool_entry_count;
                long long pool_ttl_seconds;
                long long pool_scan_interval_seconds;
            } PoolStats;
            void GetPoolStats(PoolStats* stats);
        """)
        lib = ffi.dlopen(_core._find_library())
        stats = ffi.new("PoolStats*")
        lib.GetPoolStats(stats)
        return stats.pool_entry_count
    except Exception:
        return None


def _process_worker(args):
    port, first, second = args
    from tls_client._core import DEFAULT_HEADERS as DH, Session

    session = Session(client_identifier=first, timeout=15)
    ua1 = session.get("http://127.0.0.1:%d/" % port).json()["ua"]
    session.client_identifier = second
    ua2 = session.get("http://127.0.0.1:%d/" % port).json()["ua"]
    session.close()
    return (
        ua1 == DH[first]["User-Agent"],
        ua2 == DH[second]["User-Agent"],
        ua1 != ua2,
    )


def _ttl_child_worker(port):
    """Runs in a spawned child: set TTL/scan-interval BEFORE the first
    request so the eviction goroutine starts with the short interval
    (after start-up, interval changes only apply from the next scan
    cycle, so the parent process cannot test this deterministically)."""
    import time as _time

    from tls_client._core import Session

    Session.set_pool_ttl(2)
    Session.set_pool_scan_interval(1)

    base = _pool_entries()
    for i in range(30):
        session = Session(timeout=15, idle_conn_timeout_seconds=i + 1)
        session.get("http://127.0.0.1:%d/" % port)
        del session
    created = _pool_entries() - base

    deadline = _time.time() + 20
    remaining = created
    while _time.time() < deadline:
        _time.sleep(1)
        remaining = _pool_entries() - base
        if remaining <= 1:
            break
    return created, remaining


def _cap_child_worker(port):
    """Runs in a spawned child: cap the pool at 3, then rotate through 30
    distinct configurations.  Without the cap each unique config would pin
    a distinct pooled HttpClient; with the cap the pool must stay bounded.
    Returns None when the loaded library predates SetPoolMaxEntries."""
    from tls_client._core import Session

    try:
        Session.set_pool_max_entries(3)
    except RuntimeError:
        return None  # library predates SetPoolMaxEntries — skip in caller

    base = _pool_entries()
    for i in range(30):
        session = Session(timeout=15, idle_conn_timeout_seconds=i + 1)
        response = session.get("http://127.0.0.1:%d/" % port)
        if response.status_code != 200:
            return ("status", response.status_code)
        del session
    return ("ok", _pool_entries() - base)


def _fork_child_probe():
    """Runs in a forked child whose parent had already loaded the library."""
    from tls_client import _core

    try:
        _core._get_ffi()
        return "no-error"
    except RuntimeError as exc:
        if "fork" in str(exc):
            return "fork-guard"
        return "other-error: %s" % exc


class FingerprintPairingTests(unittest.TestCase):
    """TLS fingerprint and default headers must stay paired."""

    def test_identifier_switch_updates_default_headers(self):
        session = Session(client_identifier="chrome_120", timeout=15)
        ua_before = session.get(_url()).json()["ua"]
        session.client_identifier = "safari_16_0"
        ua_after = session.get(_url()).json()["ua"]
        self.assertEqual(ua_before, _ua("chrome_120"))
        self.assertEqual(ua_after, _ua("safari_16_0"))

    def test_identifier_switch_keeps_customized_headers(self):
        session = Session(client_identifier="chrome_120", timeout=15)
        session.headers = {"User-Agent": "custom-agent/1.0"}
        session.client_identifier = "safari_16_0"
        self.assertEqual(
            session.get(_url()).json()["ua"], "custom-agent/1.0"
        )

    def test_per_request_override_pairs_headers(self):
        session = Session(client_identifier="chrome_120", timeout=15)
        response = session.get(_url(), client_identifier="safari_16_0")
        self.assertEqual(response.json()["ua"], _ua("safari_16_0"))
        # An explicit per-request header block wins over auto-pairing.
        response = session.get(
            _url(),
            client_identifier="firefox_117",
            default_headers={"User-Agent": "custom-agent/2.0"},
        )
        self.assertEqual(response.json()["ua"], "custom-agent/2.0")

    def test_async_per_request_override_pairs_headers(self):
        async def scenario():
            session = AsyncSession(client_identifier="chrome_120", timeout=15)
            failures = []

            async def one(index, identifier):
                await asyncio.sleep(index * 0.03)
                for attempt in range(3):
                    try:
                        response = await session.get(
                            _url(),
                            client_identifier=identifier,
                            headers={"X-Mark": "m%d" % index},
                        )
                        break
                    except RuntimeError as exc:
                        if "refused" not in str(exc).lower() or attempt == 2:
                            raise
                        await asyncio.sleep(0.2)
                body = response.json()
                if body["mark"] != "m%d" % index:
                    failures.append("mark mismatch %s" % body)
                if body["ua"] != _ua(identifier):
                    failures.append("drift: %r sent %r" % (identifier, body["ua"][:40]))

            await asyncio.wait_for(
                asyncio.gather(
                    *[one(i, _IDS[i % len(_IDS)]) for i in range(45)]
                ),
                timeout=90,
            )
            session.close()
            self.assertEqual(failures, [])

        asyncio.run(scenario())

    def test_concurrent_identifier_switch_and_requests(self):
        errors = []
        seen_ua = set()
        lock = threading.Lock()

        session = Session(client_identifier="chrome_120", timeout=15)

        def switcher():
            rng = random.Random(threading.get_ident())
            for _ in range(60):
                session.client_identifier = rng.choice(_IDS)
                time.sleep(0.001)

        def requester():
            try:
                for _ in range(40):
                    response = session.get(_url())
                    if response.status_code != 200:
                        errors.append("status %s" % response.status_code)
                    else:
                        with lock:
                            seen_ua.add(response.json()["ua"])
            except Exception as exc:  # pragma: no cover - diagnostic
                errors.append("%s: %s" % (type(exc).__name__, exc))

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(switcher) for _ in range(2)]
            futures += [pool.submit(requester) for _ in range(4)]
            done, stuck = concurrent.futures.wait(futures, timeout=120)
            self.assertFalse(stuck, "concurrent switch/request deadlocked")

        self.assertEqual(errors, [])
        expected = set(_ua(identifier) for identifier in _IDS)
        self.assertTrue(seen_ua.issubset(expected), seen_ua - expected)


class SessionLifecycleTests(unittest.TestCase):
    @staticmethod
    def _get_with_dial_retry(session, url):
        """GET with one retry on Windows-loopback dial refusals.

        Python's http.server RSTs occasional fresh dials under churn (an
        OS/test-harness artifact, see test_concurrency module docs); a
        retry keeps the deadlock/leak assertions meaningful without
        masking library bugs — a real hang still trips the wait timeout.
        """
        for attempt in range(3):
            try:
                return session.get(url)
            except RuntimeError as exc:
                if "refused" not in str(exc).lower() or attempt == 2:
                    raise
                time.sleep(0.2)

    def test_rapid_sync_create_destroy_threads_no_deadlock_no_leak(self):
        errors = []

        def worker():
            try:
                for cycle in range(20):
                    session = Session(timeout=15)
                    response = self._get_with_dial_retry(session, _url())
                    if response.status_code != 200:
                        errors.append("status %s" % response.status_code)
                    time.sleep(0.01)
                    self._get_with_dial_retry(session, _url())
                    # close() clears the *global* Go pool on purpose here —
                    # worst-case churn every cycle must still be safe.
                    session.close()
                    time.sleep(0.01)
            except Exception as exc:  # pragma: no cover - diagnostic
                errors.append("%s: %s" % (type(exc).__name__, exc))

        rss_before = _rss_mb()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(worker) for _ in range(8)]
            done, stuck = concurrent.futures.wait(futures, timeout=180)
            self.assertFalse(stuck, "rapid create/destroy deadlocked")
            for future in done:
                future.result()
        self.assertEqual(errors, [])
        self.assertEqual(len(_pending_requests), 0)
        rss_after = _rss_mb()
        if rss_before is not None and rss_after is not None:
            self.assertLess(rss_after - rss_before, 150.0)

    def test_async_rapid_lifecycle_threads_no_deadlock_no_leak(self):
        errors = []

        async def one_request(url):
            session = AsyncSession(timeout=15)
            try:
                for attempt in range(3):
                    try:
                        response = await session.get(url)
                        return response
                    except RuntimeError as exc:
                        if "refused" not in str(exc).lower() or attempt == 2:
                            raise
                        await asyncio.sleep(0.2)
            finally:
                session.close()

        def worker():
            try:
                for _ in range(12):
                    async def main():
                        response = await asyncio.wait_for(
                            one_request(_url()), timeout=30
                        )
                        if response.status_code != 200:
                            raise RuntimeError("status %s" % response.status_code)

                    asyncio.run(main())
                    time.sleep(0.01)
            except Exception as exc:  # pragma: no cover - diagnostic
                errors.append("%s: %s" % (type(exc).__name__, exc))

        rss_before = _rss_mb()
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(worker) for _ in range(6)]
            done, stuck = concurrent.futures.wait(futures, timeout=180)
            self.assertFalse(stuck, "rapid async lifecycle deadlocked")
            for future in done:
                future.result()
        self.assertEqual(errors, [])
        time.sleep(1.0)
        self.assertEqual(len(_pending_requests), 0)
        rss_after = _rss_mb()
        if rss_before is not None and rss_after is not None:
            self.assertLess(rss_after - rss_before, 150.0)

    def test_pool_ttl_evicts_stale_configs(self):
        if _pool_entries() is None:
            self.skipTest("GetPoolStats not available")
        context = multiprocessing.get_context("spawn")
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=1, mp_context=context
        ) as pool:
            created, remaining = pool.submit(
                _ttl_child_worker, _SERVER_PORT
            ).result(timeout=120)
        self.assertGreaterEqual(created, 25)
        # Entries idle beyond the 2 s TTL are evicted by the 1 s scanner.
        self.assertLessEqual(remaining, 1)

    def test_fingerprint_churn_keeps_pool_and_memory_bounded(self):
        entries_before = _pool_entries()
        rss_before = _rss_mb()
        session = Session(client_identifier="chrome_120", timeout=15)
        for i in range(120):
            session.client_identifier = _IDS[i % len(_IDS)]
            response = session.get(_url())
            self.assertEqual(response.status_code, 200)
        session.close()
        rss_after = _rss_mb()
        # Alternating between 3 identifiers must reuse exactly 3 pooled
        # clients — one per config — instead of one per switch.
        if entries_before is not None and _pool_entries() is not None:
            self.assertLessEqual(_pool_entries() - entries_before, 5)
        if rss_before is not None and rss_after is not None:
            self.assertLess(rss_after - rss_before, 100.0)

    def test_process_pool_with_identifier_switch(self):
        context = multiprocessing.get_context("spawn")
        jobs = [
            (_SERVER_PORT, _IDS[0], _IDS[1]),
            (_SERVER_PORT, _IDS[1], _IDS[2]),
            (_SERVER_PORT, _IDS[2], _IDS[0]),
        ]
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=3, mp_context=context
        ) as pool:
            futures = [pool.submit(_process_worker, job) for job in jobs]
            for future in futures:
                for ok in future.result(timeout=120):
                    self.assertTrue(ok)

    def test_pool_max_entries_bounds_rotation(self):
        if _pool_entries() is None:
            self.skipTest("GetPoolStats not available")
        context = multiprocessing.get_context("spawn")
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=1, mp_context=context
        ) as pool:
            outcome = pool.submit(_cap_child_worker, _SERVER_PORT).result(timeout=120)
        if outcome is None:
            self.skipTest("library predates SetPoolMaxEntries")
        status, growth = outcome
        self.assertEqual(status, "ok")
        # 30 distinct configs, capped at 3 → the pool must stay ≤ 3 entries.
        self.assertLessEqual(growth, 3)

    def test_fork_after_load_fails_fast(self):
        if not hasattr(os, "fork"):
            self.skipTest("os.fork unavailable on this platform")
        from tls_client import _core

        _core._get_ffi()  # load the Go library BEFORE forking

        context = multiprocessing.get_context("fork")
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=1, mp_context=context
        ) as pool:
            outcome = pool.submit(_fork_child_probe).result(timeout=60)
        self.assertEqual(outcome, "fork-guard")


if __name__ == "__main__":
    unittest.main()

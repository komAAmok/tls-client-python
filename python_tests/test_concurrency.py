"""High-concurrency regression tests for the tls_client binding.

Focus areas (per project audit requirements):
- no memory leak of `_pending_requests` under async bursts, cancellation,
  session close and hung-goroutine zombie timeouts;
- no deadlock / hang when sync sessions run inside thread pools nested in
  asyncio executors;
- safe fan-out through process pools (spawn);
- requests-compat idioms like ``session.timeout = None`` must not crash.

The tests talk to a local ThreadingHTTPServer.  Bursts are lightly
staggered because Windows loopback RSTs very large simultaneous SYN bursts
towards Python's accept loop — an OS artifact unrelated to the binding.
"""

import asyncio
import concurrent.futures
import multiprocessing
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tls_client import _core
from tls_client._core import (
    AsyncSession,
    Session,
    _apply_future_state,
    _compute_cache_key_hash,
    _defensive_timeout_seconds,
    _drop_pending_request,
    _normalize_int_fields,
    _on_zombie_timeout,
    _pending_lock,
    _pending_requests,
)

# ---------------------------------------------------------------------------
# Local test server
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.startswith("/slow"):
            time.sleep(0.2)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


_SERVER = None
_SERVER_PORT = None


def setUpModule():
    global _SERVER, _SERVER_PORT
    _SERVER = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    _SERVER.request_queue_size = 512
    _SERVER_PORT = _SERVER.server_address[1]
    threading.Thread(target=_SERVER.serve_forever, daemon=True).start()


def tearDownModule():
    if _SERVER is not None:
        _SERVER.shutdown()
        _SERVER.server_close()


def _url(path="/"):
    return "http://127.0.0.1:%d%s" % (_SERVER_PORT, path)


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
            # GetProcessMemoryInfo with the pseudo-handle can fail under
            # restricted tokens; open the own process by PID explicitly.
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
            return int(handle.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1048576.0
    except Exception:
        return None


class _RecordingHandler(BaseHTTPRequestHandler):
    """Records each request's headers so a test can assert on what was sent."""

    protocol_version = "HTTP/1.1"
    records = []

    def do_GET(self):
        type(self).records.append({k.lower(): v for k, v in self.headers.items()})
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _process_worker(args):
    port, count = args
    from tls_client._core import Session

    session = Session(timeout=10)
    try:
        total = 0
        for _ in range(count):
            total += session.get("http://127.0.0.1:%d/" % port).status_code
        return total
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Pure unit tests (no native library needed)
# ---------------------------------------------------------------------------

class NormalizeIntFieldsTests(unittest.TestCase):
    def test_none_maps_to_zero(self):
        resolved = {"timeout_seconds": None, "tcp_ttl": None}
        _normalize_int_fields(resolved)
        self.assertEqual(resolved["timeout_seconds"], 0)
        self.assertEqual(resolved["tcp_ttl"], 0)

    def test_bool_maps_to_int(self):
        resolved = {"max_connections_per_host": True, "timeout_milliseconds": False}
        _normalize_int_fields(resolved)
        self.assertEqual(resolved["max_connections_per_host"], 1)
        self.assertEqual(resolved["timeout_milliseconds"], 0)

    def test_regular_ints_untouched(self):
        resolved = {"timeout_seconds": 30, "tcp_mss": 1460}
        _normalize_int_fields(resolved)
        self.assertEqual(resolved["timeout_seconds"], 30)
        self.assertEqual(resolved["tcp_mss"], 1460)

    def test_normalization_keeps_cache_key_identical(self):
        template = {
            "client_identifier": "chrome_120", "proxy": None,
            "server_name_overwrite": None, "local_address": None,
            "insecure_skip_verify": 0, "force_http1": 0,
            "with_random_tls_extension_order": 1, "with_protocol_racing": 0,
            "max_idle_connections": None, "max_idle_connections_per_host": 0,
            "max_connections_per_host": True, "max_response_header_bytes": 0,
            "write_buffer_size": 0, "read_buffer_size": 0,
            "idle_conn_timeout_seconds": 0, "disable_keep_alives": 0,
            "disable_compression": 0, "disable_http3": 0, "disable_ipv4": 0,
            "disable_ipv6": 0, "follow_redirects": 0, "without_cookie_jar": 0,
            "allow_empty_cookies": 0, "with_default_bad_pin_handler": 0,
            "timeout_seconds": None, "timeout_milliseconds": False,
            "tcp_ttl": 0, "tcp_window_size": 0, "tcp_window_scale": 0,
            "tcp_mss": 0, "pseudo_header_order": None,
            "h3_pseudo_header_order": None, "default_headers": None,
            "connect_headers": None, "certificate_pinning_hosts": None,
            "client_certificates": None, "custom_tls_client": None,
        }
        _normalize_int_fields(template)
        self.assertEqual(
            _compute_cache_key_hash(template),
            _compute_cache_key_hash(dict(template, max_idle_connections=0,
                                          max_connections_per_host=1,
                                          timeout_seconds=0, timeout_milliseconds=0)),
        )


class DefensiveTimeoutTests(unittest.TestCase):
    def test_seconds_and_milliseconds(self):
        self.assertEqual(_defensive_timeout_seconds(30, 0), 62.0)
        self.assertEqual(_defensive_timeout_seconds(10, 0), 60.0)   # lower clamp
        self.assertEqual(_defensive_timeout_seconds(0, 500), 60.0)  # lower clamp
        self.assertEqual(_defensive_timeout_seconds(0, 120000), 242.0)
        self.assertEqual(_defensive_timeout_seconds(300, 0), 600.0)  # upper clamp

    def test_zero_uses_engine_default(self):
        # Go maps 0 to tls_client.DefaultTimeoutSeconds (30s), so the
        # defensive bound must assume 30s as well.
        self.assertEqual(_defensive_timeout_seconds(0, 0), 62.0)
        self.assertEqual(_defensive_timeout_seconds(None, None), 62.0)


class FutureStateTests(unittest.TestCase):
    def test_apply_state_ignores_completed_future(self):
        async def scenario():
            loop = asyncio.get_running_loop()
            done = loop.create_future()
            done.set_result("done")
            _apply_future_state(done, True, RuntimeError("late"))  # must not raise
            self.assertEqual(done.result(), "done")

            cancelled = loop.create_future()
            cancelled.cancel()
            _apply_future_state(cancelled, True, RuntimeError("late"))  # must not raise

        asyncio.run(scenario())

    def test_zombie_timeout_fails_future_and_cleans_up(self):
        async def scenario():
            loop = asyncio.get_running_loop()
            future = loop.create_future()
            with _pending_lock:
                _pending_requests[424242] = (future, [], None, None)

            _on_zombie_timeout(424242, 60.0)
            await asyncio.sleep(0)
            self.assertNotIn(424242, _pending_requests)
            self.assertTrue(future.done())
            with self.assertRaises(asyncio.TimeoutError):
                future.result()

            # Idempotent: a second (late) fire or callback pop finds nothing.
            _on_zombie_timeout(424242, 60.0)

        asyncio.run(scenario())

    def test_drop_pending_request_cancels_timer(self):
        async def scenario():
            loop = asyncio.get_running_loop()
            future = loop.create_future()
            handle = loop.call_later(30, lambda: None)
            with _pending_lock:
                _pending_requests[424243] = (future, [], handle, None)

            entry = _drop_pending_request(424243)
            self.assertIsNotNone(entry)
            self.assertTrue(handle.cancelled())
            self.assertFalse(future.done())
            self.assertIsNone(_drop_pending_request(424243))

        asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Native-library tests (skipped when the shared library is unavailable)
# ---------------------------------------------------------------------------

def _native_available():
    try:
        _core._get_ffi()
        return True
    except Exception:
        return False


@unittest.skipUnless(_native_available(), "native tls-client library not available")
class NativeConcurrencyTests(unittest.TestCase):
    def test_none_timeout_does_not_crash_sync(self):
        session = Session(timeout=None)
        self.assertEqual(session.get(_url()).status_code, 200)
        # None on other int-typed fields must be equally tolerated.
        response = session.get(_url(), max_idle_connections=None, tcp_ttl=None)
        self.assertEqual(response.status_code, 200)

    def test_none_timeout_does_not_crash_async(self):
        async def scenario():
            session = AsyncSession(timeout=None)
            response = await session.get(_url())
            self.assertEqual(response.status_code, 200)
            session.close()

        asyncio.run(scenario())

    def test_async_burst_drains_pending_requests(self):
        async def scenario():
            session = AsyncSession(timeout=10)
            async def one(index):
                await asyncio.sleep(index * 0.01)  # light stagger
                response = await session.get(_url())
                self.assertEqual(response.status_code, 200)
            await asyncio.wait_for(
                asyncio.gather(*[one(i) for i in range(100)]), timeout=60
            )
            session.close()

        asyncio.run(scenario())
        self.assertEqual(len(_pending_requests), 0)

    def test_async_cancel_midflight_is_clean(self):
        loop_exceptions = []

        async def scenario():
            loop = asyncio.get_running_loop()
            loop.set_exception_handler(
                lambda loop, context: loop_exceptions.append(context.get("exception"))
            )
            session = AsyncSession(timeout=10)
            task = asyncio.create_task(session.get(_url("/slow")))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await asyncio.sleep(0.8)  # let the Go callback fire afterwards
            session.close()

        asyncio.run(scenario())
        self.assertEqual(len(_pending_requests), 0)
        for exc in loop_exceptions:
            self.assertNotIsInstance(exc, asyncio.InvalidStateError)

    def test_close_while_inflight_fails_pending_cleanly(self):
        async def scenario():
            session = AsyncSession(timeout=10)
            tasks = [
                asyncio.create_task(session.get(_url("/slow"))) for _ in range(4)
            ]
            await asyncio.sleep(0.05)
            session.close()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                self.assertIsInstance(result, RuntimeError)
                self.assertIn("closed", str(result))
            await asyncio.sleep(0.8)  # late Go callbacks find no entry

        asyncio.run(scenario())
        self.assertEqual(len(_pending_requests), 0)

    def test_mixed_thread_pool_and_asyncio_no_deadlock(self):
        errors = []

        def sync_worker(worker_id):
            try:
                session = Session(timeout=15)
                for i in range(5):
                    response = session.get(_url("/slow" if i % 2 else "/"))
                    if response.status_code != 200:
                        errors.append("status %s" % response.status_code)
                session.close()
            except Exception as exc:  # pragma: no cover - diagnostic path
                errors.append("%s: %s" % (type(exc).__name__, exc))

        async def scenario():
            session = AsyncSession(timeout=15)
            loop = asyncio.get_running_loop()

            async def async_one(index):
                await asyncio.sleep(index * 0.02)
                response = await session.get(_url("/slow" if index % 3 else "/"))
                if response.status_code != 200:
                    errors.append("async status %s" % response.status_code)

            nested = concurrent.futures.ThreadPoolExecutor(max_workers=4)
            try:
                nested_jobs = [
                    loop.run_in_executor(nested, sync_worker, i) for i in range(8)
                ]
                coro_jobs = [async_one(i) for i in range(40)]
                await asyncio.wait_for(
                    asyncio.gather(*nested_jobs, *coro_jobs), timeout=60
                )
            finally:
                nested.shutdown(wait=True)
            session.close()

        asyncio.run(scenario())
        self.assertEqual(errors, [])
        self.assertEqual(len(_pending_requests), 0)

    def test_process_pool_smoke(self):
        context = multiprocessing.get_context("spawn")
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=2, mp_context=context
        ) as pool:
            futures = [
                pool.submit(_process_worker, (_SERVER_PORT, 4)) for _ in range(3)
            ]
            for future in futures:
                self.assertEqual(future.result(timeout=90), 800)

    def test_unique_default_headers_do_not_grow_the_client_pool(self):
        """A per-request default_headers block must not mint a pooled client.

        The profile default block is folded into the per-request headers by
        _merge_default_headers, and the engine only reads the client-level copy
        when the request carries no headers at all.  Keying default_headers
        therefore bought nothing and cost a lot: every unique block produced a
        distinct cache key, so the pool filled with one HttpClient (each with
        its own cookie jar and idle-connection pool) per block - measured at
        ~125 MB RSS after 3200 unique blocks, against ~53 MB when the same
        workload varies a per-request header instead.
        """
        session = Session(timeout=10)
        Session.clear_client_pool()
        try:
            for index in range(200):
                session.get(_url(), default_headers={"User-Agent": "UA-%d" % index})
            stats = Session.get_pool_stats()
        except RuntimeError as exc:  # library predates the GetPoolStats export
            self.skipTest(str(exc))
        finally:
            Session.clear_client_pool()
        self.assertLessEqual(
            stats["pool_entry_count"],
            1,
            "200 unique default_headers blocks created %d pooled clients; "
            "default_headers is folded into the request headers, so it must "
            "not participate in the client cache key"
            % stats["pool_entry_count"],
        )

    def test_pool_stats_reports_what_the_cache_key_controls(self):
        """get_pool_stats exposes the pool, so growth is measurable, not guessed."""
        try:
            before = Session.get_pool_stats()
        except RuntimeError as exc:
            self.skipTest(str(exc))
        for key in (
            "pool_entry_count",
            "pool_ttl_seconds",
            "pool_scan_interval_seconds",
            "total_evictions",
        ):
            self.assertIn(key, before)
        Session.clear_client_pool()
        self.assertEqual(Session.get_pool_stats()["pool_entry_count"], 0)
        session = Session(timeout=10)
        session.get(_url())
        self.assertEqual(Session.get_pool_stats()["pool_entry_count"], 1)
        # A distinct fingerprint is a distinct transport, so it IS a new client.
        session.get(_url(), client_identifier="safari_16_0")
        self.assertEqual(Session.get_pool_stats()["pool_entry_count"], 2)

    def test_async_override_pairs_headers_with_the_resolved_identifier(self):
        """The async auto-pairing must read the request snapshot, not live state.

        Reading the live session default is a TOCTOU race: a concurrent
        ``session.client_identifier = ...`` landing between the snapshot and
        the comparison can make the two compare equal, which skips the
        re-pairing and sends the snapshot profile's headers alongside the
        override's TLS fingerprint (a Chrome User-Agent with a Safari
        handshake, which is trivially detectable).
        """
        seen = []
        handler = _RecordingHandler
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        handler.records = seen
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = "http://127.0.0.1:%d/" % server.server_address[1]
        try:
            session = AsyncSession(client_identifier="chrome_120", timeout=10)
            snapshot = session._session._snapshot_selected_defaults

            def racing_snapshot(names):
                # Take the snapshot, then let a setter land before the caller
                # reaches the auto-pairing comparison.
                result = snapshot(names)
                session._session.defaults["client_identifier"] = "safari_16_0"
                return result

            session._session._snapshot_selected_defaults = racing_snapshot

            async def scenario():
                await session.get(url, client_identifier="safari_16_0")

            asyncio.run(scenario())
        finally:
            server.shutdown()
            server.server_close()
        self.assertTrue(seen, "the test server recorded no request")
        user_agent = seen[0].get("user-agent", "")
        self.assertIn(
            "Version/",
            user_agent,
            "async override sent %r; a Safari TLS fingerprint must not go out "
            "with a Chrome User-Agent" % user_agent,
        )

    def test_rss_growth_is_bounded(self):
        start = _rss_mb()
        if start is None:
            self.skipTest("RSS measurement not supported on this platform")

        async def burst():
            session = AsyncSession(timeout=10)
            async def one(index):
                await asyncio.sleep(index * 0.005)
                await session.get(_url())
            await asyncio.gather(*[one(i) for i in range(100)])
            session.close()

        for _ in range(3):
            session = Session(timeout=10)
            for _ in range(100):
                session.get(_url())
            session.close()
            asyncio.run(burst())

        growth = _rss_mb() - start
        # Working-set growth includes the Go runtime heap warming up; a leak
        # of response bodies / pending futures would grow it every round.
        self.assertLess(growth, 80.0, "RSS grew %.1f MB across rounds" % growth)


if __name__ == "__main__":
    unittest.main()

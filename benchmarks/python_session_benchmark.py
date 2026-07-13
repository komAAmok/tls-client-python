#!/usr/bin/env python3
import asyncio
import copy
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tls_client import AsyncSession, Session
from tls_client._core import (
    ASYNC_REQUEST_DEFAULT_KEYS,
    SYNC_REQUEST_DEFAULT_KEYS,
    _clone_default_value,
)


class FastServer(ThreadingHTTPServer):
    request_queue_size = 256


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def build_sample_defaults():
    return {
        "proxy": {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8081"},
        "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
        "h3_pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
        "default_headers": {"User-Agent": "bench", "Accept": "*/*", "X-Test": "1"},
        "connect_headers": {"Proxy-Authorization": "Basic abc"},
        "certificate_pinning_hosts": {"example.com": ["pin1", "pin2"]},
        "client_certificates": [{"cert_pem": b"cert", "key_pem": b"key"}],
        "custom_tls_client": {
            "ja3_string": "771,4865,0,29,0",
            "alpn_protocols": ["h2", "http/1.1"],
            "h2_settings": {"HEADER_TABLE_SIZE": 65536, "ENABLE_PUSH": 0},
        },
        "client_identifier": "chrome_120",
        "server_name_overwrite": "example.com",
        "local_address": "127.0.0.1",
        "insecure_skip_verify": 0,
        "force_http1": 0,
        "with_random_tls_extension_order": 1,
        "with_protocol_racing": 0,
        "max_idle_connections": 10,
        "max_idle_connections_per_host": 5,
        "max_connections_per_host": 10,
        "max_response_header_bytes": 16384,
        "write_buffer_size": 4096,
        "read_buffer_size": 4096,
        "idle_conn_timeout_seconds": 30,
        "disable_keep_alives": 0,
        "disable_compression": 0,
        "disable_http3": 0,
        "disable_ipv4": 0,
        "disable_ipv6": 0,
        "follow_redirects": 0,
        "without_cookie_jar": 0,
        "allow_empty_cookies": 0,
        "with_default_bad_pin_handler": 0,
        "timeout_seconds": 30,
        "timeout_milliseconds": 0,
        "tcp_ttl": 0,
        "tcp_window_size": 0,
        "tcp_window_scale": 0,
        "tcp_mss": 0,
        "catch_panics": 1,
        "with_debug": 0,
        "request_host_override": None,
        "request_cookies": {"a": "1", "b": "2"},
    }


def baseline_clone_all(defaults):
    return copy.deepcopy(defaults)


def baseline_clone_selected(defaults, keys):
    return {k: copy.deepcopy(defaults[k]) for k in keys if k in defaults}


def current_clone_selected(defaults, keys):
    return {k: _clone_default_value(defaults[k]) for k in keys if k in defaults}


def session_snapshot_selected(session, keys):
    return session._snapshot_selected_defaults(keys)


def simulated_old_snapshot_selected(defaults, keys):
    return {k: copy.deepcopy(defaults[k]) for k in keys if k in defaults}


def bench(name, fn, rounds=5000, warmup=200):
    for _ in range(warmup):
        fn()

    samples = []
    for _ in range(5):
        start = time.perf_counter()
        for _ in range(rounds):
            fn()
        samples.append((time.perf_counter() - start) * 1000)
    print(f"{name}: mean={mean(samples):.2f}ms runs={[round(v, 2) for v in samples]}")


def bench_sync_loopback(base_url):
    s = Session(timeout=5, headers={"X-Bench": "1"})
    samples = []
    for _ in range(3):
        start = time.perf_counter()
        for i in range(50):
            r = s.get(base_url + "/sync", params={"i": str(i)})
            assert r.status_code == 200
        samples.append((time.perf_counter() - start) * 1000)
    s.close()
    print(f"sync_loopback_50: mean={mean(samples):.2f}ms runs={[round(v, 2) for v in samples]}")


def bench_sync_threads(base_url):
    s = Session(timeout=5)
    samples = []
    for _ in range(3):
        errors = []
        start = time.perf_counter()

        def worker(idx):
            try:
                for j in range(10):
                    r = s.get(base_url + f"/t{idx}_{j}", params={"i": str(idx), "j": str(j)})
                    assert r.status_code == 200
            except Exception as exc:
                errors.append(repr(exc))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        samples.append((time.perf_counter() - start) * 1000)
        if errors:
            raise RuntimeError(f"sync thread benchmark errors: {errors}")

    s.close()
    print(f"sync_threads_8x10: mean={mean(samples):.2f}ms runs={[round(v, 2) for v in samples]}")


async def bench_async_loopback(base_url):
    a = AsyncSession(timeout=5)
    samples = []
    for _ in range(3):
        start = time.perf_counter()
        responses = await asyncio.gather(*[
            a.get(base_url + f"/a{i}", params={"i": str(i)}) for i in range(32)
        ])
        for r in responses:
            assert r.status_code == 200
        samples.append((time.perf_counter() - start) * 1000)
    a.close()
    print(f"async_gather_32: mean={mean(samples):.2f}ms runs={[round(v, 2) for v in samples]}")


def main():
    defaults = build_sample_defaults()
    session = Session()
    session.defaults.clear()
    session.defaults.update(copy.deepcopy(defaults))
    session._defaults_version += 1
    session._selected_snapshot_cache.clear()

    print("== config clone microbench ==")
    bench("baseline_all_defaults_deepcopy", lambda: baseline_clone_all(defaults), rounds=1500)
    bench(
        "baseline_selected_deepcopy_sync_keys",
        lambda: baseline_clone_selected(defaults, SYNC_REQUEST_DEFAULT_KEYS),
    )
    bench(
        "current_selected_clone_sync_keys",
        lambda: current_clone_selected(defaults, SYNC_REQUEST_DEFAULT_KEYS),
    )
    bench(
        "baseline_selected_deepcopy_async_keys",
        lambda: baseline_clone_selected(defaults, ASYNC_REQUEST_DEFAULT_KEYS),
    )
    bench(
        "current_selected_clone_async_keys",
        lambda: current_clone_selected(defaults, ASYNC_REQUEST_DEFAULT_KEYS),
    )
    bench(
        "simulated_old_session_snapshot_sync_keys",
        lambda: simulated_old_snapshot_selected(session.defaults, SYNC_REQUEST_DEFAULT_KEYS),
    )
    bench(
        "current_session_snapshot_sync_keys",
        lambda: session_snapshot_selected(session, SYNC_REQUEST_DEFAULT_KEYS),
    )
    bench(
        "simulated_old_session_snapshot_async_keys",
        lambda: simulated_old_snapshot_selected(session.defaults, ASYNC_REQUEST_DEFAULT_KEYS),
    )
    bench(
        "current_session_snapshot_async_keys",
        lambda: session_snapshot_selected(session, ASYNC_REQUEST_DEFAULT_KEYS),
    )

    server = FastServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"

    try:
        print("\n== loopback request bench ==")
        bench_sync_loopback(base)
        bench_sync_threads(base)
        asyncio.run(bench_async_loopback(base))
    finally:
        server.shutdown()
        server.server_close()
        session.close()


if __name__ == "__main__":
    main()

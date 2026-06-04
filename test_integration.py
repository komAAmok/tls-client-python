#!/usr/bin/env python3
"""
Integration test for the tls_client package.

Tests: import, library loading, Session creation, HTTP requests,
Response class, error handling, AsyncSession, and clear_client_pool.

Note: httpbin.org is behind Cloudflare which may return 503 for
TLS-fingerprinted clients.  The test falls back to alternate endpoints
and gracefully skips body-dependent checks on non-2xx responses.
"""

import sys
import traceback

# ── helpers ───────────────────────────────────────────────────────────

PASS = 0
FAIL = 0
SKIP = 0

def ok(msg: str) -> None:
    global PASS
    PASS += 1
    print(f"   ✅ {msg}")

def warn(msg: str) -> None:
    global SKIP
    SKIP += 1
    print(f"   ⚠️  {msg}")

def bad(msg: str) -> None:
    global FAIL
    FAIL += 1
    print(f"   ❌ {msg}")

# Alternate test endpoints (tried in order)
_ENDPOINTS = [
    "https://httpbingo.org",       # no Cloudflare
    "https://postman-echo.com",
    "https://httpbin.org",         # Cloudflare – may return 503
]

def _try_get(session, path: str, **kw):
    """Try GET against each endpoint; return (response, endpoint_name)."""
    for ep in _ENDPOINTS:
        url = f"{ep}{path}"
        try:
            resp = session.get(url, **kw)
            return resp, ep
        except RuntimeError as e:
            warn(f"{ep}: {e}")
            continue
    raise RuntimeError("All endpoints failed")


def _check_resp(resp, label: str) -> bool:
    """Print response summary.  Return True if body checks are safe."""
    print(f"   {label}: {resp}")
    print(f"   status_code:  {resp.status_code}")
    print(f"   ok:           {resp.ok}")
    print(f"   url:          {resp.url}")
    print(f"   protocol:     {resp.used_protocol}")
    print(f"   encoding:     {resp.encoding}")
    print(f"   content[:80]: {resp.content[:80]!r}")
    print(f"   headers:      {dict(list(resp.headers.items())[:3])}")
    print(f"   __repr__:     {repr(resp)}")
    print(f"   bool(resp):   {bool(resp)}")
    print(f"   reason:       {resp.reason}")
    print(f"   cookies:      {resp.cookies}")
    if not resp.ok:
        warn(f"non-2xx ({resp.status_code}) — skipping body-dependent checks")
        return False
    if not resp.content:
        warn("body is empty — skipping body-dependent checks")
        return False
    return True

# ── 1. Import ──────────────────────────────────────────────────────────

print("=" * 60)
print("1. Testing import…")
print("=" * 60)

try:
    import tls_client
    from tls_client import Session, AsyncSession, Request, Response, clear_client_pool
    ok(f"Import successful  (v{tls_client.__version__})")
except Exception as e:
    bad(f"Import failed: {e}")
    traceback.print_exc()
    sys.exit(1)

# ── 2. Library loading ────────────────────────────────────────────────

print("\n" + "=" * 60)
print("2. Testing library loading…")
print("=" * 60)

from tls_client._core import _find_library, _shared_lib_name, _detect_libc

try:
    libc = _detect_libc()
    print(f"   Detected libc: {libc}")
    print(f"   Expected binary: {_shared_lib_name()}")
    lib_path = _find_library()
    ok(f"Found: {lib_path}")
except FileNotFoundError as e:
    bad(f"Library not found: {e}")
    sys.exit(1)
except Exception as e:
    bad(f"Library loading failed: {e}")
    traceback.print_exc()
    sys.exit(1)

# ── 3. Session creation ───────────────────────────────────────────────

print("\n" + "=" * 60)
print("3. Testing Session creation…")
print("=" * 60)

try:
    s = Session(
        client_identifier="chrome_146",
        timeout=30,
        follow_redirects=True,
        catch_panics=True,
    )
    ok(f"Session created: {s}")
    ok(f"defaults has {len(s.defaults)} keys")
except Exception as e:
    bad(f"Session creation failed: {e}")
    traceback.print_exc()
    sys.exit(1)

# ── 4. HTTP GET ───────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("4. Testing HTTP GET…")
print("=" * 60)

try:
    resp, src = _try_get(s, "/get?foo=bar", headers={"X-Test": "hello"})
    ok(f"Request to {src} succeeded")
    body_ok = _check_resp(resp, "GET")
    if body_ok:
        data = resp.json()
        ok(f"json() keys: {list(data.keys())}")
except Exception as e:
    bad(f"GET request failed: {e}")
    traceback.print_exc()

# ── 5. HTTP POST ──────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("5. Testing HTTP POST…")
print("=" * 60)

try:
    resp, src = _try_get(s, "/post", headers={"Content-Type": "application/json"},
                         body=b'{"hello": "world", "num": 42}')
    # _try_get uses GET; override with POST
    resp = s.post(f"{src}/post", headers={"Content-Type": "application/json"},
                  body=b'{"hello": "world", "num": 42}')
    ok(f"POST to {src}: {resp.status_code}")
    if _check_resp(resp, "POST"):
        data = resp.json()
        ok(f"echoed json: {data.get('json', data.get('data', '(missing)'))}")
except Exception as e:
    bad(f"POST request failed: {e}")
    traceback.print_exc()

# ── 6. Response cookies ───────────────────────────────────────────────

print("\n" + "=" * 60)
print("6. Testing cookies…")
print("=" * 60)

try:
    resp, src = _try_get(s, "/cookies/set?session=abc123&user=test")
    print(f"   {src}: {resp.status_code}")
    print(f"   cookies: {resp.cookies}")
    if resp.cookies:
        ok(f"Got {len(resp.cookies)} cookies")
    else:
        warn("no cookies set (may need redirect-following)")
except Exception as e:
    bad(f"Cookie test failed: {e}")
    traceback.print_exc()

# ── 7. Response.raise_for_status ──────────────────────────────────────

print("\n" + "=" * 60)
print("7. Testing raise_for_status…")
print("=" * 60)

try:
    resp, _ = _try_get(s, "/status/404")
    print(f"   status_code: {resp.status_code}")
    try:
        resp.raise_for_status()
        bad("Should have raised RuntimeError")
    except RuntimeError as e:
        ok(f"Correctly raised: {e}")
except Exception as e:
    bad(f"404 request failed: {e}")
    traceback.print_exc()

# ── 8. Streaming to file ──────────────────────────────────────────────

print("\n" + "=" * 60)
print("8. Testing stream_to_file…")
print("=" * 60)

import tempfile, os

try:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp_path = tmp.name

    resp, src = _try_get(s, "/json")
    # Now stream to file using the working endpoint
    resp = s.stream_to_file("GET", f"{src}/json", tmp_path)
    print(f"   status_code: {resp.status_code}")
    print(f"   content:     {resp.content!r}  (empty = data on disk)")
    with open(tmp_path, "rb") as f:
        disk_data = f.read()
    ok(f"Streamed {len(disk_data)} bytes to disk")
    os.unlink(tmp_path)
except Exception as e:
    bad(f"Stream test failed: {e}")
    traceback.print_exc()

# ── 9. AsyncSession ───────────────────────────────────────────────────

print("\n" + "=" * 60)
print("9. Testing AsyncSession…")
print("=" * 60)

import asyncio

async def async_test():
    async with AsyncSession(client_identifier="chrome_146", timeout=30) as asess:
        # async fallback: try each endpoint manually
        resp = None
        for ep in _ENDPOINTS:
            url = f"{ep}/get"
            try:
                resp = await asess.get(url)
                src = ep
                break
            except RuntimeError:
                continue
        if resp is None:
            raise RuntimeError("All async endpoints failed")
        ok(f"Async GET to {src}: {resp.status_code}")
        return resp

try:
    asyncio.run(async_test())
except Exception as e:
    bad(f"Async test failed: {e}")
    traceback.print_exc()

# ── 10. clear_client_pool ─────────────────────────────────────────────

print("\n" + "=" * 60)
print("10. Testing clear_client_pool…")
print("=" * 60)

try:
    clear_client_pool()
    ok("clear_client_pool() succeeded")
except Exception as e:
    bad(f"clear_client_pool() failed: {e}")
    traceback.print_exc()

# ── Finish ─────────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print(f"RESULTS:  {PASS} passed  /  {SKIP} skipped  /  {FAIL} failed")
print("=" * 60)

if FAIL > 0:
    sys.exit(1)

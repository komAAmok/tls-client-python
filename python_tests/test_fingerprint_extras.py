"""Tests for the fingerprint presets, request-context layer and boundaries."""

import asyncio
import json
import re
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import tls_client
from tls_client._core import Session, AsyncSession
from tls_client._multipart_boundary import blink_boundary, boundary, gecko_boundary
from tls_client.context import (
    RequestContext,
    apply_context,
    compute_fetch_site,
    expand_client_hints,
    priority_header,
    sec_fetch_headers,
)
from tls_client.fingerprints import (
    apply as apply_preset,
    list_presets,
    load_preset_file,
    resolve,
)


class BoundaryTests(unittest.TestCase):
    def test_blink_shape(self):
        b = blink_boundary()
        self.assertTrue(b.startswith("----WebKitFormBoundary"))
        tail = b[len("----WebKitFormBoundary"):]
        self.assertEqual(len(tail), 16)
        self.assertRegex(tail, r"^[A-Za-z0-9]+$")

    def test_blink_double_weight_ab(self):
        # 'A'/'B' appear twice in the 64-slot map → ~2/64 vs 1/64 each.
        counts = {"A": 0, "B": 0, "C": 0, "Z": 0, "9": 0}
        total = 0
        for _ in range(4000):
            for ch in blink_boundary()[22:]:
                if ch in counts:
                    counts[ch] += 1
                total += 1
        self.assertGreater(counts["A"] / total, counts["Z"] / total * 1.3)
        self.assertGreater(counts["B"] / total, counts["9"] / total * 1.3)

    def test_gecko_shape(self):
        b = gecko_boundary()
        self.assertRegex(b, r"^-{27}\d{3,30}$")

    def test_boundary_alias(self):
        self.assertTrue(boundary("chrome").startswith("----WebKitFormBoundary"))
        self.assertTrue(boundary("firefox").startswith("---------------------------"))


class RegistryTests(unittest.TestCase):
    def test_list_and_resolve_inheritance(self):
        names = list_presets()
        self.assertIn("chrome_152_windows", names)
        self.assertIn("firefox_148_android", names)
        resolved = resolve("chrome_152_windows")
        # inherited from chrome_152_base
        self.assertEqual(resolved["client_identifier"], "chrome_152")
        self.assertEqual(
            resolved["pseudo_header_order"],
            [":method", ":authority", ":scheme", ":path"],
        )
        # own layer
        self.assertIn("Windows NT 10.0", resolved["default_headers"]["User-Agent"])

    def test_alias_resolution(self):
        self.assertEqual(
            resolve("chrome_152")["client_identifier"], "chrome_152"
        )
        self.assertEqual(
            resolve("firefox_148")["client_identifier"], "firefox_148"
        )

    def test_unknown_preset_raises(self):
        with self.assertRaises(ValueError):
            resolve("nope_999")

    def test_cycle_detection(self):
        from tls_client.fingerprints import registry

        registry.register({"name": "cyc_a", "based_on": "cyc_b"})
        registry.register({"name": "cyc_b", "based_on": "cyc_a"})
        with self.assertRaises(ValueError):
            resolve("cyc_a")

    def test_load_preset_file(self):
        import json
        import tempfile
        import os

        data = {
            "name": "my_custom_preset",
            "based_on": "chrome_152_windows",
            "default_headers": {"Accept-Language": "de-DE,de;q=0.9"},
        }
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(data, handle)
        handle.close()
        try:
            name = load_preset_file(handle.name)
            self.assertEqual(name, "my_custom_preset")
            resolved = resolve(name)
            self.assertEqual(
                resolved["default_headers"]["Accept-Language"], "de-DE,de;q=0.9"
            )
            # inherited keys survive the override
            self.assertIn("sec-ch-ua", resolved["default_headers"])
        finally:
            os.unlink(handle.name)


class ContextTests(unittest.TestCase):
    def test_fetch_site(self):
        self.assertEqual(compute_fetch_site("https://a.com/x", None), "none")
        self.assertEqual(
            compute_fetch_site("https://a.com/x", "https://a.com/y"), "same-origin"
        )
        self.assertEqual(
            compute_fetch_site("https://x.a.com/x", "https://y.a.com/"), "same-site"
        )
        self.assertEqual(
            compute_fetch_site("https://a.com/x", "https://b.com/"), "cross-site"
        )

    def test_sec_fetch_user_only_for_user_navigations(self):
        nav = RequestContext.navigation("https://a.com/")
        self.assertEqual(sec_fetch_headers(nav).get("sec-fetch-user"), "?1")
        xhr = RequestContext.xhr("https://a.com/api")
        self.assertNotIn("sec-fetch-user", sec_fetch_headers(xhr))

    def test_priority_values(self):
        # Captured Chrome 147 table (httpcloak defaultPriorityTable):
        # document u=0,i / empty u=1,i / image u=2,i / script u=1 / style u=0.
        self.assertEqual(
            priority_header(RequestContext(dest="document")),
            "u=0, i",
        )
        self.assertEqual(priority_header(RequestContext(dest="empty")), "u=1, i")
        self.assertEqual(priority_header(RequestContext(dest="image")), "u=2, i")
        self.assertEqual(priority_header(RequestContext(dest="script")), "u=1")
        self.assertIsNone(
            priority_header(RequestContext(dest="empty", urgency=3))
        )
        self.assertEqual(
            priority_header(RequestContext(dest="empty", urgency=3,
                                          incremental=True)),
            "i",
        )

    def test_apply_context_overrides_defaults_not_user(self):
        defaults = {
            "Accept": "text/html,...",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Mode": "navigate",
            "sec-fetch-user": "?1",
        }
        merged = apply_context(defaults, RequestContext.xhr("https://a.com/"))
        lowered = {k.casefold(): v for k, v in merged.items()}
        self.assertEqual(lowered["accept"], "*/*")
        self.assertNotIn("upgrade-insecure-requests", lowered)
        self.assertNotIn("sec-fetch-user", lowered)
        # original casing of the profile header is preserved on override
        self.assertEqual(merged["Sec-Fetch-Mode"], "cors")

    def test_user_headers_win(self):
        merged = apply_context(
            {"Accept": "custom", "Sec-Fetch-Mode": "cors-manual"},
            RequestContext.navigation("https://a.com/"),
            user_keys={"accept", "sec-fetch-mode"},
        )
        self.assertEqual(merged["Accept"], "custom")
        self.assertEqual(merged["Sec-Fetch-Mode"], "cors-manual")
        self.assertEqual(merged["sec-fetch-dest"], "document")

    def test_expand_client_hints(self):
        hints = expand_client_hints(
            '"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"',
            ua_full_version="152.0.7977.1",
        )
        self.assertEqual(
            hints["sec-ch-ua-full-version-list"],
            '"Chromium";v="152.0.7977.1", "Not?A_Brand";v="24.0.0.0",'
            ' "Google Chrome";v="152.0.7977.1"',
        )


class _EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        recorded = {k.lower(): v for k, v in self.headers.items()}
        body = json.dumps({"ok": True, "headers": recorded}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


_SERVER = None
_PORT = None


def setUpModule():
    global _SERVER, _PORT
    _SERVER = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    _PORT = _SERVER.server_address[1]
    threading.Thread(target=_SERVER.serve_forever, daemon=True).start()


def tearDownModule():
    _SERVER.shutdown()
    _SERVER.server_close()


def _url():
    return "http://127.0.0.1:%d/" % _PORT


def _native_available():
    try:
        from tls_client import _core

        _core._get_ffi()
        return True
    except Exception:
        return False


@unittest.skipUnless(_native_available(), "native tls-client library not available")
class EndToEndTests(unittest.TestCase):
    def test_preset_navigation_via_native(self):
        session = Session(timeout=15)
        apply_preset(session, "chrome_133_windows")
        response = session.get(
            _url(), context=RequestContext.navigation(_url(), referrer=None)
        )
        headers = response.json()["headers"]
        self.assertTrue(headers["user-agent"].startswith("Mozilla/5.0 (Windows"))
        self.assertEqual(headers["sec-fetch-mode"], "navigate")
        self.assertEqual(headers["sec-fetch-site"], "none")
        self.assertEqual(headers["sec-fetch-user"], "?1")
        self.assertIn("priority", headers)

    def test_preset_xhr_via_native(self):
        session = Session(timeout=15)
        apply_preset(session, "chrome_133_windows")
        response = session.get(_url(), context=RequestContext.xhr(_url()))
        headers = response.json()["headers"]
        self.assertEqual(headers["accept"], "*/*")
        self.assertEqual(headers["priority"], "u=1, i")
        self.assertNotIn("upgrade-insecure-requests", headers)

    def test_compat_layer_fingerprint_and_context(self):
        compat = tls_client.Session(timeout=15, fingerprint="chrome_133_windows")
        response = compat.get(_url(), context=RequestContext.xhr(_url()))
        headers = response.json()["headers"]
        self.assertEqual(headers["accept"], "*/*")
        self.assertEqual(headers["sec-fetch-dest"], "empty")

    def test_async_preset_and_context(self):
        async def scenario():
            session = AsyncSession(timeout=15, fingerprint="chrome_133_windows")
            try:
                return await session.get(
                    _url(), context=RequestContext.xhr(_url())
                )
            finally:
                session.close()

        response = asyncio.run(scenario())
        headers = response.json()["headers"]
        self.assertEqual(headers["priority"], "u=1, i")


if __name__ == "__main__":
    unittest.main()

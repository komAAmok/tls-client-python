"""ABI 3 fingerprint-control coverage: presets, knobs and request plumbing.

These tests are pure-Python (no shared library required) — they exercise the
parts that can be validated without compiling: the generated Chrome preset
catalogue, the ABI 3 default keys, the tri-state TCP normalisation, and the
preset→session application path.
"""

import unittest

from tls_client._core import (
    _INT_REQUEST_KEYS,
    _TRISTATE_REQUEST_KEYS,
    _normalize_int_fields,
    ASYNC_REQUEST_DEFAULT_KEYS,
    SYNC_REQUEST_DEFAULT_KEYS,
)

ABI3_REQUEST_KEYS = (
    "extension_permute_mode",
    "extension_permute_prefix",
    "h2_disable_priority_frames",
    "header_order_by_dest",
    "header_order_dest",
    "tcp_dont_fragment",
    "tcp_tos",
    "tcp_no_delay",
    "tcp_window_clamp",
    "tcp_ip_id_mode",
)


class Abi3KeyTests(unittest.TestCase):
    def test_sync_defaults_cover_abi3(self):
        for key in ABI3_REQUEST_KEYS:
            self.assertIn(key, SYNC_REQUEST_DEFAULT_KEYS, key)

    def test_async_defaults_cover_abi3(self):
        for key in ABI3_REQUEST_KEYS:
            self.assertIn(key, ASYNC_REQUEST_DEFAULT_KEYS, key)

    def test_tristate_fields_are_int_keys(self):
        for key in _TRISTATE_REQUEST_KEYS:
            self.assertIn(key, _INT_REQUEST_KEYS, key)

    def test_tristate_none_maps_to_minus_one(self):
        resolved = {"tcp_dont_fragment": None, "tcp_tos": None, "tcp_no_delay": None}
        _normalize_int_fields(resolved)
        self.assertEqual(resolved["tcp_dont_fragment"], -1)
        self.assertEqual(resolved["tcp_tos"], -1)
        self.assertEqual(resolved["tcp_no_delay"], -1)

    def test_plain_int_none_maps_to_zero(self):
        resolved = {"tcp_window_clamp": None, "extension_permute_mode": None}
        _normalize_int_fields(resolved)
        self.assertEqual(resolved["tcp_window_clamp"], 0)
        self.assertEqual(resolved["extension_permute_mode"], 0)

    def test_tristate_zero_is_preserved(self):
        """0 is a real wire value (DF cleared / TOS 0 / Nagle off)."""
        resolved = {"tcp_dont_fragment": 0, "tcp_tos": 0, "tcp_no_delay": 0}
        _normalize_int_fields(resolved)
        self.assertEqual(resolved["tcp_dont_fragment"], 0)
        self.assertEqual(resolved["tcp_tos"], 0)
        self.assertEqual(resolved["tcp_no_delay"], 0)

    def test_bool_is_coerced_to_int(self):
        resolved = {"h2_disable_priority_frames": True, "header_order_by_dest": False}
        _normalize_int_fields(resolved)
        self.assertEqual(resolved["h2_disable_priority_frames"], 1)
        self.assertEqual(resolved["header_order_by_dest"], 0)


class ChromePresetCatalogueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tls_client.fingerprints import list_presets

        cls.names = set(list_presets())

    def test_all_majors_present(self):
        missing = [
            m for m in range(99, 154)
            if "chrome_%d" % m not in self.names
        ]
        self.assertEqual(missing, [], "missing bare Chrome aliases: %s" % missing)

    def test_per_os_variants_present(self):
        for os_name in ("windows", "macos", "linux", "android", "ios"):
            for major in (99, 116, 131, 146, 153):
                name = "chrome_%d_%s" % (major, os_name)
                self.assertIn(name, self.names, name)

    def test_base_presets_carry_abi3_knobs(self):
        from tls_client.fingerprints import resolve

        for major in (99, 120, 153):
            resolved = resolve("chrome_%d_base" % major)
            self.assertEqual(resolved["extension_permute_mode"], 1)
            self.assertEqual(resolved["extension_permute_prefix"], 0)
            self.assertTrue(resolved["header_order_by_dest"])
            self.assertFalse(resolved["h2_disable_priority_frames"])

    def test_per_os_tcp_fingerprints_are_coherent(self):
        from tls_client.fingerprints import resolve

        expectations = {
            "windows": (128, 64240, 8, 0, "random"),
            "macos": (64, 65535, 6, 1, "random"),
            "linux": (64, 65535, 7, 1, "random"),
            "android": (64, 65535, 7, 1, "random"),
            "ios": (64, 65535, 6, 1, "random"),
        }
        for os_name, (ttl, ws, wsc, df, ipid) in expectations.items():
            resolved = resolve("chrome_153_%s" % os_name)
            self.assertEqual(resolved["tcp_ttl"], ttl, os_name)
            self.assertEqual(resolved["tcp_window_size"], ws, os_name)
            self.assertEqual(resolved["tcp_window_scale"], wsc, os_name)
            self.assertEqual(resolved["tcp_dont_fragment"], df, os_name)
            self.assertEqual(resolved["tcp_ip_id_mode"], ipid, os_name)

    def test_per_os_user_agents_are_platform_coherent(self):
        from tls_client.fingerprints import resolve

        checks = {
            "windows": "Windows NT 10.0",
            "macos": "Macintosh; Intel Mac OS X",
            "linux": "X11; Linux x86_64",
            "android": "Android 10; K",
            "ios": "iPhone; CPU iPhone OS",
        }
        for os_name, needle in checks.items():
            resolved = resolve("chrome_153_%s" % os_name)
            ua = resolved["default_headers"]["User-Agent"]
            self.assertIn(needle, ua, "%s UA: %s" % (os_name, ua))

    def test_header_order_for_dest(self):
        from tls_client.fingerprints import header_order_for_dest

        nav = header_order_for_dest("document")
        sub = header_order_for_dest("script")
        self.assertIn("upgrade-insecure-requests", nav)
        self.assertIn("sec-fetch-user", nav)
        self.assertNotIn("upgrade-insecure-requests", sub)
        self.assertNotIn("sec-fetch-user", sub)
        self.assertIn("referer", sub)

    def test_header_order_unknown_dest_is_subresource(self):
        from tls_client.fingerprints import header_order_for_dest

        self.assertEqual(
            header_order_for_dest("something-weird"),
            header_order_for_dest("script"),
        )


class PresetApplyTests(unittest.TestCase):
    """`apply()` must write the ABI 3 knobs onto a session's defaults."""

    class _FakeSession:
        def __init__(self):
            self.defaults = {k: None for k in SYNC_REQUEST_DEFAULT_KEYS}
            self.client_identifier = None
            self.with_random_tls_extension_order = False
            self.pseudo_header_order = None
            self.h3_pseudo_header_order = None
            self.default_headers = None
            self.custom_tls_client = None

    def test_apply_writes_abi3_knobs(self):
        from tls_client.fingerprints import apply

        session = self._FakeSession()
        apply(session, "chrome_153_linux")
        self.assertEqual(session.client_identifier, "chrome_153")
        self.assertEqual(session.defaults["extension_permute_mode"], 1)
        self.assertEqual(session.defaults["header_order_by_dest"], 1)
        self.assertEqual(session.defaults["tcp_ttl"], 64)
        self.assertEqual(session.defaults["tcp_ip_id_mode"], "random")
        self.assertTrue(session.defaults["h2_disable_priority_frames"] is not None)


if __name__ == "__main__":
    unittest.main()

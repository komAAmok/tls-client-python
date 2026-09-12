"""Cache-key parity regression: Python hash vs Go buildCacheKeyFromConfig.

The constants here are pinned against the Go-side test
``cffi_binding/cachekey_parity_test.go`` (TestCacheKeyParityWithPython).
Both sides must produce byte-identical hashes for the same logical config
or the pre-computed cache-key hash will silently diverge from the Go
fallback and poison the client pool.  Format version: 5 (ABI 3 — extension
permutation, PRIORITY-frame suppression and the deep TCP fingerprint).
"""

import unittest

from tls_client._core import _compute_cache_key_hash

_TEST_PEM = b"-----BEGIN CERTIFICATE-----\nAAE=\n-----END CERTIFICATE-----\n"

_FULL = {
    "client_identifier": "chrome_133", "proxy": "", "server_name_overwrite": "",
    "local_address": "", "insecure_skip_verify": 0, "force_http1": 0,
    "with_random_tls_extension_order": 1, "with_protocol_racing": 0,
    "max_idle_connections": 0, "max_idle_connections_per_host": 0,
    "max_connections_per_host": 0, "max_response_header_bytes": 0,
    "write_buffer_size": 0, "read_buffer_size": 0,
    "idle_conn_timeout_seconds": 0, "disable_keep_alives": 0,
    "disable_compression": 0, "disable_http3": 0, "disable_ipv4": 0,
    "disable_ipv6": 0, "follow_redirects": 0, "without_cookie_jar": 0,
    "allow_empty_cookies": 0, "with_default_bad_pin_handler": 0,
    "timeout_seconds": 30, "timeout_milliseconds": 0,
    "tcp_ttl": 0, "tcp_window_size": 0, "tcp_window_scale": 0, "tcp_mss": 0,
    "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
    "h3_pseudo_header_order": None, "default_headers": {"User-Agent": "UA1"},
    "connect_headers": None, "certificate_pinning_hosts": None,
    "client_certificates": None, "custom_tls_client": None,
    "disable_session_tickets": 1, "tls_keylog_path": "C:/temp/kl.txt",
    "root_ca_pem": _TEST_PEM,
    "h2_max_data_frame_size": 14000, "preface_ping_idle_ms": 10000,
    "hpack_indexing_policy": "chrome",
    # ABI 3 — must all participate in the hash.
    "extension_permute_mode": 1, "extension_permute_prefix": 0,
    "h2_disable_priority_frames": 0,
    "tcp_dont_fragment": 0, "tcp_tos": 0, "tcp_no_delay": 1,
    "tcp_window_clamp": 0, "tcp_ip_id_mode": "random",
}

_MINIMAL = dict(
    _FULL,
    disable_session_tickets=0, tls_keylog_path=None, root_ca_pem=None,
    h2_max_data_frame_size=0, preface_ping_idle_ms=0,
    hpack_indexing_policy=None,
    pseudo_header_order=None,
    # ABI 3 fields reset to their "unset" sentinels.  Note the tri-state TCP
    # fields use -1 (0 is a meaningful wire value), which is exactly the
    # distinction _normalize_int_fields preserves.
    extension_permute_mode=0, extension_permute_prefix=0,
    h2_disable_priority_frames=0,
    tcp_dont_fragment=-1, tcp_tos=-1, tcp_no_delay=-1,
    tcp_window_clamp=0, tcp_ip_id_mode="",
    custom_tls_client={
        "ja3_string": "771,4865-4866-4867,0-23-65281,29-23-24,0",
        "connection_flow": 15663105,
        "trust_anchors_payload": "ABCD",
    },
)


class CacheKeyParityTests(unittest.TestCase):
    def test_full_vector(self):
        self.assertEqual(
            _compute_cache_key_hash(_FULL),
            "a2c79b647bc79f4cdb78ad3e2bbbda85ead64047d0c6bfa08b8c680fcba0f07d",
        )

    def test_minimal_vector(self):
        # The tri-state TCP fields hash RAW (-1 stays -1) and
        # extension_permute_mode is not collapsed through a truthiness test,
        # so this vector matches Go's buildCacheKeyFromConfig byte for byte.
        self.assertEqual(
            _compute_cache_key_hash(_MINIMAL),
            "fcdf48ebf9e03e1ff1d0b5c15be5f2da2f5e96e7bfd94cff94c3cc74ab7dca98",
        )

    def test_abi2_fields_participate(self):
        self.assertNotEqual(
            _compute_cache_key_hash(_FULL), _compute_cache_key_hash(_MINIMAL)
        )

    def test_abi3_extension_permute_participates(self):
        changed = dict(_MINIMAL, extension_permute_mode=2)
        self.assertNotEqual(
            _compute_cache_key_hash(_MINIMAL), _compute_cache_key_hash(changed)
        )

    def test_abi3_tristate_zero_differs_from_unset(self):
        """0 is a meaningful TCP value and must not hash like the -1 sentinel."""
        off = dict(_MINIMAL, tcp_no_delay=0)
        unset = dict(_MINIMAL, tcp_no_delay=-1)
        self.assertNotEqual(
            _compute_cache_key_hash(off), _compute_cache_key_hash(unset)
        )

    def test_abi3_ipid_mode_participates(self):
        changed = dict(_MINIMAL, tcp_ip_id_mode="zero")
        self.assertNotEqual(
            _compute_cache_key_hash(_MINIMAL), _compute_cache_key_hash(changed)
        )

    def test_deterministic(self):
        self.assertEqual(
            _compute_cache_key_hash(_FULL), _compute_cache_key_hash(dict(_FULL))
        )


if __name__ == "__main__":
    unittest.main()

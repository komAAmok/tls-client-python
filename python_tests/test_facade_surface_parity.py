# -*- coding: utf-8 -*-
"""The requests-compatible facade must not hide the native surface.

`tls_client.Session` (tls_client/sessions.py) is a requests-shaped facade in
front of `tls_client.NativeSession` (tls_client/_core.py).  It forwards each
request to `self._native`, so anything the engine exposes but the facade does
not re-expose silently disappears from the class the documentation points at.

That is exactly how `stream_to_file` shipped broken: it existed only on
NativeSession, so the documented `session.stream_to_file(...)` raised
AttributeError on `tls_client.Session`.

This test walks both surfaces per instance and fails on any public member the
facade lacks.
"""

import inspect
import unittest

import tls_client
from tls_client._core import Session as NativeSession
from tls_client.sessions import Session as FacadeSession

# Members of the native session that are deliberately not part of the facade,
# with the reason.  Everything else must be reachable.
_INTENTIONAL = {
    # The facade owns its own requests-style state under these names; the
    # native objects are reached through the facade's equivalent.
    "defaults": "the facade keeps its own option store",
    "client_identifier": "exposed as a facade property",
}

# Names the facade satisfies through instance attributes rather than class
# members (requests-compatible state created in __init__).
_INSTANCE_ATTRS = frozenset((
    "auth", "cert", "cookies", "headers", "params", "proxies", "proxy",
    "stream", "timeout", "verify", "follow_redirects", "fingerprint",
))


def _public(obj):
    return {
        name for name in dir(obj)
        if not name.startswith("_") and name not in _INTENTIONAL
    }


class FacadeSurfaceParityTests(unittest.TestCase):
    def test_facade_exposes_every_native_member(self):
        native = NativeSession()
        facade = FacadeSession()

        native_members = _public(native)
        self.assertGreater(len(native_members), 60, "native surface shrank unexpectedly")

        missing = sorted(
            name for name in native_members
            if not hasattr(facade, name)
        )
        self.assertEqual(
            missing, [],
            "tls_client.Session is missing native members: %s" % missing,
        )

    def test_stream_to_file_is_reachable_from_the_facade(self):
        # The specific regression, kept as its own case so the failure message
        # names the feature instead of a generic surface diff.
        facade = FacadeSession()
        self.assertTrue(
            hasattr(facade, "stream_to_file"),
            "tls_client.Session lost stream_to_file (documented in Readme.md)",
        )
        # The facade may narrow the signature, but it has to accept the same
        # positional shape the native method does: (method, url, output_path).
        native_params = [
            p.name for p in
            inspect.signature(NativeSession.stream_to_file).parameters.values()
            if p.kind in (p.POSITIONAL_OR_KEYWORD, p.POSITIONAL_ONLY)
        ]
        facade_params = [
            p.name for p in
            inspect.signature(FacadeSession.stream_to_file).parameters.values()
            if p.kind in (p.POSITIONAL_OR_KEYWORD, p.POSITIONAL_ONLY)
        ]
        for name in ("method", "url", "output_path"):
            self.assertIn(name, native_params, "native signature changed")
            self.assertIn(
                name, facade_params,
                "facade signature dropped %r; the documented call is "
                "session.stream_to_file(method, url, output_path)" % name,
            )


if __name__ == "__main__":
    unittest.main()

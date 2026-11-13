# -*- coding: utf-8 -*-
"""A WebSocket upgrade must never be able to block forever.

The handshake runs on the calling thread.  With no deadline, a peer that accepts
the TCP connection and then answers nothing blocks that thread indefinitely --
measured against a black-hole server, connect() hung past a 20 s external
timeout and produced no error at all, so a caller had no way to recover.

Three properties are pinned:

* an explicit ``handshake_timeout_milliseconds``` is honoured,
* omitting it still terminates (the deadline fires),
* the timeout is per client, so one session cannot shorten another's handshake.

The tests lower the *default* through
``websocket_set_default_handshake_timeout`` rather than waiting the shipped 30 s:
the property under test is "finite", not "exactly 30", and a load-time
environment variable was tried first and silently ignored because the library is
already loaded by the time a test module runs.
"""

import socket
import threading
import time
import unittest

from tls_client import _core
from tls_client.websocket import WebSocket

# Short enough to keep the suite fast, long enough to be distinguishable from the
# 600 ms explicit case.
TEST_DEFAULT_MS = 1500


class _BlackHoleServer:
    """Accepts connections and never answers, holding the sockets open."""

    def __init__(self, port=18852):
        self._server = socket.socket()
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", port))
        self._server.listen(8)
        self.port = port
        self._held = []
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self):
        while True:
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            self._held.append(conn)  # keep it open, send nothing

    def close(self):
        self._server.close()
        for conn in self._held:
            try:
                conn.close()
            except OSError:
                pass


class WebsocketHandshakeTimeoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _BlackHoleServer()
        _core._get_ffi()
        cls._previous_default = _core.websocket_set_default_handshake_timeout(
            TEST_DEFAULT_MS
        )

    @classmethod
    def tearDownClass(cls):
        _core.websocket_set_default_handshake_timeout(cls._previous_default)
        cls.server.close()

    def _client(self, **kwargs):
        return WebSocket(url="ws://127.0.0.1:%d/" % self.server.port,
                         client_identifier="chrome_154", **kwargs)

    def _attempt(self, client=None):
        client = client or self._client()
        start = time.perf_counter()
        with self.assertRaises(Exception):
            client.connect()
        return time.perf_counter() - start

    def test_explicit_timeout_is_honoured(self):
        elapsed = self._attempt(self._client(handshake_timeout_milliseconds=600))
        self.assertLess(elapsed, 5.0,
                        "an 600 ms handshake timeout took %.1fs" % elapsed)
        self.assertGreater(elapsed, 0.3,
                           "the explicit timeout fired too early (%.2fs)" % elapsed)

    def test_default_timeout_fires(self):
        """No explicit option still terminates, at the configured default."""
        elapsed = self._attempt()
        self.assertGreater(
            elapsed, TEST_DEFAULT_MS / 1000.0 * 0.5,
            "the default fired before the configured %d ms (%.2fs)"
            % (TEST_DEFAULT_MS, elapsed),
        )
        self.assertLess(
            elapsed, TEST_DEFAULT_MS / 1000.0 + 5.0,
            "the default handshake timeout did not fire (%.1fs)" % elapsed,
        )

    def test_one_clients_timeout_does_not_leak_to_another(self):
        """A timeout is per client, not a process-wide setting.

        A global would let any session that passes a short timeout silently
        shorten every other session's handshake -- including ones that never
        asked for it.
        """
        short_client = self._client(handshake_timeout_milliseconds=400)
        try:
            start = time.perf_counter()
            with self.assertRaises(Exception):
                short_client.connect()
            self.assertLess(time.perf_counter() - start, 3.0)
        except Exception:
            short_client.close()
            raise

        # A client that asks for nothing must get the default (TEST_DEFAULT_MS),
        # not this client's 400 ms.  short_client stays alive so its stored
        # timeout is still present while the second handshake runs.
        elapsed = self._attempt()
        short_client.close()
        self.assertGreater(
            elapsed, 0.4 * 1.5,
            "a client that set no timeout inherited another client's 400 ms "
            "(handshake gave up after %.2fs)" % elapsed,
        )


if __name__ == "__main__":
    unittest.main()

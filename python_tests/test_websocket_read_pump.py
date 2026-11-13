# -*- coding: utf-8 -*-
"""The WebSocket read pump: bounded backpressure without a thread per socket.

A blocking ``read_message`` parks the calling OS thread in recv.  One connection
per Python thread therefore costs a thread per idle socket, and nothing bounds
how far a fast peer may run ahead of a slow reader.

The pump moves the read into one Go goroutine per connection that feeds a
**bounded** channel.  When the channel fills, the goroutine stops reading the
socket, so TCP flow control reaches the peer: backpressure without dropping.
"""

import os
import socket
import subprocess
import time
import unittest

from tls_client.websocket import PUMP_CLOSED, PUMP_WOULD_WAIT, WebSocket

_WS_SERVER = "/tmp/wsserver/wssrv"


def _start_server(port=18841):
    server = subprocess.Popen([_WS_SERVER], stderr=subprocess.DEVNULL)
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return server
        except OSError:
            time.sleep(0.05)
    server.terminate()
    raise unittest.SkipTest("local websocket echo server did not start")


class WebsocketReadPumpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _start_server()
        cls.url = "ws://127.0.0.1:18841/"

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=5)

    def test_round_trip_through_the_pump(self):
        ws = WebSocket(url=self.url, client_identifier="chrome_154")
        conn = ws.connect()
        try:
            conn.start_read_pump(capacity=8)
            conn.send_text("hello-pump")
            got = conn.pump_read(timeout=5.0)
            self.assertIsNotNone(got, "pump returned nothing for an echoed frame")
            self.assertEqual(got[1], b"hello-pump")
            stats = conn.pump_stats()
            self.assertEqual(stats["delivered"], 1)
            self.assertEqual(stats["capacity"], 8)
        finally:
            conn.close()

    def test_timeout_returns_none_instead_of_blocking(self):
        ws = WebSocket(url=self.url, client_identifier="chrome_154")
        conn = ws.connect()
        try:
            conn.start_read_pump(capacity=8)
            t0 = time.perf_counter()
            got = conn.pump_read(timeout=0.25)
            elapsed = time.perf_counter() - t0
            self.assertIsNone(got, "an idle pump must report a timeout, not a message")
            # Generous upper bound: this is about "does not block forever".
            self.assertLess(elapsed, 2.0)
        finally:
            conn.close()

    def test_second_pump_is_refused(self):
        """Two readers on one socket would interleave frames."""
        ws = WebSocket(url=self.url, client_identifier="chrome_154")
        conn = ws.connect()
        try:
            conn.start_read_pump(capacity=8)
            with self.assertRaises(RuntimeError):
                conn.start_read_pump(capacity=8)
        finally:
            conn.close()

    def test_pump_does_not_add_a_thread_per_connection(self):
        """The point of the pump: idle connections share the Go scheduler."""
        def threads():
            return len(os.listdir("/proc/self/task"))

        conns = []
        try:
            for _ in range(6):
                ws = WebSocket(url=self.url, client_identifier="chrome_154")
                conns.append(ws.connect())
            before = threads()
            for conn in conns:
                conn.start_read_pump(capacity=4)
            time.sleep(0.2)
            after = threads()
            # Go goroutines multiplex onto existing OS threads, so N pumps must
            # not add N threads.
            self.assertLess(
                after - before, len(conns),
                "starting %d pumps added %d threads; the pump is supposed to "
                "share the scheduler" % (len(conns), after - before),
            )
        finally:
            for conn in conns:
                conn.close()


if __name__ == "__main__":
    unittest.main()

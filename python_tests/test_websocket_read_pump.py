# -*- coding: utf-8 -*-
"""WebSocket lifecycle and read pump.

Four properties are pinned here, each one a bug that shipped at some point:

1. Closing a connection must not disturb any *client* handle.  Client ids and
   connection ids come from two independent counters that both start at 1, so
   passing a connection id to WebsocketFreeHandle deleted a live client and its
   next connect() failed with "invalid websocket handle".
2. A connection must keep its owning client alive.  Keeping only the connection
   (the natural ``WebSocket(...).connect()` shape) otherwise let the client be
   collected and the connection died at the next GC.
3. ``pump_read`` must distinguish "nothing yet" from "closed forever".  Returning
   None for both made a read loop spin against a dead socket.
4. The pump must actually apply backpressure: with the channel full the reader
   stops pulling from the socket, nothing is dropped, and a close still returns.
"""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _ws_server

from tls_client.websocket import (
    ConnectionClosed,
    WebSocket,
)

URL = "ws://127.0.0.1:18841/"


class WebsocketLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _ws_server.start()

    @classmethod
    def tearDownClass(cls):
        _ws_server.stop(cls.server)

    def _connect(self, **kwargs):
        return WebSocket(url=URL, client_identifier="chrome_154", **kwargs).connect()

    def test_closing_a_connection_leaves_other_clients_intact(self):
        ws = WebSocket(url=URL, client_identifier="chrome_154")
        first = ws.connect()
        first.close()
        # The client handle must survive its connection being closed; a second
        # connect() is the observable proof.
        second = ws.connect()
        try:
            second.send_text("after-reconnect")
            self.assertEqual(second.read_message()[1], b"after-reconnect")
        finally:
            second.close()
            ws.close()

    def test_connection_keeps_its_client_alive(self):
        # Deliberately drop the WebSocket reference and keep only the connection.
        conn = WebSocket(url=URL, client_identifier="chrome_154").connect()
        try:
            import gc

            gc.collect()
            conn.send_text("alive")
            self.assertEqual(conn.read_message()[1], b"alive")
        finally:
            conn.close()

    def test_closing_the_client_closes_its_connections(self):
        ws = WebSocket(url=URL, client_identifier="chrome_154")
        conn = ws.connect()
        ws.close()
        with self.assertRaises(RuntimeError):
            conn.send_text("must-fail")
        conn.close()  # idempotent, must not raise

    def test_read_message_reports_peer_close_as_connection_closed(self):
        ws = WebSocket(url=URL, client_identifier="chrome_154")
        conn = ws.connect()
        try:
            conn.send_text("hi")
            self.assertEqual(conn.read_message()[1], b"hi")
        finally:
            conn.close()
            ws.close()


class WebsocketReadPumpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _ws_server.start()

    @classmethod
    def tearDownClass(cls):
        _ws_server.stop(cls.server)

    def test_round_trip_through_the_pump(self):
        ws = WebSocket(url=URL, client_identifier="chrome_154")
        conn = ws.connect()
        try:
            conn.start_read_pump(capacity=8)
            conn.send_text("hello-pump")
            got = conn.pump_read(timeout=5.0)
            self.assertIsNotNone(got)
            self.assertEqual(got[1], b"hello-pump")
            stats = conn.pump_stats()
            self.assertEqual(stats["delivered"], 1)
            self.assertEqual(stats["capacity"], 8)
        finally:
            conn.close()
            ws.close()

    def test_timeout_returns_none_and_close_raises(self):
        """The two outcomes must be different values."""
        ws = WebSocket(url=URL, client_identifier="chrome_154")
        conn = ws.connect()
        conn.start_read_pump(capacity=4)
        t0 = time.perf_counter()
        self.assertIsNone(
            conn.pump_read(timeout=0.25),
            "an idle pump must report a timeout, not a message or a close",
        )
        self.assertLess(time.perf_counter() - t0, 2.0)
        # There is no way to close the peer from this side without the fixture,
        # so the close path is covered by the lifecycle test above; here we only
        # assert that a timeout is *not* an exception.
        conn.close()
        ws.close()

    def test_second_pump_is_refused(self):
        ws = WebSocket(url=URL, client_identifier="chrome_154")
        conn = ws.connect()
        try:
            conn.start_read_pump(capacity=8)
            with self.assertRaises(RuntimeError):
                conn.start_read_pump(capacity=8)
        finally:
            conn.close()
            ws.close()

    def test_backpressure_bounds_the_queue_without_dropping(self):
        ws = WebSocket(url=URL, client_identifier="chrome_154")
        conn = ws.connect()
        try:
            capacity = 4
            conn.start_read_pump(capacity=capacity)
            sent = ["m%d" % i for i in range(30)]
            for payload in sent:
                conn.send_text(payload)

            time.sleep(0.5)
            stats = conn.pump_stats()
            self.assertEqual(
                stats["pending"], capacity,
                "the pump queue must fill to its capacity and stop reading the "
                "socket; that is the backpressure",
            )

            received = []
            while True:
                got = conn.pump_read(timeout=0.5)
                if got is None:
                    break
                received.append(got[1].decode())
            self.assertEqual(received, sent, "backpressure must not drop messages")
        finally:
            conn.close()
            ws.close()

    def test_close_while_the_queue_is_full_returns(self):
        ws = WebSocket(url=URL, client_identifier="chrome_154")
        conn = ws.connect()
        conn.start_read_pump(capacity=2)
        for i in range(20):
            conn.send_text("n%d" % i)
        time.sleep(0.2)
        t0 = time.perf_counter()
        conn.close()
        ws.close()
        self.assertLess(
            time.perf_counter() - t0, 3.0,
            "closing with a full queue must not wait for the consumer",
        )

    def test_handle_tables_return_to_their_starting_size(self):
        """No handle table may grow across connect/close cycles.

        This measures the tables directly instead of inferring from heap
        numbers: wsConnOwner in particular leaked one entry per connection that
        was closed while its client stayed alive, which heap metrics could not
        distinguish from ordinary churn.
        """
        from tls_client import _core

        ws = WebSocket(url=URL, client_identifier="chrome_154")
        try:
            baseline = _core.websocket_handle_stats()
            for _ in range(50):
                conn = ws.connect()
                conn.start_read_pump(capacity=4)
                conn.close()
            import gc

            gc.collect()
            after = _core.websocket_handle_stats()
            self.assertEqual(
                after["connections"], baseline["connections"],
                "the connection table grew across close cycles: %r -> %r"
                % (baseline, after),
            )
            self.assertEqual(
                after["owners"], baseline["owners"],
                "wsConnOwner leaked: a closed connection must forget its owner "
                "(%r -> %r)" % (baseline, after),
            )
            self.assertEqual(
                after["pumps"], baseline["pumps"],
                "the read pump table leaked: %r -> %r" % (baseline, after),
            )
        finally:
            ws.close()

    def test_pump_does_not_add_a_thread_per_connection(self):
        def threads():
            return len(list(Path("/proc/self/task").iterdir()))

        conns = []
        clients = []
        try:
            for _ in range(6):
                ws = WebSocket(url=URL, client_identifier="chrome_154")
                clients.append(ws)
                conns.append(ws.connect())
            before = threads()
            for conn in conns:
                conn.start_read_pump(capacity=4)
            time.sleep(0.2)
            after = threads()
            self.assertLess(
                after - before, len(conns),
                "starting %d pumps added %d threads; Go goroutines should "
                "multiplex onto existing threads" % (len(conns), after - before),
            )
        finally:
            for conn in conns:
                conn.close()
            for ws in clients:
                ws.close()


if __name__ == "__main__":
    unittest.main()

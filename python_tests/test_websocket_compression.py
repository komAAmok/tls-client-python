# -*- coding: utf-8 -*-
"""permessage-deflate must be offered only when asked for.

The engine has supported upstream's WithEnableCompression since the 1.18.1
sync, but the CFFI layer did not expose it, so WebSocketOptions carried no
flag and every client looked like one that does not support compression -
itself a fingerprint difference at the upgrade.  This test drives a local
socket server and reads the handshake request to prove the header is there
(and absent when disabled).
"""

import socket
import threading
import unittest

from tls_client.websocket import WebSocket


def _collect_upgrade_requests(port, expected):
    """Accept *expected* connections and return their handshake payloads."""
    captured = []
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(expected)

    def serve():
        try:
            for _ in range(expected):
                conn, _ = server.accept()
                captured.append(conn.recv(8192).decode("latin-1"))
                # Answer with a plain rejection: the handshake bytes are what
                # this test is about, not a completed upgrade.
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                conn.close()
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return captured, thread


def _extensions_header(payload):
    for line in payload.split("\r\n"):
        if line.lower().startswith("sec-websocket-extensions:"):
            return line.split(":", 1)[1].strip()
    return None


class WebsocketCompressionTests(unittest.TestCase):
    def test_compression_controls_the_extension_header(self):
        captured, thread = _collect_upgrade_requests(18771, 2)

        for compression in (False, True):
            ws = WebSocket(
                url="ws://127.0.0.1:18771/",
                client_identifier="chrome_154",
                compression=compression,
            )
            try:
                ws.connect()
            except Exception:
                pass  # the server rejects on purpose

        thread.join(timeout=5)
        self.assertEqual(len(captured), 2, "both handshakes should have arrived")

        plain, compressed = captured
        self.assertIsNone(
            _extensions_header(plain),
            "compression=False must not offer permessage-deflate",
        )
        header = _extensions_header(compressed)
        self.assertIsNotNone(header, "compression=True must offer an extension")
        self.assertIn("permessage-deflate", header)


if __name__ == "__main__":
    unittest.main()

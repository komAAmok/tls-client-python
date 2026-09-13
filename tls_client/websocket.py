"""TLS-fingerprinted WebSocket client (native Go engine).

Builds on the same ``tls-client`` Go engine as :mod:`tls_client` so a
WebSocket handshake carries the identical TLS fingerprint, HTTP/2 → HTTP/1.1
upgrade headers and connection pool settings as regular HTTP requests.

WebSocket requires HTTP/1.1, so the underlying fingerprint client is always
created with ``force_http1``.

Example::

    from tls_client import WebSocket

    ws = WebSocket(url="wss://echo.websocket.events", client_identifier="chrome_131")
    conn = ws.connect()
    conn.send_text("hello")
    message_type, data = conn.read_message()
    conn.close()
    ws.close()
"""

from typing import Dict, List, Optional, Tuple

import tls_client._core as _core

# Message type codes — mirror the Go `github.com/bogdanfinn/websocket` package.
TEXT = 1
BINARY = 2
CLOSE = 8
PING = 9
PONG = 10


def _read_error(ffi, lib, err_ptr) -> str:
    """Drain a ``char**`` out-param into a Python string, freeing the C buffer."""
    if err_ptr[0] == ffi.NULL:
        return "unknown error"
    message = ffi.string(err_ptr[0]).decode("utf-8", errors="replace")
    lib.FreeCString(err_ptr[0])
    err_ptr[0] = ffi.NULL
    return message


class WebSocketConnection:
    """A live, TLS-fingerprinted WebSocket connection.

    Returned by :meth:`WebSocket.connect`.  Use :meth:`send_text` /
    :meth:`send_binary` to write frames and :meth:`read_message` to read the
    next frame (blocking).
    """

    def __init__(self, conn_id: int) -> None:
        self._conn_id = conn_id
        self._closed = False

    @property
    def closed(self) -> bool:
        """``True`` once the connection has been closed."""
        return self._closed

    def read_message(self) -> Optional[Tuple[int, bytes]]:
        """Block until the next message arrives.

        Returns a ``(message_type, data)`` tuple.  ``message_type`` is one of
        :data:`TEXT` / :data:`BINARY` / :data:`PING` / :data:`PONG` / etc.;
        ``data`` is the raw payload bytes.  Returns ``None`` when the peer
        closes the connection cleanly.

        Raises :class:`RuntimeError` on a transport error.
        """
        if self._closed:
            raise RuntimeError("websocket connection is closed")
        ffi, lib = _core._get_ffi()
        err = ffi.new("char **")
        msg = lib.WebsocketReadMessage(self._conn_id, err)
        if msg == ffi.NULL:
            raise RuntimeError("websocket read failed: %s" % _read_error(ffi, lib, err))
        try:
            message_type = int(msg.message_type)
            if msg.data != ffi.NULL and int(msg.data_len) > 0:
                data = ffi.buffer(msg.data, int(msg.data_len))[:]
            else:
                data = b""
            return message_type, data
        finally:
            lib.WebsocketFreeMessage(msg)

    def send(self, data, message_type: int = TEXT) -> None:
        """Send one frame.  ``data`` may be ``str`` (UTF-8) or ``bytes``."""
        if self._closed:
            raise RuntimeError("websocket connection is closed")
        if isinstance(data, str):
            data = data.encode("utf-8")
        ffi, lib = _core._get_ffi()
        buf = ffi.from_buffer(data) if data else ffi.NULL
        err = ffi.new("char **")
        ret = lib.WebsocketWriteMessage(self._conn_id, message_type, buf, len(data), err)
        if ret != 0:
            raise RuntimeError("websocket send failed: %s" % _read_error(ffi, lib, err))

    def send_text(self, data) -> None:
        """Send a UTF-8 text frame."""
        self.send(data, TEXT)

    def send_binary(self, data: bytes) -> None:
        """Send a binary frame."""
        self.send(data, BINARY)

    def close(self) -> None:
        """Close the underlying connection (idempotent)."""
        if self._closed:
            return
        ffi, lib = _core._get_ffi()
        err = ffi.new("char **")
        lib.WebsocketClose(self._conn_id, err)
        lib.WebsocketFreeHandle(self._conn_id)
        self._conn_id = 0
        self._closed = True

    def __enter__(self) -> "WebSocketConnection":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class WebSocket:
    """A TLS-fingerprinted WebSocket client.

    Parameters mirror the native Go ``NewWebsocket`` + ``WithTlsClient``
    options.  The fingerprint client is created from ``client_identifier``
    (always with HTTP/1.1, as WebSocket requires).

    Parameters
    ----------
    url:
        WebSocket URL (``ws://`` or ``wss://``).  Required.
    client_identifier:
        TLS fingerprint identifier — one of
        :data:`tls_client.ClientIdentifiers`.
    headers:
        Extra handshake headers (e.g. ``User-Agent``, ``Origin``).
    header_order:
        Ordered list of header names controlling the wire order.
    read_buffer_size / write_buffer_size:
        Per-frame buffer sizes (0 = engine default).
    handshake_timeout_milliseconds:
        Handshake timeout (0 = engine default).
    """

    def __init__(
        self,
        *,
        url: str,
        client_identifier: str = "chrome_120",
        headers: Optional[Dict[str, str]] = None,
        header_order: Optional[List[str]] = None,
        read_buffer_size: int = 0,
        write_buffer_size: int = 0,
        handshake_timeout_milliseconds: int = 0,
    ) -> None:
        if client_identifier not in _core.SUPPORTED_CLIENT_IDENTIFIERS:
            raise ValueError("unsupported client_identifier %r" % client_identifier)

        ffi, lib = _core._get_ffi()
        keep_alive = []
        opts = ffi.new("WebsocketOptions *")
        keep_alive.append(opts)

        c_url = _core._c_string(ffi, url)
        keep_alive.append(c_url)
        opts.url = c_url

        c_ci = _core._c_string(ffi, client_identifier)
        keep_alive.append(c_ci)
        opts.client_identifier = c_ci

        opts.force_http1 = 1

        hdr_ptr, hdr_len = _core._build_headers(ffi, headers, keep_alive)
        opts.headers = hdr_ptr
        opts.headers_len = hdr_len

        ho_ptr, ho_len = _core._build_string_array(ffi, header_order, keep_alive)
        opts.header_order = ho_ptr
        opts.header_order_len = ho_len

        opts.read_buffer_size = read_buffer_size
        opts.write_buffer_size = write_buffer_size
        opts.handshake_timeout_milliseconds = handshake_timeout_milliseconds

        err = ffi.new("char **")
        ws_id = lib.WebsocketNew(opts, err)
        if ws_id == 0:
            raise RuntimeError("failed to create websocket: %s" % _read_error(ffi, lib, err))

        self._ws_id = ws_id
        self._closed = False

    @property
    def closed(self) -> bool:
        """``True`` once this client has been released."""
        return self._closed

    def connect(self) -> WebSocketConnection:
        """Open the WebSocket connection (blocking handshake)."""
        if self._closed:
            raise RuntimeError("websocket is closed")
        ffi, lib = _core._get_ffi()
        err = ffi.new("char **")
        conn_id = lib.WebsocketConnect(self._ws_id, err)
        if conn_id == 0:
            raise RuntimeError("websocket connect failed: %s" % _read_error(ffi, lib, err))
        return WebSocketConnection(conn_id)

    def close(self) -> None:
        """Release the client handle (idempotent)."""
        if self._closed:
            return
        ffi, lib = _core._get_ffi()
        lib.WebsocketFreeHandle(self._ws_id)
        self._ws_id = 0
        self._closed = True

    def __enter__(self) -> "WebSocket":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

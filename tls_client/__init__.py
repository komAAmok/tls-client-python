"""
tls_client  –  High-performance Python binding for
github.com/bogdanfinn/tls-client via CFFI + platform-native shared library.

The package auto‑detects the host OS and architecture at import time,
selecting the correct pre‑compiled binary from the bundled ``bin/``
directory.  A ``TLS_CLIENT_LIB`` environment variable may be used to
override automatic discovery.

Quick start
-----------
>>> from tls_client import Session
>>> s = Session(client_identifier="chrome_146")
>>> resp = s.get("https://httpbin.org/json")
>>> print(resp["status_code"], resp["text"][:50])

Async
-----
>>> from tls_client import AsyncSession
>>> async with AsyncSession() as s:
...     resp = await s.get("https://httpbin.org/json")
"""

from tls_client._core import (
    AsyncSession,
    Session,
    Request,
    Response,
    clear_client_pool,
)

__all__ = [
    "Session",
    "AsyncSession",
    "Request",
    "Response",
    "clear_client_pool",
]
__version__ = "1.0.0"

"""
tls_client  –  High-performance Python binding for
github.com/bogdanfinn/tls-client via CFFI + platform-native shared library.

The package auto‑detects the host OS and architecture at import time,
selecting the correct pre‑compiled binary from the bundled ``bin/``
directory.  A ``TLS_CLIENT_LIB`` environment variable may be used to
override automatic discovery.
"""

from tls_client._core import (
    AsyncSession,
    Session,
    Request,
    Response,
    ClientIdentifiers,
    clear_client_pool,
)

__all__ = [
    "Session",
    "AsyncSession",
    "Request",
    "Response",
    "ClientIdentifiers",
    "clear_client_pool",
]
__version__ = "1.15.0.3"

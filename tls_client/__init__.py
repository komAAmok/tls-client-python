"""
tls_client  –  High-performance Python binding for
github.com/bogdanfinn/tls-client via CFFI + platform-native shared library.

The package auto‑detects the host OS and architecture at import time,
selecting the correct pre‑compiled binary from the bundled ``bin/``
directory.  A ``TLS_CLIENT_LIB`` environment variable may be used to
override automatic discovery.
"""

from tls_client._core import AsyncSession, ClientIdentifiers, clear_client_pool
from tls_client._core import Request as TLSRequest
from tls_client._core import Response as NativeResponse
from tls_client._core import Session as NativeSession
from tls_client.requests_compat import (
    PreparedRequest,
    Request,
    Response,
    Session,
    TLSClientAdapter,
    delete,
    get,
    head,
    options,
    patch,
    post,
    put,
    request,
)

from tls_client import adapters, auth, cookies, exceptions, models, status_codes, structures
from tls_client.status_codes import codes

__all__ = [
    "Session",
    "AsyncSession",
    "Request",
    "PreparedRequest",
    "Response",
    "TLSClientAdapter",
    "NativeSession",
    "NativeResponse",
    "TLSRequest",
    "ClientIdentifiers",
    "clear_client_pool",
    "request",
    "get",
    "options",
    "head",
    "post",
    "put",
    "patch",
    "delete",
    "adapters",
    "auth",
    "codes",
    "cookies",
    "exceptions",
    "models",
    "status_codes",
    "structures",
]
__version__ = "1.16.0"

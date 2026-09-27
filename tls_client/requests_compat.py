"""Backwards-compatible re-exports of the requests facade.

The implementation moved to dedicated modules so each one mirrors the requests
module of the same name.  Import from there in new code::

    from tls_client.sessions import Session
    from tls_client.models import Request, PreparedRequest, Response
    from tls_client.adapters import BaseAdapter, TLSClientAdapter

This module keeps the historical import path working.
"""

# Historical alias: the native engine session used to be called NativeSession
# and was reachable through this module.
from tls_client._core import Request as TLSRequest
from tls_client._core import Response as NativeResponse
from tls_client._core import Session as NativeSession
from tls_client.adapters import BaseAdapter, TLSClientAdapter
from tls_client.api import delete, get, head, options, patch, post, put, request
from tls_client.models import PreparedRequest, Request, Response
from tls_client.sessions import Session

# The names above are re-exported through __all__, which is why the unused
# import warnings are suppressed.

__all__ = [
    "BaseAdapter",
    "NativeResponse",
    "NativeSession",
    "PreparedRequest",
    "Request",
    "Response",
    "Session",
    "TLSClientAdapter",
    "TLSRequest",
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
]

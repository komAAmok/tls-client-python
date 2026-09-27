"""
tls_client  -  High-performance Python binding for
github.com/bogdanfinn/tls-client via CFFI + platform-native shared library.

The package auto-detects the host OS and architecture at import time,
selecting the correct pre-compiled binary from the bundled bin/ directory.
A TLS_CLIENT_LIB environment variable may be used to override automatic
discovery.

The public surface is a drop-in superset of requests: every module, class,
function and constant requests exposes is re-exported here under the same name,
so "import tls_client as requests" runs existing code unchanged.  On top of
that, every tls-client specific knob is available as a session constructor
argument, a read/write session attribute, or a per-request override.
"""

import logging
import warnings
from logging import NullHandler

from tls_client import (  # noqa: F401  (requests parity)
    _internal_utils,
    _types,
    adapters,
    api,
    auth,
    certs,
    compat,
    cookies,
    ech,
    exceptions,
    fingerprints,
    help,
    hooks,
    models,
    packages,
    sessions,
    status_codes,
    structures,
    utils,
)
from tls_client import context as request_context
from tls_client.__version__ import (
    __author__,
    __author_email__,
    __build__,
    __cake__,
    __copyright__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
)
from tls_client._core import (
    SUPPORTED_CLIENT_IDENTIFIERS,
    AsyncSession,
    ClientIdentifiers,
    clear_client_pool,
)
from tls_client._core import Request as TLSRequest
from tls_client._core import Response as NativeResponse
from tls_client._core import Session as NativeSession
from tls_client._multipart_boundary import blink_boundary, boundary, gecko_boundary
from tls_client.adapters import BaseAdapter, HTTPAdapter, TLSClientAdapter
from tls_client.api import delete, get, head, options, patch, post, put, request
from tls_client.context import RequestContext
from tls_client.exceptions import (
    ConnectionError,
    ConnectTimeout,
    FileModeWarning,
    HTTPError,
    JSONDecodeError,
    ReadTimeout,
    RequestException,
    RequestsDependencyWarning,
    Timeout,
    TooManyRedirects,
    URLRequired,
)
from tls_client.models import (
    PreparedRequest as PreparedRequest,
)
from tls_client.models import Request as Request
from tls_client.models import Response as Response
from tls_client.sessions import Session as Session
from tls_client.sessions import session as session
from tls_client.status_codes import codes as codes
from tls_client.websocket import (
    BINARY as BINARY,
)
from tls_client.websocket import (
    CLOSE as CLOSE,
)
from tls_client.websocket import (
    PING as PING,
)
from tls_client.websocket import (
    PONG as PONG,
)
from tls_client.websocket import (
    TEXT as TEXT,
)
from tls_client.websocket import (
    WebSocket as WebSocket,
)
from tls_client.websocket import (
    WebSocketConnection as WebSocketConnection,
)

try:  # pragma: no cover - urllib3 is a dependency of requests, not of us
    from urllib3.exceptions import DependencyWarning
except ImportError:  # pragma: no cover
    DependencyWarning = RequestsDependencyWarning


def check_compatibility(
    urllib3_version=None,
    chardet_version=None,
    charset_normalizer_version=None,
) -> None:
    """Warn when an installed dependency is outside the supported range.

    requests calls this at import time for urllib3/chardet/charset_normalizer.
    The native engine owns its own TLS and decoding stack, so nothing here can
    break a request; the function exists so callers and tooling that probe
    requests.check_compatibility keep working.
    """
    if urllib3_version is None:
        try:
            import urllib3

            urllib3_version = urllib3.__version__
        except ImportError:
            return
    if chardet_version is None:
        try:
            from chardet import __version__ as chardet_version
        except ImportError:
            chardet_version = None
    if charset_normalizer_version is None:
        try:
            from charset_normalizer import __version__ as charset_normalizer_version
        except ImportError:
            charset_normalizer_version = None

    problems = []
    try:
        parts = urllib3_version.split(".")[:3]
        if len(parts) == 2:
            parts.append("0")
        major, minor = int(parts[0]), int(parts[1])
        if major < 1 or (major == 1 and minor < 21):
            problems.append("urllib3 %s" % urllib3_version)
    except (ValueError, IndexError):
        problems.append("urllib3 %s" % urllib3_version)

    for name, version, low, high in (
        ("chardet", chardet_version, (3, 0, 2), (8, 0, 0)),
        ("charset_normalizer", charset_normalizer_version, (2, 0, 0), (4, 0, 0)),
    ):
        if not version:
            continue
        try:
            parts = tuple(int(part) for part in version.split(".")[:3])
        except ValueError:
            continue
        if not low <= parts < high:
            problems.append("%s %s" % (name, version))

    if problems:
        warnings.warn(
            "%s does not match a supported version; the TLS engine ignores "
            "them, but other libraries may not." % ", ".join(problems),
            RequestsDependencyWarning,
        )

# Silence urllib3's DependencyWarning the way requests does; the native engine
# does not use urllib3 for transport.
warnings.simplefilter("ignore", DependencyWarning)

logging.getLogger(__name__).addHandler(NullHandler())

__all__ = [  # noqa: RUF022 - grouped by purpose, not alphabetically
    # -- requests API -------------------------------------------------------
    "Session",
    "session",
    "Request",
    "PreparedRequest",
    "Response",
    "request",
    "get",
    "options",
    "head",
    "post",
    "put",
    "patch",
    "delete",
    "codes",
    "adapters",
    "api",
    "auth",
    "certs",
    "compat",
    "cookies",
    "exceptions",
    "help",
    "hooks",
    "models",
    "packages",
    "sessions",
    "status_codes",
    "structures",
    "utils",
    "ConnectionError",
    "ConnectTimeout",
    "DependencyWarning",
    "FileModeWarning",
    "HTTPError",
    "JSONDecodeError",
    "ReadTimeout",
    "RequestException",
    "RequestsDependencyWarning",
    "Timeout",
    "check_compatibility",
    "TooManyRedirects",
    "URLRequired",
    # -- tls-client extensions ---------------------------------------------
    "AsyncSession",
    "ClientIdentifiers",
    "SUPPORTED_CLIENT_IDENTIFIERS",
    "BaseAdapter",
    "HTTPAdapter",
    "NativeSession",
    "NativeResponse",
    "TLSRequest",
    "TLSClientAdapter",
    "clear_client_pool",
    "ech",
    "fingerprints",
    "request_context",
    "RequestContext",
    "blink_boundary",
    "boundary",
    "gecko_boundary",
    "WebSocket",
    "WebSocketConnection",
    "TEXT",
    "BINARY",
    "CLOSE",
    "PING",
    "PONG",
    # -- metadata -----------------------------------------------------------
    "__title__",
    "__description__",
    "__url__",
    "__version__",
    "__build__",
    "__author__",
    "__author_email__",
    "__license__",
    "__copyright__",
    "__cake__",
]

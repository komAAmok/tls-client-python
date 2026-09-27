"""Transport adapters, mirroring requests.adapters."""

import io
import time
from datetime import timedelta
from http.client import responses as reason_phrases

from tls_client import exceptions
from tls_client._core import _load_client_certificates, _resolve_proxy_url
from tls_client.cookies import extract_cookies_to_jar  # noqa: F401
from tls_client.exceptions import (  # noqa: F401
    ConnectionError,
    ConnectTimeout,
    InvalidHeader,
    InvalidProxyURL,
    InvalidSchema,
    InvalidURL,
    ProxyError,
    ReadTimeout,
    RetryError,
    SSLError,
)
from tls_client.models import Response
from tls_client.structures import CaseInsensitiveDict  # noqa: F401
from tls_client.utils import (  # noqa: F401
    extract_zipped_paths,
    get_auth_from_url,
    get_encoding_from_headers,
    prepend_scheme_if_needed,
    select_proxy,
    urldefragauth,
)

#: requests.adapters re-exports the SOCKS pool manager when PySocks is present.
#: The native engine handles SOCKS5 itself, so the name exists only to keep
#: "from tls_client.adapters import SOCKSProxyManager" imports working.
try:  # pragma: no cover - optional dependency
    import warnings as _warnings

    with _warnings.catch_warnings():
        # urllib3 warns when PySocks is absent; the import still succeeds.
        _warnings.simplefilter("ignore")
        from urllib3.contrib.socks import SOCKSProxyManager  # type: ignore[import]
except Exception:  # pragma: no cover - urllib3 without socks support
    SOCKSProxyManager = None

DEFAULT_POOLBLOCK = False
DEFAULT_POOLSIZE = 10
DEFAULT_RETRIES = 0
DEFAULT_POOL_TIMEOUT = None

__all__ = [
    "DEFAULT_POOLBLOCK",
    "DEFAULT_POOLSIZE",
    "DEFAULT_POOL_TIMEOUT",
    "DEFAULT_RETRIES",
    "BaseAdapter",
    "HTTPAdapter",
    "SOCKSProxyManager",
    "TLSClientAdapter",
]


class BaseAdapter:
    """The base class for all transport adapters, mirroring requests."""

    def __init__(self):
        self.max_retries = DEFAULT_RETRIES
        self.config = {}
        self.proxy_manager = {}

    def send(self, request, stream=False, timeout=None, verify=True, cert=None,
             proxies=None):
        """Abstract method: send a PreparedRequest."""
        raise NotImplementedError

    def close(self):
        """Clean up the adapter's resources."""
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _timeout_options(timeout):
    """Translate a requests timeout into the engine's timeout keywords."""
    if timeout is None:
        return {}
    if isinstance(timeout, (tuple, list)):
        if len(timeout) != 2:
            raise ValueError("timeout must be a number or a (connect, read) tuple")
        values = [value for value in timeout if value is not None]
        if not values:
            return {}
        timeout = max(values)
    seconds = float(timeout)
    if seconds <= 0:
        raise ValueError("timeout must be greater than zero")
    if seconds.is_integer():
        return {"timeout": int(seconds)}
    return {"timeout_milliseconds": max(1, int(seconds * 1000))}


def _body_bytes(value):
    """Coerce a PreparedRequest body into the bytes the engine expects."""
    if value is None or isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if hasattr(value, "read"):
        value = value.read()
        return value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return b"".join(
        chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
        for chunk in value
    )


def _transport_error(error, request):
    """Map a native engine error onto the matching requests exception type."""
    message = str(error)
    lowered = message.lower()
    if "timeout" in lowered or "deadline exceeded" in lowered:
        kind = exceptions.Timeout
    elif "proxy" in lowered:
        kind = exceptions.ProxyError
    elif "certificate" in lowered or "tls" in lowered or "ssl" in lowered:
        kind = exceptions.SSLError
    else:
        kind = exceptions.ConnectionError
    return kind(message, request=request)


class TLSClientAdapter(BaseAdapter):
    """A requests adapter that sends through the native tls-client engine.

    It is also exported as HTTPAdapter, so requests.adapters.HTTPAdapter style
    configuration keeps working.
    """

    def __init__(self, native_session):
        super().__init__()
        self.native_session = native_session
        self._closed = False

    def send(
        self,
        request,
        stream=False,
        timeout=None,
        verify=True,
        cert=None,
        proxies=None,
        tls_options=None,
        **options
    ):
        """Send a PreparedRequest through the Go engine.

        requests arguments keep their meaning; tls_options carries the
        per-request TLS overrides collected from Session.request.
        """
        proxy = options.pop("proxy", None) or _resolve_proxy_url(proxies, request.url)
        options.update(_timeout_options(timeout))
        if tls_options:
            options.update(tls_options)
        options.update(
            body=_body_bytes(request.body),
            follow_redirects=False,
            headers=dict(request.headers.items()),
            proxy=proxy,
            verify=bool(verify),
        )
        if cert:
            options["client_certificates"] = _load_client_certificates(cert)
        started = time.monotonic()
        try:
            native = self.native_session.execute_request(
                request.method, request.url, **options
            )
        except RuntimeError as error:
            raise _transport_error(error, request)

        response = Response()
        response.status_code = native.status_code
        for name, values in native.headers.items():
            response.headers[name] = (
                ", ".join(str(item) for item in values)
                if isinstance(values, (list, tuple))
                else str(values)
            )
        response._content = native.content
        response._content_consumed = True
        response.raw = io.BytesIO(native.content)
        response.url = native.url or request.url
        response.reason = native.reason or reason_phrases.get(native.status_code, "")
        response.encoding = get_encoding_from_headers(response.headers)
        from tls_client.cookies import extract_cookies

        response.cookies = extract_cookies(native.headers, response.url)
        for name, value in (native.cookies or {}).items():
            if response.cookies.get(name) is None:
                response.cookies.set(name, value)
        response.elapsed = timedelta(seconds=time.monotonic() - started)
        response.request, response.connection = request, self
        response.used_protocol = native.used_protocol
        return response

    def close(self):
        """Mark the adapter closed.

        The Go client pool is process-global and TTL-evicted; individual
        sessions do not own pool entries.  Calling ClearClientPool() here would
        evict the clients pooled for every other concurrent session - and the
        top-level request() helpers close a session on every call, which used
        to nuke the whole pool under load.  Call
        NativeSession.clear_client_pool() explicitly when a global teardown is
        really intended.
        """
        self._closed = True


HTTPAdapter = TLSClientAdapter


def _encoding_from_headers(headers):
    """Backwards-compatible alias for utils.get_encoding_from_headers."""
    return get_encoding_from_headers(headers)

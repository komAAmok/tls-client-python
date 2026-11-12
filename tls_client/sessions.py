"""Requests-compatible Session: the full requests surface plus TLS controls.

The class is composed from three sources, so nothing can drift silently:

* tls_client._tls_surface.TLSOptionsMixin - every session-level TLS knob as an
  explicit read/write property.  "session = Session()" followed by
  "session.tcp_mss = 1460" therefore behaves exactly like
  "Session(tcp_mss=1460)", and IDEs/static analysis can see all of them.
* tls_client._tls_surface.TLSVerbMixin - request() and the seven verb helpers
  with explicit named parameters.
* this module - the requests semantics: attribute merging, redirects, hooks,
  environment proxies, digest auth replay and the mount/adapter machinery.

Every constructor parameter below is a real, literal keyword parameter, so
inspect.signature(), help() and IDE completion all see the complete surface.
"""

import os
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin, urlparse

from tls_client import exceptions
from tls_client._core import SUPPORTED_CLIENT_IDENTIFIERS, ClientIdentifiers
from tls_client._core import Session as NativeSession
from tls_client._internal_utils import to_native_string
from tls_client._tls_surface import (
    REQUESTS_OWNED_ATTRIBUTES,
    TLSOptionsMixin,
    TLSVerbMixin,
)
from tls_client.adapters import BaseAdapter, HTTPAdapter, TLSClientAdapter
from tls_client.auth import _basic_auth_str
from tls_client.cookies import (
    RequestsCookieJar,
    cookiejar_from_dict,
    extract_cookies_to_jar,
    merge_cookies,
)
from tls_client.exceptions import (
    ChunkedEncodingError,
    ContentDecodingError,
    InvalidSchema,
    TooManyRedirects,
)
from tls_client.hooks import default_hooks, dispatch_hook, merge_hooks, merge_setting
from tls_client.models import REDIRECT_STATI, PreparedRequest, Request
from tls_client.status_codes import codes
from tls_client.structures import CaseInsensitiveDict
from tls_client.utils import (
    default_headers,
    get_auth_from_url,
    get_environ_proxies,
    get_netrc_auth,
    requote_uri,
    resolve_proxies,
    rewind_body,
    should_bypass_proxies,
)

DEFAULT_REDIRECT_LIMIT = 30
DEFAULT_PORTS = {"http": 80, "https": 443}

#: requests picks the fastest monotonic clock the platform offers.
preferred_clock = getattr(time, "perf_counter", time.time)

#: Native (engine) options the facade passes straight to Session.__init__.
NATIVE_SESSION_OPTION_NAMES = frozenset(REQUESTS_OWNED_ATTRIBUTES) | frozenset(
    (
        "client_identifier",
        "force_http1",
        "disable_http3",
        "with_protocol_racing",
        "random_tls_extension_order",
        "timeout",
        "timeout_milliseconds",
        "follow_redirects",
        "verify",
        "server_name_overwrite",
        "proxy",
        "proxies",
        "local_address",
        "request_host_override",
        "pseudo_header_order",
        "h3_pseudo_header_order",
        "default_headers",
        "headers",
        "connect_headers",
        "certificate_pinning_hosts",
        "with_default_bad_pin_handler",
        "request_cookies",
        "cookies",
        "custom_tls_client",
        "client_certificates",
        "max_idle_connections",
        "max_idle_connections_per_host",
        "max_connections_per_host",
        "disable_keep_alives",
        "disable_compression",
        "idle_conn_timeout_seconds",
        "max_response_header_bytes",
        "write_buffer_size",
        "read_buffer_size",
        "disable_ipv4",
        "disable_ipv6",
        "tcp_ttl",
        "tcp_window_size",
        "tcp_window_scale",
        "tcp_mss",
        "allow_empty_cookies",
        "without_cookie_jar",
        "catch_panics",
        "with_debug",
        "disable_session_tickets",
        "tls_keylog_path",
        "root_ca_pem",
        "h2_max_data_frame_size",
        "preface_ping_idle_ms",
        "hpack_indexing_policy",
        "cookie_crumb",
        "extension_permute_mode",
        "extension_permute_prefix",
        "h2_disable_priority_frames",
        "header_order_by_dest",
        "header_order_dest",
        "tcp_dont_fragment",
        "tcp_tos",
        "tcp_no_delay",
        "tcp_window_clamp",
        "tcp_ip_id_mode",
        "fingerprint",
    )
)

#: Requests-only keywords accepted by Session.__init__ but not sent to the engine.
REQUESTS_SESSION_EXTRAS = ("hooks", "max_redirects", "trust_env")

# Re-exported for compatibility with requests.sessions; referenced here so the
# imports above are not flagged as unused.
_REQUESTS_SESSION_REEXPORTS = (
    BaseAdapter,
    SUPPORTED_CLIENT_IDENTIFIERS,
    CaseInsensitiveDict,
    ChunkedEncodingError,
    ContentDecodingError,
    HTTPAdapter,
    InvalidSchema,
    PreparedRequest,
    REDIRECT_STATI,
    Request,
    TLSClientAdapter,
    TooManyRedirects,
    codes,
    default_headers,
    dispatch_hook,
    get_auth_from_url,
    get_environ_proxies,
    get_netrc_auth,
    merge_hooks,
    merge_setting,
    requote_uri,
    resolve_proxies,
    rewind_body,
    should_bypass_proxies,
    to_native_string,
)

__all__ = [
    "DEFAULT_PORTS",
    "DEFAULT_REDIRECT_LIMIT",
    "NATIVE_SESSION_OPTION_NAMES",
    "REDIRECT_STATI",
    "SUPPORTED_CLIENT_IDENTIFIERS",
    "BaseAdapter",
    "CaseInsensitiveDict",
    "HTTPAdapter",
    "PreparedRequest",
    "Request",
    "Session",
    "SessionRedirectMixin",
    "TLSClientAdapter",
    "codes",
    "default_headers",
    "merge_hooks",
    "merge_setting",
    "session",
]


def _normalize_proxies(proxies, proxy=None):
    """Fold the requests proxies mapping and the single-proxy alias together."""
    if proxies is None:
        normalized = {}
    elif isinstance(proxies, str):
        normalized = {"http": proxies, "https": proxies}
    else:
        normalized = dict(proxies)

    if proxy:
        if isinstance(proxy, str):
            normalized.setdefault("http", proxy)
            normalized.setdefault("https", proxy)
        else:
            for key, value in proxy.items():
                normalized.setdefault(key, value)
    return normalized


class SessionRedirectMixin:
    """Redirect handling, mirroring requests.sessions.SessionRedirectMixin."""

    max_redirects: int
    trust_env: bool
    cookies: RequestsCookieJar

    def get_redirect_target(self, resp):
        """Receives a Response.  Returns a redirect URI or None."""
        if resp.is_redirect:
            location = resp.headers["location"]
            # The underlying http module decodes headers as latin1, but
            # empirical evidence suggests latin1 is very rarely used with
            # non-ASCII characters in HTTP headers.  Re-encode so UTF-8
            # Location headers survive.
            location = location.encode("latin1")
            return location.decode("utf8")
        return None

    def should_strip_auth(self, old_url, new_url):
        """Decide whether the Authorization header should be removed."""
        old_parsed = urlparse(old_url)
        new_parsed = urlparse(new_url)
        if old_parsed.hostname != new_parsed.hostname:
            return True
        # Special case: allow http -> https redirect when using the standard
        # ports.  This isn't specified by RFC 7235, but is kept to avoid
        # breaking backwards compatibility with older versions of requests
        # that allowed any redirects on the same host.
        if (
            old_parsed.scheme == "http"
            and old_parsed.port in (80, None)
            and new_parsed.scheme == "https"
            and new_parsed.port in (443, None)
        ):
            return False

        # Handle default port usage corresponding to scheme.
        changed_port = old_parsed.port != new_parsed.port
        changed_scheme = old_parsed.scheme != new_parsed.scheme
        default_port = (DEFAULT_PORTS.get(old_parsed.scheme, None), None)
        if (
            not changed_scheme
            and old_parsed.port in default_port
            and new_parsed.port in default_port
        ):
            return False

        # Standard case: root URI must match
        return changed_port or changed_scheme

    def rebuild_auth(self, prepared_request, response):
        """Strip authentication from the request when redirecting.

        Preserves the credentials only when the redirect stays on the same host
        (or upgrades http to https on the standard ports).
        """
        headers = prepared_request.headers
        url = prepared_request.url

        if "Authorization" in headers:
            original_parsed = urlparse(response.request.url)
            redirect_parsed = urlparse(url)

            if (
                original_parsed.hostname != redirect_parsed.hostname
                and redirect_parsed.hostname is not None
                and redirect_parsed.hostname != original_parsed.hostname
            ) or self.should_strip_auth(response.request.url, url):
                del headers["Authorization"]

        # .netrc might have more auth for us on our new host.
        new_auth = get_netrc_auth(url) if self.trust_env else None
        if new_auth is not None:
            prepared_request.prepare_auth(new_auth)

    def rebuild_proxies(self, prepared_request, proxies):
        """Re-evaluate the proxy configuration for the redirected request.

        If we are redirected to a URL covered by NO_PROXY, the proxy
        configuration is stripped.
        """
        headers = prepared_request.headers
        scheme = urlparse(prepared_request.url).scheme
        new_proxies = resolve_proxies(prepared_request, proxies, self.trust_env)

        if "Proxy-Authorization" in headers:
            del headers["Proxy-Authorization"]

        try:
            username, password = get_auth_from_url(new_proxies[scheme])
        except KeyError:
            return new_proxies

        if username and password:
            headers["Proxy-Authorization"] = _basic_auth_str(username, password)

        return new_proxies

    def rebuild_method(self, prepared_request, response):
        """Adjust the request method when following a redirect.

        Mirrors browser behaviour: 303 becomes GET, 302 becomes GET for
        non-HEAD, and a POST answered with 301 becomes GET.
        """
        method = prepared_request.method

        # https://tools.ietf.org/html/rfc7231#section-6.4.4
        if response.status_code == codes.see_other and method != "HEAD":
            method = "GET"

        # Do what the browsers do, despite standards...
        if response.status_code == codes.found and method != "HEAD":
            method = "GET"

        if response.status_code == codes.moved and method == "POST":
            method = "GET"

        prepared_request.method = method

    def resolve_redirects(
        self,
        resp,
        req,
        stream=False,
        timeout=None,
        verify=True,
        cert=None,
        proxies=None,
        yield_requests=False,
        **adapter_kwargs,
    ):
        """Receives a Response.  Returns a generator of Responses or Requests."""
        hist = []  # keep track of history

        url = self.get_redirect_target(resp)
        previous_fragment = urlparse(req.url).fragment
        while url:
            prepared_request = req.copy()

            # Update history and keep track of redirects.
            resp.history = hist[:]
            hist.append(resp)
            resp._next = None

            if len(resp.history) >= self.max_redirects:
                raise exceptions.TooManyRedirects(
                    "Exceeded %s redirects." % self.max_redirects, response=resp
                )

            # Release the connection back into the pool.
            resp.close()

            # Handle redirection without scheme (see: RFC 1808 Section 4)
            if url.startswith("//"):
                parsed_rurl = urlparse(resp.url)
                url = ":".join([parsed_rurl.scheme, url])

            # Normalize url case and attach the previous fragment if needed
            parsed = urlparse(url)
            if parsed.fragment == "" and previous_fragment:
                parsed = parsed._replace(fragment=previous_fragment)
            elif parsed.fragment:
                previous_fragment = parsed.fragment
            url = parsed.geturl()

            # Facilitate relative 'location' headers, as allowed by RFC 7231.
            if not parsed.netloc:
                url = urljoin(resp.url, requote_uri(url))
            else:
                url = requote_uri(url)

            prepared_request.url = url

            self.rebuild_method(prepared_request, resp)

            if resp.status_code not in (
                codes.temporary_redirect,
                codes.permanent_redirect,
            ):
                purged_headers = ("Content-Length", "Content-Type", "Transfer-Encoding")
                for header in purged_headers:
                    prepared_request.headers.pop(header, None)
                prepared_request.body = None

            headers = prepared_request.headers
            headers.pop("Cookie", None)

            # Extract any cookies sent on the response into the cookiejar in the
            # new request.
            extract_cookies_to_jar(prepared_request._cookies, req, resp.raw)
            merge_cookies(prepared_request._cookies, self.cookies)
            prepared_request.prepare_cookies(prepared_request._cookies)

            # Rebuild auth and proxy information.
            proxies = self.rebuild_proxies(prepared_request, proxies)
            self.rebuild_auth(prepared_request, resp)

            # A failed tell() sets _body_position to object().  This non-None
            # value ensures "rewindable" is True, allowing us to raise an
            # UnrewindableBodyError instead of hanging the connection.
            rewindable = prepared_request._body_position is not None and (
                "Content-Length" in headers or "Transfer-Encoding" in headers
            )

            # Attempt to rewind a consumed file-like object.
            if rewindable:
                rewind_body(prepared_request)

            # Override the original request.
            req = prepared_request

            if yield_requests:
                yield req
            else:
                resp = self.send(
                    req,
                    stream=stream,
                    timeout=timeout,
                    verify=verify,
                    cert=cert,
                    proxies=proxies,
                    allow_redirects=False,
                    **adapter_kwargs,
                )

                extract_cookies_to_jar(self.cookies, prepared_request, resp.raw)

                # extract redirect url, if any, for the next loop
                url = self.get_redirect_target(resp)
                yield resp

    def send(self, request, **kwargs):
        """Send a PreparedRequest, following redirects when allowed."""
        allow_redirects = kwargs.pop("allow_redirects", True)
        history = []
        current = request
        response = None
        while True:
            response = self.get_adapter(current.url).send(current, **kwargs)
            response = dispatch_hook("response", current.hooks, response, **kwargs)
            extract_cookies_to_jar(self.cookies, current, response.raw)
            merge_cookies(self.cookies, response.cookies)
            if not response.is_redirect:
                break
            next_request = self._redirect_request(current, response)
            response._next = next_request
            if not allow_redirects:
                break
            history.append(response)
            if len(history) > self.max_redirects:
                raise exceptions.TooManyRedirects(
                    "Exceeded %s redirects." % self.max_redirects, response=response
                )
            current = next_request
        response.history = history
        return response

    def _redirect_request(self, request, response):
        """Build the PreparedRequest for the next hop of a redirect chain."""
        prepared = request.copy()
        prepared.url = urljoin(response.url, response.headers["location"])
        self.rebuild_method(prepared, response)
        if response.status_code not in (
            codes.temporary_redirect,
            codes.permanent_redirect,
        ):
            for header in ("Content-Length", "Content-Type", "Transfer-Encoding"):
                prepared.headers.pop(header, None)
            prepared.body = None
        elif prepared._body_position is not None and (
            "Content-Length" in prepared.headers
            or "Transfer-Encoding" in prepared.headers
        ):
            # 307/308 preserve the method and the body, so a file-like body
            # must be rewound before the next hop: the adapter already read it
            # to completion while sending the first request, and copy() shares
            # the same object.  Without this the replay silently sent an empty
            # body.  A body that cannot be rewound raises UnrewindableBodyError
            # rather than sending nothing, matching requests.
            rewind_body(prepared)
        prepared.headers.pop("Cookie", None)
        extract_cookies_to_jar(prepared._cookies, request, response.raw)
        merge_cookies(prepared._cookies, self.cookies)
        prepared.prepare_cookies(prepared._cookies)
        self.rebuild_auth(prepared, response)
        return prepared


class Session(TLSOptionsMixin, TLSVerbMixin, SessionRedirectMixin):
    """A Requests session with the complete TLS-client control surface.

    Provides cookie persistence, connection-pooling and configuration - every
    requests.Session attribute and method keeps its meaning - and adds every
    knob the native tls-client engine exposes.

    Basic Usage::

      >>> import tls_client as requests
      >>> s = requests.Session()
      >>> s.get('https://example.com/')
      <Response [200]>

    Session-level TLS knobs can be passed to the constructor, read back, or
    assigned at any time; an assignment applies to every later request::

      >>> s = requests.Session(client_identifier="chrome_120", tcp_ttl=64)
      >>> s.tcp_mss = 1460
      >>> s.get("https://example.com/")

    Every knob is also accepted per request, where it overrides the session
    value for that call only::

      >>> s.get("https://example.com/", tcp_ttl=128)
    """

    __attrs__ = [
        "headers",
        "cookies",
        "auth",
        "proxies",
        "hooks",
        "params",
        "verify",
        "cert",
        "adapters",
        "stream",
        "trust_env",
        "max_redirects",
    ]

    def __init__(
        self,
        client_identifier: ClientIdentifiers = 'chrome_120',
        force_http1: bool = False,
        disable_http3: bool = False,
        with_protocol_racing: bool = False,
        random_tls_extension_order: bool = True,
        timeout: int = 30,
        timeout_milliseconds: int = 0,
        follow_redirects: bool = False,
        verify: bool = True,
        server_name_overwrite: Optional[str] = None,
        proxy: Optional[Union[str, Dict[str, str]]] = None,
        proxies: Optional[Union[str, Dict[str, str]]] = None,
        local_address: Optional[str] = None,
        request_host_override: Optional[str] = None,
        pseudo_header_order: Optional[List[str]] = None,
        h3_pseudo_header_order: Optional[List[str]] = None,
        default_headers: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        connect_headers: Optional[Dict[str, str]] = None,
        certificate_pinning_hosts: Optional[Dict[str, List[str]]] = None,
        with_default_bad_pin_handler: bool = False,
        request_cookies: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        custom_tls_client: Optional[Dict[str, Any]] = None,
        client_certificates: Optional[List[Dict[str, bytes]]] = None,
        max_idle_connections: int = 0,
        max_idle_connections_per_host: int = 0,
        max_connections_per_host: int = 0,
        disable_keep_alives: bool = False,
        disable_compression: bool = False,
        idle_conn_timeout_seconds: int = 0,
        max_response_header_bytes: int = 0,
        write_buffer_size: int = 0,
        read_buffer_size: int = 0,
        disable_ipv4: bool = False,
        disable_ipv6: bool = False,
        tcp_ttl: int = 0,
        tcp_window_size: int = 0,
        tcp_window_scale: int = 0,
        tcp_mss: int = 0,
        allow_empty_cookies: bool = False,
        without_cookie_jar: bool = False,
        auth: Optional[Tuple[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        cert: Optional[Union[str, Tuple[str, str]]] = None,
        stream: bool = False,
        catch_panics: bool = True,
        with_debug: bool = False,
        disable_session_tickets: bool = False,
        tls_keylog_path: Optional[str] = None,
        root_ca_pem: Optional[bytes] = None,
        h2_max_data_frame_size: int = 0,
        preface_ping_idle_ms: int = 0,
        hpack_indexing_policy: str = '',
        cookie_crumb: bool = False,
        h2_read_idle_timeout_ms: int = 0,
        h2_ping_timeout_ms: int = 0,
        response_header_timeout_ms: int = 0,
        extension_permute_mode: int = 0,
        extension_permute_prefix: int = 0,
        h2_disable_priority_frames: bool = False,
        header_order_by_dest: bool = False,
        header_order_dest: Optional[str] = None,
        tcp_dont_fragment: int = -1,
        tcp_tos: int = -1,
        tcp_no_delay: int = -1,
        tcp_window_clamp: int = 0,
        tcp_ip_id_mode: str = '',
        fingerprint: Optional[str] = None,

        # -- requests.Session extras ----------------------------------
        hooks: Optional[Dict[str, Any]] = None,
        max_redirects: int = DEFAULT_REDIRECT_LIMIT,
        trust_env: bool = True,
        **kwargs: Any,
    ) -> None:
        self._setup_requests_attributes(locals())
        self._setup_native_session(locals(), kwargs)
        self._setup_adapters()

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------

    def _setup_requests_attributes(self, options: Dict[str, Any]) -> None:
        """Install the attributes requests.Session owns."""
        # Validate the fingerprint identifier before anything else, so an
        # unsupported profile fails fast even when the caller injects a
        # pre-built native session (tests, adapters, connection reuse).
        identifier = options.get("client_identifier")
        if identifier is not None and identifier not in SUPPORTED_CLIENT_IDENTIFIERS:
            raise ValueError("unsupported client_identifier %r" % identifier)

        self.headers = CaseInsensitiveDict(options.get("headers") or {})
        self.params = dict(options.get("params") or {})
        self.auth = options.get("auth")
        self.cookies = RequestsCookieJar()
        merge_cookies(self.cookies, options.get("request_cookies") or {})
        merge_cookies(self.cookies, options.get("cookies") or {})
        self.proxies = _normalize_proxies(options.get("proxies"), options.get("proxy"))
        hooks = options.get("hooks")
        self.hooks = merge_hooks(hooks, None) if hooks else default_hooks()
        self.stream = bool(options.get("stream"))
        self.verify = options.get("verify", True)
        self.cert = options.get("cert")
        self.max_redirects = options.get("max_redirects", DEFAULT_REDIRECT_LIMIT)
        self.trust_env = options.get("trust_env", True)
        self.follow_redirects = bool(options.get("follow_redirects"))
        self._default_timeout = options.get("timeout", 30)
        self._timeout_milliseconds = options.get("timeout_milliseconds", 0)

    def _setup_native_session(
        self, options: Dict[str, Any], extra: Dict[str, Any]
    ) -> None:
        """Create (or adopt) the native engine session behind this facade."""
        native = options.get("_native_session") or extra.pop("_native_session", None)
        if native is None:
            native_options = dict(extra)
            for name, value in options.items():
                if name in REQUESTS_SESSION_EXTRAS or name == "_native_session":
                    continue
                if name in NATIVE_SESSION_OPTION_NAMES:
                    native_options[name] = value
            native_options["without_cookie_jar"] = True
            native = NativeSession(**native_options)
            if extra:
                raise TypeError(
                    "unexpected Session argument: %s" % next(iter(extra))
                )
        self._native = native
        fingerprint = options.get("fingerprint")
        if fingerprint is not None:
            from tls_client.fingerprints import apply as _apply_fingerprint

            _apply_fingerprint(self, fingerprint)

    def _setup_adapters(self) -> None:
        """Attach the default transport adapter for both schemes."""
        adapter = TLSClientAdapter(self._native)
        self.adapters = OrderedDict()
        self.mount("https://", adapter)
        self.mount("http://", adapter)

    # ------------------------------------------------------------------
    # TLS option plumbing (the TLSOptionsMixin properties call these)
    # ------------------------------------------------------------------

    def _get_tls_option(self, name: str) -> Any:
        """Read a session-level TLS knob from the native engine."""
        return getattr(self._native, name)

    def _set_tls_option(self, name: str, value: Any) -> None:
        """Write a session-level TLS knob; applies to every later request."""
        if name in REQUESTS_OWNED_ATTRIBUTES:
            object.__setattr__(self, name, value)
            return
        try:
            setattr(self._native, name, value)
        except AttributeError:
            # Options the engine only accepts at construction time have no
            # native property; record them on the session defaults instead so
            # the next request still observes the value.
            self._native._set_default(name, value)
        if name == "timeout":
            object.__setattr__(self, "_default_timeout", value)

    # ------------------------------------------------------------------
    # requests.Session API
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        native = self.__dict__.get("_native")
        if native is not None and hasattr(native, name):
            return getattr(native, name)
        raise AttributeError(
            "%r object has no attribute %r" % (type(self).__name__, name)
        )

    def __setattr__(self, name: str, value: Any) -> None:
        native = self.__dict__.get("_native")
        descriptor = getattr(type(native), name, None) if native is not None else None
        if (
            native is not None
            and name not in REQUESTS_OWNED_ATTRIBUTES
            and isinstance(descriptor, property)
        ):
            setattr(native, name, value)
            if name == "timeout":
                object.__setattr__(self, "_default_timeout", value)
            return
        object.__setattr__(self, name, value)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def prepare_request(self, request: Request) -> PreparedRequest:
        """Construct a PreparedRequest for transmission.

        The PreparedRequest has settings merged from the Request instance and
        those of the Session.
        """
        cookies = request.cookies or {}

        # Dict-like and cookie-jar inputs are both accepted.
        if not isinstance(cookies, RequestsCookieJar):
            cookies = cookiejar_from_dict(cookies)

        # Merge with session cookies
        merged_cookies = merge_cookies(
            merge_cookies(RequestsCookieJar(), self.cookies), cookies
        )

        auth = request.auth
        if self.trust_env and not auth and not self.auth:
            auth = get_netrc_auth(request.url)

        p = PreparedRequest()
        p.prepare(
            method=request.method.upper(),
            url=request.url,
            files=request.files,
            data=request.data,
            json=request.json,
            headers=merge_setting(
                request.headers, self.headers, dict_class=CaseInsensitiveDict
            ),
            params=merge_setting(request.params, self.params),
            auth=merge_setting(auth, self.auth),
            cookies=merged_cookies,
            hooks=merge_hooks(request.hooks, self.hooks),
        )
        return p

    def _dispatch_request(
        self,
        method,
        url,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        timeout=None,
        allow_redirects=None,
        proxies=None,
        hooks=None,
        stream=None,
        verify=None,
        cert=None,
        json=None,
        context=None,
        tls_options=None,
        extra_kwargs=None,
    ):
        """Shared body of request() and the seven verb helpers."""
        tls_options = tls_options or {}
        extra_kwargs = extra_kwargs or {}

        if "follow_redirects" in extra_kwargs:
            allow_redirects = extra_kwargs.pop("follow_redirects")
        body = extra_kwargs.pop("body", None)
        if body is not None and data is None:
            data = body
        proxy = extra_kwargs.pop("proxy", None)
        if proxy is not None:
            # proxy accepts a URL string (both schemes) or a requests-style
            # mapping; fold it into the proxies mapping the adapter consumes.
            base = dict(proxies) if isinstance(proxies, dict) else {}
            proxies = _normalize_proxies(base, proxy)
        if extra_kwargs:
            raise TypeError(
                "unexpected request argument: %s" % next(iter(extra_kwargs))
            )

        if isinstance(url, bytes):
            url = url.decode("utf-8")

        req = Request(
            method=method.upper(),
            url=url,
            headers=headers,
            files=files,
            data=data or {},
            json=json,
            params=params or {},
            auth=auth,
            cookies=cookies,
            hooks=hooks,
        )
        prep = self.prepare_request(req)

        settings = self.merge_environment_settings(
            prep.url, proxies or {}, stream, verify, cert
        )
        settings["timeout"] = self._default_timeout if timeout is None else timeout
        # requests defaults allow_redirects to True; the head() helper passes
        # False explicitly, and follow_redirects=... overrides both.
        settings["allow_redirects"] = True if allow_redirects is None else allow_redirects
        if context is not None:
            settings["context"] = context

        # Per-request TLS overrides travel through the adapter onto the engine.
        for name, value in tls_options.items():
            settings.setdefault("tls_options", {})[name] = value

        return self.send(prep, **settings)

    def execute_request(self, method, url, **kwargs):
        """Send a request through the requests pipeline.

        The native engine exposes an execute_request with the same name; this
        override keeps the requests-compatible arguments (params, json, hooks,
        allow_redirects, ...) working on the facade.
        """
        return self.request(method, url, **kwargs)

    def typed_request(self, request, **kwargs):
        """Send a Request, a PreparedRequest or a mapping describing one."""
        if isinstance(request, PreparedRequest):
            return self.send(request, **kwargs)
        if isinstance(request, Request):
            return self.send(self.prepare_request(request), **kwargs)
        values = dict(request)
        method = values.pop("method")
        url = values.pop("url")
        values.update(kwargs)
        values["method"] = method
        values["url"] = url
        return self._dispatch_request(**values)

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        """Check the environment and merge it with the given settings."""
        # Gather clues from the surrounding environment.
        if self.trust_env:
            # Set the environment's proxies.
            no_proxy = proxies.get("no_proxy") if proxies is not None else None
            env_proxies = get_environ_proxies(url, no_proxy=no_proxy)
            for (k, v) in env_proxies.items():
                proxies.setdefault(k, v)

            # Look for requests environment configuration and be compatible
            # with the cURL behaviour of ignoring certs from the environment.
            if verify is True or verify is None:
                verify = (
                    os.environ.get("REQUESTS_CA_BUNDLE")
                    or os.environ.get("CURL_CA_BUNDLE")
                    or verify
                )

        # Merge all the kwargs.
        proxies = merge_setting(proxies, self.proxies)
        stream = merge_setting(stream, self.stream)
        verify = merge_setting(verify, self.verify)
        cert = merge_setting(cert, self.cert)

        return {"proxies": proxies, "stream": stream, "verify": verify, "cert": cert}

    def get_adapter(self, url):
        """Returns the appropriate connection adapter for the given URL."""
        for (prefix, adapter) in self.adapters.items():
            if url.lower().startswith(prefix.lower()):
                return adapter

        raise exceptions.InvalidSchema("No connection adapters were found for %r" % url)

    def mount(self, prefix, adapter):
        """Registers a connection adapter to a prefix.

        Adapters are sorted in descending order by prefix length.
        """
        self.adapters[prefix] = adapter
        keys_to_move = [k for k in self.adapters if len(k) < len(prefix)]

        for key in keys_to_move:
            self.adapters[key] = self.adapters.pop(key)

    def close(self):
        """Closes all adapters and, as such, the Session."""
        for adapter in set(self.adapters.values()):
            adapter.close()

    def __getstate__(self):
        """Pickle the requests-visible state.

        The transport adapter owns the native engine session, which holds a
        lock and a live Go client pool and therefore cannot be serialised.
        Adapters are rebuilt on unpickling, exactly as a fresh Session would
        build them, so the session's cookies, headers and configuration - the
        part requests promises to preserve - survive the round trip.
        """
        state = {attr: getattr(self, attr, None) for attr in self.__attrs__}
        # Rebuilt by __setstate__ from the engine defaults.
        state.pop("adapters", None)
        return state

    def __setstate__(self, state):
        for attr, value in state.items():
            setattr(self, attr, value)

        # The cookie jar is rebuilt from the pickled pairs so the policy
        # objects are fresh for this process.
        self.cookies = cookiejar_from_dict(dict(self.cookies.items()))

        # Attributes that are not part of __attrs__ still need defaults.
        if self.__dict__.get("_default_timeout") is None:
            self._default_timeout = 30
        if self.__dict__.get("_timeout_milliseconds") is None:
            self._timeout_milliseconds = 0

        # Rebuild the engine session and the adapters that __getstate__ dropped.
        # Only the requests-visible transport defaults are restored; the TLS
        # knobs live on the engine and are not part of the pickled state.
        self._native = NativeSession(verify=self.verify, without_cookie_jar=True)
        self._setup_adapters()


def session():
    """Returns a Session for context-manager usage."""
    return Session()

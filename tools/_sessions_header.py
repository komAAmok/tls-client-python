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

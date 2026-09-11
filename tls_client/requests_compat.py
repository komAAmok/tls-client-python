"""Dependency-free Requests-compatible API over the native tls-client engine."""

from __future__ import absolute_import

import io
import json as jsonlib
import math
import time
import uuid
from datetime import timedelta
from http.client import responses as reason_phrases
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import getproxies

from tls_client import exceptions
from tls_client.auth import HTTPBasicAuth
from tls_client.cookies import RequestsCookieJar, cookie_header, extract_cookies, merge_cookies
from tls_client.hooks import default_hooks, dispatch_hook, merge_hooks
from tls_client.structures import CaseInsensitiveDict
from tls_client._core import Session as NativeSession
from tls_client._core import _load_client_certificates, _resolve_proxy_url


REDIRECT_STATI = (301, 302, 303, 307, 308)

_REQUESTS_ATTRIBUTES = {
    "adapters", "auth", "cert", "cookies", "headers", "hooks",
    "max_redirects", "params", "proxies", "stream", "trust_env", "verify",
}

_TLS_REQUEST_OPTIONS = {
    "allow_empty_cookies", "catch_panics", "certificate_pinning_hosts",
    "client_certificates", "client_identifier", "connect_headers",
    "custom_tls_client", "default_headers", "disable_compression",
    "disable_http3", "disable_ipv4", "disable_ipv6", "disable_keep_alives",
    "force_http1", "h3_pseudo_header_order", "header_order",
    "idle_conn_timeout_seconds", "local_address", "max_connections_per_host",
    "max_idle_connections", "max_idle_connections_per_host",
    "max_response_header_bytes", "pseudo_header_order",
    "random_tls_extension_order", "read_buffer_size", "request_cookies",
    "request_host_override", "server_name_overwrite", "tcp_mss", "tcp_ttl",
    "tcp_window_scale", "tcp_window_size", "timeout_milliseconds", "with_debug",
    "with_default_bad_pin_handler", "with_protocol_racing", "without_cookie_jar",
    "write_buffer_size",
}


def _merge_url_params(url, params):
    if not params:
        return url
    query = urlencode(params, doseq=True)
    scheme, netloc, path, old_query, fragment = urlsplit(url)
    query = "&".join(filter(None, (old_query, query)))
    return urlunsplit((scheme, netloc, path, query, fragment))


def _body_bytes(value):
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


def _multipart(data, files):
    boundary = uuid.uuid4().hex
    chunks = []

    def add(value):
        chunks.append(value.encode("utf-8") if isinstance(value, str) else value)

    fields = data.items() if hasattr(data, "items") else (data or [])
    for name, value in fields:
        values = value if isinstance(value, (list, tuple)) else [value]
        for item in values:
            add("--%s\r\n" % boundary)
            add('Content-Disposition: form-data; name="%s"\r\n\r\n' % name)
            add(str(item))
            add("\r\n")

    entries = files.items() if hasattr(files, "items") else files
    for name, value in entries:
        filename, content_type, extra_headers, content = name, "application/octet-stream", {}, value
        if isinstance(value, tuple):
            filename, content = value[:2]
            if len(value) > 2:
                content_type = value[2]
            if len(value) > 3:
                extra_headers = value[3]
        add("--%s\r\n" % boundary)
        add('Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (name, filename))
        add("Content-Type: %s\r\n" % content_type)
        for header, header_value in extra_headers.items():
            add("%s: %s\r\n" % (header, header_value))
        add("\r\n")
        add(_body_bytes(content))
        add("\r\n")
    add("--%s--\r\n" % boundary)
    return b"".join(chunks), "multipart/form-data; boundary=%s" % boundary


def _timeout_options(timeout):
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
    return {"timeout_milliseconds": max(1, int(math.ceil(seconds * 1000)))}


def _transport_error(error, request):
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


class Request(object):
    def __init__(self, method=None, url=None, headers=None, files=None, data=None,
                 params=None, auth=None, cookies=None, hooks=None, json=None):
        self.hooks = merge_hooks(hooks, None) if hooks else default_hooks()
        self.method, self.url, self.headers = method, url, headers
        self.files, self.data, self.json = files, data, json
        self.params, self.auth, self.cookies = params, auth, cookies

    def prepare(self):
        prepared = PreparedRequest()
        return prepared.prepare(
            method=self.method, url=self.url, headers=self.headers, files=self.files,
            data=self.data, params=self.params, auth=self.auth, cookies=self.cookies,
            hooks=self.hooks, json=self.json,
        )


class PreparedRequest(object):
    def __init__(self):
        self.method = self.url = self.body = None
        self.headers = CaseInsensitiveDict()
        self.hooks = default_hooks()
        self._cookies = RequestsCookieJar()

    def prepare(self, method=None, url=None, headers=None, files=None, data=None,
                params=None, auth=None, cookies=None, hooks=None, json=None):
        if not url:
            raise exceptions.URLRequired("Invalid URL: no URL supplied")
        parsed = urlsplit(str(url))
        if not parsed.scheme:
            raise exceptions.MissingSchema("Invalid URL %r: no scheme supplied" % url)
        if parsed.scheme not in ("http", "https"):
            raise exceptions.InvalidSchema("No connection adapter for %r" % url)
        self.method = str(method or "GET").upper()
        self.url = _merge_url_params(str(url), params)
        self.headers = CaseInsensitiveDict(headers or {})
        self.hooks = hooks or default_hooks()

        if files:
            self.body, content_type = _multipart(data, files)
            self.headers.setdefault("Content-Type", content_type)
        elif json is not None:
            self.body = jsonlib.dumps(json, allow_nan=False).encode("utf-8")
            self.headers.setdefault("Content-Type", "application/json")
        elif hasattr(data, "items") or (
            isinstance(data, (list, tuple)) and data and isinstance(data[0], tuple)
        ):
            self.body = urlencode(data, doseq=True).encode("utf-8")
            self.headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            self.body = _body_bytes(data)
        if self.body is not None:
            self.headers["Content-Length"] = str(len(self.body))

        self.prepare_cookies(cookies)
        if auth is not None:
            auth = HTTPBasicAuth(*auth) if isinstance(auth, tuple) else auth
            if callable(auth):
                auth(self)
        return self

    def prepare_cookies(self, cookies):
        if cookies:
            if isinstance(cookies, RequestsCookieJar):
                self._cookies = cookies.copy()
            else:
                self._cookies.update(cookies)
        value = cookie_header(self._cookies, self.url)
        if value:
            self.headers["Cookie"] = value

    def copy(self):
        copied = PreparedRequest()
        copied.method, copied.url, copied.body = self.method, self.url, self.body
        copied.headers = self.headers.copy()
        copied.hooks = dict((key, list(value)) for key, value in self.hooks.items())
        copied._cookies = self._cookies.copy()
        return copied


class Response(object):
    def __init__(self):
        self._content = b""
        self.status_code = None
        self.headers = CaseInsensitiveDict()
        self.raw = self.url = self.encoding = self.reason = None
        self.history = []
        self.cookies = RequestsCookieJar()
        self.elapsed = timedelta(0)
        self.request = self.connection = self.used_protocol = self._next = None

    @property
    def content(self):
        return self._content

    @property
    def text(self):
        if not self._content:
            return ""
        try:
            return self._content.decode(self.encoding or "utf-8", errors="replace")
        except LookupError:
            return self._content.decode("utf-8", errors="replace")

    @property
    def apparent_encoding(self):
        try:
            self._content.decode("utf-8")
            return "utf-8"
        except UnicodeDecodeError:
            return "ISO-8859-1"

    @property
    def ok(self):
        return self.status_code is not None and self.status_code < 400

    @property
    def is_redirect(self):
        return "location" in self.headers and self.status_code in REDIRECT_STATI

    @property
    def is_permanent_redirect(self):
        return "location" in self.headers and self.status_code in (301, 308)

    @property
    def next(self):
        return self._next

    @property
    def links(self):
        result = {}
        for value in self.headers.get("link", "").split(","):
            parts = [part.strip() for part in value.split(";")]
            if not parts or not parts[0].startswith("<"):
                continue
            link = {"url": parts[0].strip("<>")}
            for part in parts[1:]:
                if "=" in part:
                    key, item = part.split("=", 1)
                    link[key.strip()] = item.strip(' "')
            result[link.get("rel") or link["url"]] = link
        return result

    def json(self, **kwargs):
        return jsonlib.loads(self.text, **kwargs)

    def raise_for_status(self):
        if 400 <= self.status_code < 500:
            label = "Client Error"
        elif 500 <= self.status_code < 600:
            label = "Server Error"
        else:
            return None
        message = "%s %s: %s for url: %s" % (
            self.status_code, label, self.reason, self.url,
        )
        raise exceptions.HTTPError(message, response=self, request=self.request)

    def iter_content(self, chunk_size=1, decode_unicode=False):
        if not isinstance(chunk_size, int) or chunk_size <= 0:
            raise TypeError("chunk_size must be a positive integer")
        for index in range(0, len(self._content), chunk_size):
            chunk = self._content[index:index + chunk_size]
            yield chunk.decode(self.encoding or "utf-8") if decode_unicode else chunk

    def iter_lines(self, chunk_size=512, decode_unicode=False, delimiter=None):
        data = self.text if decode_unicode else self._content
        for line in data.split(delimiter) if delimiter else data.splitlines():
            yield line

    def close(self):
        if self.raw is not None:
            self.raw.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __bool__(self):
        return self.ok

    __nonzero__ = __bool__

    def __repr__(self):
        return "<Response [%s]>" % self.status_code


class BaseAdapter(object):
    def send(self, request, **kwargs):
        raise NotImplementedError

    def close(self):
        pass


class TLSClientAdapter(BaseAdapter):
    def __init__(self, native_session):
        self.native_session = native_session
        self._closed = False

    def send(self, request, stream=False, timeout=None, verify=True, cert=None,
             proxies=None, **options):
        proxy = options.pop("proxy", None) or _resolve_proxy_url(proxies, request.url)
        options.update(_timeout_options(timeout))
        options.update(body=request.body, follow_redirects=False,
                       headers=dict(request.headers.items()), proxy=proxy,
                       verify=bool(verify))
        if cert:
            options["client_certificates"] = _load_client_certificates(cert)
        started = time.monotonic()
        try:
            native = self.native_session.execute_request(request.method, request.url, **options)
        except RuntimeError as error:
            raise _transport_error(error, request)

        response = Response()
        response.status_code = native.status_code
        for name, values in native.headers.items():
            response.headers[name] = ", ".join(str(item) for item in values) \
                if isinstance(values, (list, tuple)) else str(values)
        response._content = native.content
        response.raw = io.BytesIO(native.content)
        response.url = native.url or request.url
        response.reason = native.reason or reason_phrases.get(native.status_code, "")
        response.encoding = _encoding_from_headers(response.headers)
        response.cookies = extract_cookies(native.headers, response.url)
        for name, value in (native.cookies or {}).items():
            if response.cookies.get(name) is None:
                response.cookies.set(name, value)
        response.elapsed = timedelta(seconds=time.monotonic() - started)
        response.request, response.connection = request, self
        response.used_protocol = native.used_protocol
        return response

    def close(self):
        if not self._closed:
            self._closed = True
            self.native_session.close()


def _encoding_from_headers(headers):
    content_type = headers.get("content-type", "")
    for item in content_type.split(";")[1:]:
        if "=" in item:
            key, value = item.split("=", 1)
            if key.strip().lower() == "charset":
                return value.strip(' "\'')
    return "utf-8" if "application/json" in content_type.lower() else None


class Session(object):
    def __init__(self, **options):
        native_session = options.pop("_native_session", None)
        initial_headers = options.pop("headers", None)
        initial_cookies = options.pop("cookies", None)
        request_cookies = options.pop("request_cookies", None)
        initial_params = options.pop("params", None)
        initial_auth = options.pop("auth", None)
        initial_proxies = options.pop("proxies", None)
        initial_proxy = options.pop("proxy", None)
        initial_verify = options.pop("verify", True)
        initial_cert = options.pop("cert", None)
        initial_stream = options.pop("stream", False)
        default_timeout = options.pop("timeout", 30)

        self.headers = CaseInsensitiveDict(initial_headers or {})
        self.params = dict(initial_params or {})
        self.auth = initial_auth
        self.cookies = RequestsCookieJar()
        self.cookies.update(request_cookies or {})
        self.cookies.update(initial_cookies or {})
        self.proxies = dict(initial_proxies or {})
        if initial_proxy:
            self.proxies.update({"http": initial_proxy, "https": initial_proxy})
        self.hooks = default_hooks()
        self.stream, self.verify, self.cert = initial_stream, initial_verify, initial_cert
        self.max_redirects, self.trust_env = 30, True
        self._default_timeout = default_timeout

        if native_session is None:
            options.setdefault("without_cookie_jar", True)
            native_session = NativeSession(**options)
        self._native = native_session
        adapter = TLSClientAdapter(native_session)
        self.adapters = {}
        self.mount("http://", adapter)
        self.mount("https://", adapter)

    def __getattr__(self, name):
        native = self.__dict__.get("_native")
        if native is not None and hasattr(native, name):
            return getattr(native, name)
        raise AttributeError(name)

    def __setattr__(self, name, value):
        native = self.__dict__.get("_native")
        descriptor = getattr(type(native), name, None) if native is not None else None
        if native is not None and name not in _REQUESTS_ATTRIBUTES and isinstance(descriptor, property):
            setattr(native, name, value)
            if name == "timeout":
                object.__setattr__(self, "_default_timeout", value)
            return
        object.__setattr__(self, name, value)

    def prepare_request(self, request):
        headers = self.headers.copy()
        headers.update(request.headers or {})
        params = dict(self.params)
        if request.params:
            if hasattr(request.params, "items"):
                params.update(request.params)
            else:
                params = list(params.items()) + list(request.params)
        cookies = self.cookies.copy()
        merge_cookies(cookies, request.cookies)
        return PreparedRequest().prepare(
            method=request.method, url=request.url, headers=headers, files=request.files,
            data=request.data, params=params,
            auth=request.auth if request.auth is not None else self.auth,
            cookies=cookies, hooks=merge_hooks(request.hooks, self.hooks), json=request.json,
        )

    def request(self, method, url, params=None, data=None, headers=None, cookies=None,
                files=None, auth=None, timeout=None, allow_redirects=True, proxies=None,
                hooks=None, stream=None, verify=None, cert=None, json=None, **kwargs):
        body = kwargs.pop("body", None)
        if body is not None and data is None:
            data = body
        if "follow_redirects" in kwargs:
            allow_redirects = kwargs.pop("follow_redirects")
        tls_options = {}
        for name in list(kwargs):
            if name in _TLS_REQUEST_OPTIONS:
                tls_options[name] = kwargs.pop(name)
        if kwargs:
            raise TypeError("unexpected request argument: %s" % next(iter(kwargs)))

        prepared = self.prepare_request(Request(
            method, url, headers, files, data, params, auth, cookies, hooks, json,
        ))
        send_options = self.merge_environment_settings(prepared.url, proxies, stream, verify, cert)
        send_options.update(allow_redirects=allow_redirects,
                            timeout=self._default_timeout if timeout is None else timeout)
        send_options.update(tls_options)
        return self.send(prepared, **send_options)

    def send(self, request, **kwargs):
        allow_redirects = kwargs.pop("allow_redirects", True)
        history, current = [], request
        while True:
            response = self.get_adapter(current.url).send(current, **kwargs)
            response = dispatch_hook("response", current.hooks, response, **kwargs)
            self.cookies.update(response.cookies)
            if not response.is_redirect:
                break
            next_request = self._redirect_request(current, response)
            response._next = next_request
            if not allow_redirects:
                break
            history.append(response)
            if len(history) > self.max_redirects:
                raise exceptions.TooManyRedirects(
                    "Exceeded %s redirects" % self.max_redirects, response=response,
                )
            current = next_request
        response.history = history
        return response

    def _redirect_request(self, request, response):
        prepared = request.copy()
        prepared.url = urljoin(response.url, response.headers["location"])
        if response.status_code == 303 or (
            response.status_code == 302 and prepared.method != "HEAD"
        ) or (response.status_code == 301 and prepared.method == "POST"):
            prepared.method, prepared.body = "GET", None
            prepared.headers.pop("Content-Length", None)
            prepared.headers.pop("Content-Type", None)
        if urlsplit(request.url).netloc != urlsplit(prepared.url).netloc:
            prepared.headers.pop("Authorization", None)
        prepared.headers.pop("Cookie", None)
        prepared._cookies = self.cookies.copy()
        prepared.prepare_cookies(prepared._cookies)
        return prepared

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        merged_proxies = dict(self.proxies)
        if self.trust_env:
            for key, value in getproxies().items():
                merged_proxies.setdefault(key, value)
        if proxies:
            merged_proxies.update(proxies)
        return {
            "proxies": merged_proxies,
            "stream": self.stream if stream is None else stream,
            "verify": self.verify if verify is None else verify,
            "cert": self.cert if cert is None else cert,
        }

    def mount(self, prefix, adapter):
        self.adapters[prefix] = adapter
        self.adapters = dict(sorted(
            self.adapters.items(), key=lambda item: len(item[0]), reverse=True,
        ))

    def get_adapter(self, url):
        for prefix, adapter in self.adapters.items():
            if url.lower().startswith(prefix.lower()):
                return adapter
        raise exceptions.InvalidSchema("No connection adapter for %r" % url)

    def get(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        return self.request("GET", url, **kwargs)

    def options(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        return self.request("POST", url, data=data, json=json, **kwargs)

    def put(self, url, data=None, **kwargs):
        return self.request("PUT", url, data=data, **kwargs)

    def patch(self, url, data=None, **kwargs):
        return self.request("PATCH", url, data=data, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def execute_request(self, method, url, **kwargs):
        return self.request(method, url, **kwargs)

    def typed_request(self, request, **kwargs):
        if isinstance(request, PreparedRequest):
            return self.send(request, **kwargs)
        if isinstance(request, Request):
            return self.send(self.prepare_request(request), **kwargs)
        values = dict(request)
        method, url = values.pop("method"), values.pop("url")
        values.update(kwargs)
        return self.request(method, url, **values)

    def close(self):
        closed = set()
        for adapter in self.adapters.values():
            if id(adapter) not in closed:
                adapter.close()
                closed.add(id(adapter))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @staticmethod
    def clear_client_pool():
        NativeSession.clear_client_pool()


def request(method, url, **kwargs):
    with Session() as session:
        return session.request(method=method, url=url, **kwargs)


def get(url, params=None, **kwargs):
    return request("GET", url, params=params, **kwargs)


def options(url, **kwargs):
    return request("OPTIONS", url, **kwargs)


def head(url, **kwargs):
    kwargs.setdefault("allow_redirects", False)
    return request("HEAD", url, **kwargs)


def post(url, data=None, json=None, **kwargs):
    return request("POST", url, data=data, json=json, **kwargs)


def put(url, data=None, **kwargs):
    return request("PUT", url, data=data, **kwargs)


def patch(url, data=None, **kwargs):
    return request("PATCH", url, data=data, **kwargs)


def delete(url, **kwargs):
    return request("DELETE", url, **kwargs)

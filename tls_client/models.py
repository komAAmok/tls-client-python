"""Requests-compatible request/response models."""

import datetime
import json as complexjson
from io import UnsupportedOperation
from urllib.parse import urlencode, urlsplit, urlunsplit

from tls_client import exceptions
from tls_client._internal_utils import (  # noqa: F401
    to_native_string,
    unicode_is_ascii,
)
from tls_client.auth import HTTPBasicAuth
from tls_client.cookies import (
    RequestsCookieJar,
    cookiejar_from_dict,
    get_cookie_header,
)
from tls_client.exceptions import (  # noqa: F401
    ChunkedEncodingError,
    ConnectionError,
    ContentDecodingError,
    HTTPError,
    InvalidJSONError,
    InvalidURL,
    MissingSchema,
    StreamConsumedError,
)
from tls_client.hooks import default_hooks
from tls_client.status_codes import codes  # noqa: F401
from tls_client.structures import CaseInsensitiveDict
from tls_client.utils import (
    check_header_validity,
    get_auth_from_url,  # noqa: F401
    guess_filename,  # noqa: F401
    guess_json_utf,  # noqa: F401
    iter_slices,
    parse_header_links,
    requote_uri,
    stream_decode_response_unicode,
    super_len,
    to_key_val_list,
)

#: Historical aliases requests keeps for the renamed JSON/SSL exceptions.
RequestsJSONDecodeError = exceptions.JSONDecodeError
RequestsSSLError = exceptions.SSLError

#: The set of HTTP status codes that indicate an HTTP redirect.
REDIRECT_STATI = (301, 302, 303, 307, 308)

DEFAULT_REDIRECT_LIMIT = 30
CONTENT_CHUNK_SIZE = 10 * 1024
ITER_CHUNK_SIZE = 512

__all__ = [
    "CONTENT_CHUNK_SIZE",
    "DEFAULT_REDIRECT_LIMIT",
    "ITER_CHUNK_SIZE",
    "REDIRECT_STATI",
    "PreparedRequest",
    "Request",
    "RequestEncodingMixin",
    "RequestHooksMixin",
    "Response",
]


def _encode_params(data):
    """Encode parameters in a piece of data.

    Accepts a dictionary, a list of (key, value) tuples, or a string/bytes
    body, and returns a url-encoded string.
    """
    if isinstance(data, (str, bytes)):
        return data
    elif hasattr(data, "read"):
        return data
    elif hasattr(data, "__iter__"):
        result = []
        for k, vs in to_key_val_list(data):
            if isinstance(vs, (str, bytes)) or not hasattr(vs, "__iter__"):
                vs = [vs]
            for v in vs:
                if v is not None:
                    result.append(
                        (
                            k.encode("utf-8") if isinstance(k, str) else k,
                            v.encode("utf-8") if isinstance(v, str) else v,
                        )
                    )
        return urlencode(result, doseq=True)
    else:
        return data


def _body_bytes(value):
    """Coerce an arbitrary body value into bytes (or None)."""
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


class RequestEncodingMixin:
    @property
    def path_url(self):
        """Build the path URL to use."""
        url = []

        p = urlsplit(self.url)

        path = p.path
        if not path:
            path = "/"

        url.append(path)

        query = p.query
        if query:
            url.append("?")
            url.append(query)

        return "".join(url)

    @staticmethod
    def _encode_params(data):
        return _encode_params(data)

    @staticmethod
    def _encode_files(files, data):
        """Build a multipart/form-data body from files and form data."""
        from tls_client._multipart_boundary import boundary as _boundary

        boundary = _boundary("chrome")
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
            filename, content_type = name, "application/octet-stream"
            extra_headers, content = {}, value
            if isinstance(value, tuple):
                filename, content = value[:2]
                if len(value) > 2:
                    content_type = value[2]
                if len(value) > 3:
                    extra_headers = value[3]
            add("--%s\r\n" % boundary)
            add(
                'Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
                % (name, filename)
            )
            add("Content-Type: %s\r\n" % content_type)
            for header, header_value in extra_headers.items():
                add("%s: %s\r\n" % (header, header_value))
            add("\r\n")
            add(_body_bytes(content))
            add("\r\n")
        add("--%s--\r\n" % boundary)
        content_type = "multipart/form-data; boundary=%s" % boundary
        return content_type, b"".join(chunks)


class RequestHooksMixin:
    def register_hook(self, event, hook):
        """Properly register a hook."""
        if event not in self.hooks:
            raise ValueError('Unsupported event specified, with event name "%s"' % (event))

        if callable(hook):
            self.hooks[event].append(hook)
        elif hasattr(hook, "__iter__"):
            self.hooks[event].extend(h for h in hook if callable(h))

    def deregister_hook(self, event, hook):
        """Deregister a previously registered hook.

        Returns True if the hook existed, False if not.
        """
        try:
            self.hooks[event].remove(hook)
            return True
        except ValueError:
            return False


class Request(RequestHooksMixin):
    """A user-created Request object, used to prepare a PreparedRequest."""

    def __init__(
        self,
        method=None,
        url=None,
        headers=None,
        files=None,
        data=None,
        params=None,
        auth=None,
        cookies=None,
        hooks=None,
        json=None,
    ):
        # Default empty dicts for dict params.
        data = [] if data is None else data
        files = [] if files is None else files
        headers = {} if headers is None else headers
        params = {} if params is None else params
        hooks = {} if hooks is None else hooks

        self.hooks = default_hooks()
        for (k, v) in list(hooks.items()):
            self.register_hook(event=k, hook=v)

        self.method = method
        self.url = url
        self.headers = headers
        self.files = files
        self.data = data
        self.json = json
        self.params = params
        self.auth = auth
        self.cookies = cookies

    def __repr__(self):
        return "<Request [%s]>" % (self.method,)

    def prepare(self):
        """Construct a PreparedRequest for transmission."""
        p = PreparedRequest()
        p.prepare(
            method=self.method,
            url=self.url,
            headers=self.headers,
            files=self.files,
            data=self.data,
            json=self.json,
            params=self.params,
            auth=self.auth,
            cookies=self.cookies,
            hooks=self.hooks,
        )
        return p


class PreparedRequest(RequestEncodingMixin, RequestHooksMixin):
    """The fully mutable PreparedRequest object.

    Contains the exact bytes that will be sent to the server.
    """

    def __init__(self):
        #: HTTP verb to send to the server.
        self.method = None
        #: HTTP URL to send the request to.
        self.url = None
        #: dictionary of HTTP headers.
        self.headers = None
        # The CookieJar that was used to build the Cookie header
        self._cookies = None
        #: request body to send to the server.
        self.body = None
        #: dictionary of callback hooks, for internal usage.
        self.hooks = default_hooks()
        #: integer denoting starting position of a readable file-like body.
        self._body_position = None

    def __repr__(self):
        return "<PreparedRequest [%s]>" % (self.method,)

    def prepare(
        self,
        method=None,
        url=None,
        headers=None,
        files=None,
        data=None,
        params=None,
        auth=None,
        cookies=None,
        hooks=None,
        json=None,
    ):
        """Prepares the entire request with the given parameters."""
        self.prepare_method(method)
        self.prepare_url(url, params)
        self.prepare_headers(headers)
        self.prepare_cookies(cookies)
        self.prepare_body(data, files, json)
        self.prepare_auth(auth, url)

        # Note that prepare_auth must be last to enable authentication schemes
        # such as OAuth to work on a fully prepared request.

        # This MUST go after prepare_auth: authenticators could add a hook.
        self.prepare_hooks(hooks)

    def copy(self):
        p = PreparedRequest()
        p.method = self.method
        p.url = self.url
        p.headers = self.headers.copy() if self.headers is not None else None
        p._cookies = _copy_cookie_jar(self._cookies)
        p.body = self.body
        p.hooks = self.hooks
        p._body_position = self._body_position
        return p

    def prepare_method(self, method):
        """Prepares the given HTTP method."""
        self.method = method
        if self.method is not None:
            self.method = to_native_string(self.method.upper())

    def prepare_url(self, url, params):
        """Prepares the given HTTP URL."""
        #: Accept objects that have string representations.
        if url is None:
            raise exceptions.MissingSchema("Invalid URL None: No scheme supplied.")
        if isinstance(url, bytes):
            url = url.decode("utf8")
        else:
            url = str(url)

        # Remove leading whitespaces from url
        url = url.lstrip()

        # Reject schemes the transport cannot serve, exactly as requests does.
        if ":" in url and not url.lower().startswith("http"):
            scheme = url.split(":", 1)[0].lower()
            if scheme and not scheme.startswith("//"):
                raise exceptions.InvalidSchema(
                    "No connection adapters were found for %r" % url
                )
            self.url = url
            return

        try:
            scheme, auth, host, port, path, query, fragment = _parse_url(url)
        except Exception as exc:
            raise exceptions.InvalidURL("Invalid URL %r: %s" % (url, exc))

        if not scheme:
            raise exceptions.MissingSchema(
                "Invalid URL %r: No scheme supplied. Perhaps you meant "
                "https://%s?" % (url, url)
            )

        if scheme not in ("http", "https"):
            raise exceptions.InvalidSchema(
                "No connection adapters were found for %r" % url
            )

        # We are not able to handle hostnames that are not ascii.
        try:
            host.encode("idna")
        except UnicodeError:
            pass

        # The host can be None for urls such as 'http:///path'
        if host is not None and "." in host:
            host = host.lower()

        # A str/bytes params value is already an encoded query string; decode
        # bytes so the url assembly below never mixes str and bytes (requests
        # does the same via to_native_string).
        if isinstance(params, (str, bytes)):
            params = to_native_string(params)

        if params:
            enc_params = self._encode_params(params)
            if enc_params:
                if query:
                    query = "%s&%s" % (query, enc_params)
                else:
                    query = enc_params

        path = path or "/"
        url = _unparse_url((scheme, auth, host, port, path, query, fragment))
        self.url = requote_uri(url)

    def prepare_headers(self, headers):
        """Prepares the given HTTP headers."""
        self.headers = CaseInsensitiveDict()
        if headers:
            for header in headers.items():
                # Raise exception on invalid header value.
                check_header_validity(header)
                name, value = header
                self.headers[to_native_string(name)] = value

    def prepare_body(self, data, files, json=None):
        """Prepares the given HTTP body data."""
        body = None
        content_type = None
        self._body_position = None

        if not data and json is not None:
            # The engine takes bytes; encode the JSON document as UTF-8.
            content_type = "application/json"
            try:
                body = complexjson.dumps(json, allow_nan=False)
            except ValueError as ve:
                raise exceptions.InvalidJSONError(str(ve))
            body = body.encode("utf-8")

        is_stream = all(
            [
                hasattr(data, "__iter__"),
                not isinstance(data, (str, list, tuple, dict)),
            ]
        )

        if is_stream:
            try:
                length = super_len(data)
            except (TypeError, AttributeError, UnsupportedOperation):
                length = None

            body = data

            if getattr(body, "tell", None) is not None:
                # Record the current file position before reading.
                try:
                    self._body_position = body.tell()
                except OSError:
                    self._body_position = object()

            if files:
                raise NotImplementedError(
                    "Streamed bodies and files are mutually exclusive."
                )

            if length:
                self.headers["Content-Length"] = str(length)
            else:
                self.headers["Transfer-Encoding"] = "chunked"
        else:
            # Multi-part file uploads.
            if files:
                (content_type, body) = self._encode_files(files, data)
            else:
                if data:
                    body = self._encode_params(data)
                    if isinstance(data, (str, bytes)) or hasattr(data, "read"):
                        content_type = None
                    else:
                        content_type = "application/x-www-form-urlencoded"
                    # The transport needs bytes; requests keeps str here only
                    # because urllib3 encodes it later.
                    if isinstance(body, str):
                        body = body.encode("utf-8")

            self.prepare_content_length(body)

            # Add content-type if it wasn't explicitly provided.
            if content_type and ("content-type" not in self.headers):
                self.headers["Content-Type"] = content_type

        self.body = body

    def prepare_content_length(self, body):
        """Prepare Content-Length header based on request method and body."""
        if body is not None:
            length = super_len(body)
            if length:
                # If length exists, set it.  Otherwise, fall back to
                # Transfer-Encoding and rely on the server to add the length.
                self.headers["Content-Length"] = str(length)
        elif (
            self.method not in ("GET", "HEAD")
            and self.headers.get("Content-Length") is None
        ):
            # Set Content-Length to 0 for methods that can have a body but
            # don't provide one (e.g. POST with no data).
            self.headers["Content-Length"] = "0"

    def prepare_auth(self, auth, url=""):
        """Prepares the given HTTP auth data."""
        # If no Auth is explicitly provided, extract it from the URL first.
        if auth is None:
            from tls_client.utils import get_auth_from_url

            url_auth = get_auth_from_url(self.url)
            auth = url_auth if any(url_auth) else None

        if auth:
            if isinstance(auth, tuple) and len(auth) == 2:
                # special-case basic HTTP auth
                auth = HTTPBasicAuth(*auth)

            # Allow auth to make its changes.
            r = auth(self)

            # Update self to reflect the auth changes.
            self.__dict__.update(r.__dict__)

            # Recompute Content-Length
            self.prepare_content_length(self.body)

    def prepare_cookies(self, cookies):
        """Prepares the given HTTP cookie data."""
        if isinstance(cookies, RequestsCookieJar):
            self._cookies = cookies
        else:
            self._cookies = cookiejar_from_dict(cookies)

        cookie_header = get_cookie_header(self._cookies, self)
        if cookie_header is not None:
            self.headers["Cookie"] = cookie_header

    def prepare_hooks(self, hooks):
        """Prepares the given hooks."""
        # hooks can be passed as None to the prepare method and to this method.
        hooks = hooks or []
        if isinstance(hooks, dict):
            for event in hooks:
                self.register_hook(event, hooks[event])
        else:
            for hook in hooks:
                self.register_hook("response", hook)


# ---------------------------------------------------------------------------
# helpers used by PreparedRequest
# ---------------------------------------------------------------------------


def _parse_url(url):
    """Split a URL into (scheme, auth, host, port, path, query, fragment)."""
    parsed = urlsplit(url)
    scheme = parsed.scheme
    auth = None
    netloc = parsed.netloc
    if "@" in netloc:
        auth, _, netloc = netloc.rpartition("@")
    host, _, port = netloc.partition(":")
    if not port:
        port = None
    else:
        try:
            port = int(port)
        except ValueError:
            port = None
    return scheme, auth, host or None, port, parsed.path, parsed.query, parsed.fragment


def _unparse_url(parts):
    scheme, auth, host, port, path, query, fragment = parts
    netloc = ""
    if auth:
        netloc = "%s@" % auth
    if host:
        netloc += host
    if port:
        netloc += ":%s" % port
    return urlunsplit((scheme, netloc, path, query, fragment))


def _copy_cookie_jar(jar):
    from tls_client.cookies import _copy_cookie_jar as _copy

    return _copy(jar)


class Response:
    """The Response object, which contains a server's response to an HTTP request."""

    __attrs__ = [
        "_content",
        "status_code",
        "headers",
        "url",
        "history",
        "encoding",
        "reason",
        "cookies",
        "elapsed",
        "request",
    ]

    def __init__(self):
        self._content = False
        self._content_consumed = False
        self._next = None

        #: Integer Code of responded HTTP Status, e.g. 404 or 200.
        self.status_code = None

        #: Case-insensitive Dictionary of Response Headers.
        self.headers = CaseInsensitiveDict()

        #: File-like object representation of response (for advanced usage).
        self.raw = None
        #: Final URL location of Response.
        self.url = None

        #: Encoding to decode with when accessing r.text.
        self.encoding = None

        #: A list of Response objects from the history of the Request.
        self.history = []

        #: Textual reason of responded HTTP Status, e.g. "Not Found" or "OK".
        self.reason = None

        #: A CookieJar of Cookies the server sent back.
        self.cookies = cookiejar_from_dict({})

        #: The amount of time elapsed between sending the request and the
        #: arrival of the response (as a timedelta).
        self.elapsed = datetime.timedelta(0)

        #: The PreparedRequest object to which this Response was made.
        self.request = None

        #: The transport adapter that produced this response (tls_client extension).
        self.connection = None
        #: The negotiated protocol (tls_client extension).
        self.used_protocol = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __getstate__(self):
        # Consume everything; accessing the content attribute makes sure the
        # content has been fully read.
        if not self._content_consumed:
            self.content

        return {attr: getattr(self, attr, None) for attr in self.__attrs__}

    def __setstate__(self, state):
        for name, value in state.items():
            setattr(self, name, value)

        # pickled objects do not have .raw
        setattr(self, "_content_consumed", True)
        setattr(self, "raw", None)

    def __repr__(self):
        return "<Response [%s]>" % (self.status_code,)

    def __bool__(self):
        """Returns True if status_code is less than 400."""
        return self.ok

    __nonzero__ = __bool__

    def __iter__(self):
        """Allows you to use a response as an iterator."""
        return self.iter_content(128)

    @property
    def ok(self):
        """Returns True if status_code is less than 400, False if not."""
        try:
            self.raise_for_status()
        except exceptions.HTTPError:
            return False
        return True

    @property
    def is_redirect(self):
        """True if this Response is a well-formed HTTP redirect."""
        return "location" in self.headers and self.status_code in REDIRECT_STATI

    @property
    def is_permanent_redirect(self):
        """True if this Response is one of the permanent redirects."""
        return "location" in self.headers and self.status_code in (301, 308)

    @property
    def next(self):
        """Returns a PreparedRequest for the next request in a redirect chain."""
        return self._next

    @property
    def apparent_encoding(self):
        """The apparent encoding of the response body."""
        try:
            import charset_normalizer

            best = charset_normalizer.from_bytes(self.content).best()
            if best is not None:
                return best.encoding
        except Exception:
            pass
        try:
            self.content.decode("utf-8")
            return "utf-8"
        except UnicodeDecodeError:
            return "ISO-8859-1"

    def iter_content(self, chunk_size=1, decode_unicode=False):
        """Iterates over the response data.

        When stream=True is set on the request, this avoids reading the content
        at once into memory for large responses.  The chunk size is the number
        of bytes it should read into memory; this is not necessarily the length
        of each item returned as decoding can take place.

        chunk_size must be of type int or None.  A value of None will function
        differently depending on the value of stream: with stream=True data is
        read as it arrives in whatever size the chunks are received.  If
        stream=False, data is returned as a single chunk.
        """

        def generate():
            # Special case for a stream-capable raw object.
            if hasattr(self.raw, "stream"):
                try:
                    yield from self.raw.stream(chunk_size, decode_content=True)
                except Exception as exc:  # pragma: no cover - transport specific
                    raise exceptions.ChunkedEncodingError(exc)
            else:
                # Standard file-like object.
                while True:
                    chunk = self.raw.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

            self._content_consumed = True

        if self._content_consumed and isinstance(self._content, bool):
            raise exceptions.StreamConsumedError(
                "The content for this response was already consumed"
            )
        elif chunk_size is not None and not isinstance(chunk_size, int):
            raise TypeError(
                "chunk_size must be an int, it is instead a %s." % type(chunk_size)
            )

        if self._content_consumed:
            # Simulate reading small chunks of the content.
            chunks = iter_slices(self._content or b"", chunk_size)
        else:
            chunks = generate()

        if decode_unicode:
            chunks = stream_decode_response_unicode(chunks, self)

        return chunks

    def iter_lines(
        self, chunk_size=ITER_CHUNK_SIZE, decode_unicode=False, delimiter=None
    ):
        """Iterates over the response data, one line at a time."""
        pending = None

        for chunk in self.iter_content(
            chunk_size=chunk_size, decode_unicode=decode_unicode
        ):
            if pending is not None:
                chunk = pending + chunk

            if delimiter:
                lines = chunk.split(delimiter)
            else:
                lines = chunk.splitlines()

            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None

            for line in lines:
                yield line

        if pending is not None:
            yield pending

    @property
    def content(self):
        """Content of the response, in bytes."""
        if self._content is False:
            # Read the contents.
            if self._content_consumed:
                raise RuntimeError("The content for this response was already consumed")

            if self.status_code == 0 or self.raw is None:
                self._content = None
            else:
                self._content = b"".join(self.iter_content(CONTENT_CHUNK_SIZE)) or b""

        self._content_consumed = True
        return self._content

    @property
    def text(self):
        """Content of the response, in unicode."""
        encoding = self.encoding

        if not self.content:
            return ""

        # Fallback to auto-detected encoding.
        if self.encoding is None:
            encoding = self.apparent_encoding

        # Decode unicode from given encoding.
        try:
            content = str(self.content, encoding, errors="replace")
        except (LookupError, TypeError):
            # A LookupError is raised if the encoding was not found, which
            # could indicate a misspelling or similar mistake.
            content = str(self.content, errors="replace")

        return content

    def json(self, **kwargs):
        r"""Decodes the JSON response body (if any) into a Python object."""
        if not self.content:
            return None

        try:
            return complexjson.loads(self.text, **kwargs)
        except Exception as exc:
            raise exceptions.JSONDecodeError(str(exc), self.text, 0)

    @property
    def links(self):
        """Returns the parsed header links of the response, if any."""
        header = self.headers.get("link")

        resolved_links = {}

        if header:
            links = parse_header_links(header)

            for link in links:
                key = link.get("rel") or link.get("url")
                resolved_links[key] = link

        return resolved_links

    def raise_for_status(self):
        """Raises HTTPError, if one occurred."""
        http_error_msg = ""
        if isinstance(self.reason, bytes):
            # We attempt to decode utf-8 first because some servers localize
            # their reason strings.  If the string isn't utf-8, fall back to
            # iso-8859-1.
            try:
                reason = self.reason.decode("utf-8")
            except UnicodeDecodeError:
                reason = self.reason.decode("iso-8859-1")
        else:
            reason = self.reason

        if 400 <= self.status_code < 500:
            http_error_msg = "%s Client Error: %s for url: %s" % (
                self.status_code,
                reason,
                self.url,
            )

        elif 500 <= self.status_code < 600:
            http_error_msg = "%s Server Error: %s for url: %s" % (
                self.status_code,
                reason,
                self.url,
            )

        if http_error_msg:
            raise exceptions.HTTPError(http_error_msg, response=self)

    def close(self):
        """Releases the connection back to the pool."""
        if not self._content_consumed and self.raw is not None:
            close = getattr(self.raw, "close", None)
            if close is not None:
                close()

        if self.raw is not None:
            release = getattr(self.raw, "release_conn", None)
            if release is not None:
                release()
        self._content_consumed = True

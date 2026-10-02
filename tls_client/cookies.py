"""Requests-compatible cookie handling.

Subclasses the standard library http.cookiejar.CookieJar so that the jar
participates in Request/Response cookie policy exactly like requests: the
network layer hands us raw Set-Cookie headers and the jar decides which of them
the URL is allowed to store, when they expire, and which ones go back out on
the next request.
"""

import calendar
import copy
import threading
import time
from collections.abc import MutableMapping
from email.message import Message as HTTPMessage
from http.cookiejar import Cookie, CookieJar
from http.cookies import Morsel
from urllib.parse import urlparse, urlunparse

from tls_client._internal_utils import to_native_string

__all__ = [
    "CookieConflictError",
    "CookieJar",
    "MockRequest",
    "MockResponse",
    "RequestsCookieJar",
    "add_dict_to_cookiejar",
    "cookie_header",
    "cookiejar_from_dict",
    "create_cookie",
    "dict_from_cookiejar",
    "extract_cookies",
    "extract_cookies_to_jar",
    "get_cookie_header",
    "merge_cookies",
    "morsel_to_cookie",
    "remove_cookie_by_name",
]


class MockRequest:
    """Wraps a PreparedRequest to mimic a urllib2.Request.

    The code in http.cookiejar.CookieJar expects this interface in order to
    correctly manage cookie policies, i.e. determine whether a cookie can be
    set, given the domains of the request and the cookie.
    """

    def __init__(self, request):
        self._r = request
        self._new_headers = {}
        self.type = urlparse(self._r.url).scheme

    def get_type(self):
        return self.type

    def get_host(self):
        return urlparse(self._r.url).netloc

    def get_origin_req_host(self):
        return self.get_host()

    def get_full_url(self):
        # Only return the response's URL if the user hadn't set the Host header
        if not self._r.headers.get("Host"):
            return self._r.url
        # If they did set it, retrieve it and reconstruct the expected domain
        host = to_native_string(self._r.headers["Host"], encoding="utf-8")
        parsed = urlparse(self._r.url)
        # Reconstruct the URL as we expect it
        return urlunparse(
            [
                parsed.scheme,
                host,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            ]
        )

    def is_unverifiable(self):
        return True

    def has_header(self, name):
        return name in self._r.headers or name in self._new_headers

    def get_header(self, name, default=None):
        return self._r.headers.get(name, self._new_headers.get(name, default))

    def add_header(self, key, val):
        """cookiejar has no legitimate use for this method."""
        raise NotImplementedError(
            "Cookie headers should be added with add_unredirected_header()"
        )

    def add_unredirected_header(self, name, value):
        self._new_headers[name] = value

    def get_new_headers(self):
        return self._new_headers

    @property
    def unverifiable(self):
        return self.is_unverifiable()

    @property
    def origin_req_host(self):
        return self.get_origin_req_host()

    @property
    def host(self):
        return self.get_host()


class MockResponse:
    """Wraps an httplib.HTTPMessage to mimic a urllib.addinfourl.

    Expose the parsed HTTP headers from the server response the way
    http.cookiejar expects to see them.
    """

    def __init__(self, headers):
        self._headers = headers

    def info(self):
        return self._headers

    def getheaders(self, name):
        return self._headers.getheaders(name)


class CookieConflictError(RuntimeError):
    """Two cookies in the jar meet the same lookup criteria.

    Use .get and .set and include domain and path args in order to be more
    specific.
    """


class RequestsCookieJar(CookieJar, MutableMapping):
    """A http.cookiejar.CookieJar that also exposes a dict interface.

    This is the CookieJar created by default for requests and sessions that do
    not specify one, since some clients may expect response.cookies and
    session.cookies to support dict operations.

    Unlike a regular CookieJar, this class is pickleable.

    .. warning:: dictionary operations that are normally O(1) may be O(n).
    """

    def get(self, name, default=None, domain=None, path=None):
        """Dict-like get() that also supports optional domain and path args.

        The extra arguments resolve naming collisions when one jar is used
        across multiple domains.

        .. warning:: operation is O(n), not O(1).
        """
        try:
            return self._find_no_duplicates(name, domain, path)
        except KeyError:
            return default

    def set(self, name, value, **kwargs):
        """Dict-like set() that also supports optional domain and path args.

        Unsets a cookie when value is None.
        """
        if value is None:
            remove_cookie_by_name(
                self, name, domain=kwargs.get("domain"), path=kwargs.get("path")
            )
            return None

        if isinstance(value, Morsel):
            c = morsel_to_cookie(value)
        else:
            c = create_cookie(name, value, **kwargs)
        self.set_cookie(c)
        return c

    def iterkeys(self):
        """Dict-like iterkeys() that yields the names of cookies in the jar."""
        for cookie in iter(self):
            yield cookie.name

    def keys(self):
        """Dict-like keys() that returns a list of cookie names."""
        return list(self.iterkeys())

    def itervalues(self):
        """Dict-like itervalues() that yields the values of cookies in the jar."""
        for cookie in iter(self):
            yield cookie.value

    def values(self):
        """Dict-like values() that returns a list of cookie values."""
        return list(self.itervalues())

    def iteritems(self):
        """Dict-like iteritems() that yields name-value tuples."""
        for cookie in iter(self):
            yield cookie.name, cookie.value

    def items(self):
        """Dict-like items() that returns a list of name-value tuples.

        Allows client-code to call dict(RequestsCookieJar) and get a vanilla
        python dict of key value pairs.
        """
        return list(self.iteritems())

    def list_domains(self):
        """Utility method to list all the domains in the jar."""
        domains = []
        for cookie in iter(self):
            if cookie.domain not in domains:
                domains.append(cookie.domain)
        return domains

    def list_paths(self):
        """Utility method to list all the paths in the jar."""
        paths = []
        for cookie in iter(self):
            if cookie.path not in paths:
                paths.append(cookie.path)
        return paths

    def multiple_domains(self):
        """Returns True when the jar holds cookies for more than one domain."""
        domains = []
        for cookie in iter(self):
            if cookie.domain is not None and cookie.domain in domains:
                return True
            domains.append(cookie.domain)
        return False  # there is only one domain in jar

    def get_dict(self, domain=None, path=None):
        """Return a plain dict of the name-value pairs matching domain/path."""
        dictionary = {}
        for cookie in iter(self):
            if (domain is None or cookie.domain == domain) and (
                path is None or cookie.path == path
            ):
                dictionary[cookie.name] = cookie.value
        return dictionary

    def __contains__(self, name):
        try:
            return super().__contains__(name)
        except CookieConflictError:
            return True

    def __getitem__(self, name):
        """Dict-like __getitem__ for compatibility with client code.

        Raises when more than one cookie matches the name; use get() with
        domain/path in that case.

        .. warning:: operation is O(n), not O(1).
        """
        return self._find_no_duplicates(name)

    def __setitem__(self, name, value):
        """Dict-like __setitem__ for compatibility with client code."""
        self.set(name, value)

    def __delitem__(self, name):
        """Delete a cookie by name (wraps remove_cookie_by_name)."""
        remove_cookie_by_name(self, name)

    def set_cookie(self, cookie, *args, **kwargs):
        if (
            cookie.value is not None
            and cookie.value.startswith('"')
            and cookie.value.endswith('"')
        ):
            cookie.value = cookie.value.replace('\\"', "")
        return super().set_cookie(cookie, *args, **kwargs)

    def update(self, other):
        """Updates this jar with cookies from another CookieJar or dict-like."""
        if isinstance(other, CookieJar):
            for cookie in other:
                self.set_cookie(copy.copy(cookie))
        else:
            super().update(other)

    def _find(self, name, domain=None, path=None):
        """Requests uses this method internally to get cookie values.

        If there are conflicting cookies, _find arbitrarily chooses one.  See
        _find_no_duplicates if you want an exception thrown for conflicts.
        """
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        return cookie.value

        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def _find_no_duplicates(self, name, domain=None, path=None):
        """Both __getitem__ and get call this function.

        :raises KeyError: if cookie is not found
        :raises CookieConflictError: if there are multiple cookies that match
            name and optionally domain and path
        """
        toReturn = None
        for cookie in iter(self):
            if cookie.name == name:
                if domain is None or cookie.domain == domain:
                    if path is None or cookie.path == path:
                        if toReturn is not None:
                            # if there are multiple cookies that meet the passed
                            # in criteria, raise an exception because this method
                            # expects only one cookie
                            raise CookieConflictError(
                                "There are multiple cookies with name, %r" % (name)
                            )
                        toReturn = cookie.value

        if toReturn:
            return toReturn
        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def __getstate__(self):
        """Unlike a normal CookieJar, this class is pickleable."""
        state = self.__dict__.copy()
        # remove the unpickleable RLock object
        state.pop("_cookies_lock", None)
        return state

    def __setstate__(self, state):
        """Unlike a normal CookieJar, this class is pickleable."""
        self.__dict__.update(state)
        if not hasattr(self, "_cookies_lock"):
            self._cookies_lock = threading.RLock()

    def copy(self):
        """Return a copy of this RequestsCookieJar."""
        new_cj = RequestsCookieJar()
        new_cj.set_policy(self.get_policy())
        new_cj.update(self)
        return new_cj

    def get_policy(self):
        """Return the CookiePolicy instance used."""
        return self._policy


def _copy_cookie_jar(jar):
    if jar is None:
        return None

    if hasattr(jar, "copy"):
        # We're dealing with an instance of RequestsCookieJar
        return jar.copy()
    # We're dealing with a generic CookieJar instance
    new_jar = copy.copy(jar)
    new_jar.clear()
    for cookie in jar:
        new_jar.set_cookie(copy.copy(cookie))
    return new_jar


def create_cookie(name, value, **kwargs):
    """Make a cookie from underspecified parameters.

    By default, the pair of name and value will be set for the domain ''
    and sent on every request (this is sometimes called a supercookie).
    """
    result = {
        "version": 0,
        "name": name,
        "value": value,
        "port": None,
        "domain": "",
        "path": "/",
        "secure": False,
        "expires": None,
        "discard": True,
        "comment": None,
        "comment_url": None,
        "rest": {"HttpOnly": None},
        "rfc2109": False,
    }

    badargs = set(kwargs) - set(result)
    if badargs:
        raise TypeError(
            "create_cookie() got unexpected keyword arguments: %s" % (list(badargs),)
        )

    result.update(kwargs)
    result["port_specified"] = bool(result["port"])
    result["domain_specified"] = bool(result["domain"])
    result["domain_initial_dot"] = result["domain"].startswith(".")
    result["path_specified"] = bool(result["path"])

    return Cookie(**result)


def morsel_to_cookie(morsel):
    """Convert a Morsel object into a Cookie containing the one k/v pair."""
    expires = None
    if morsel["max-age"]:
        try:
            expires = int(time.time() + int(morsel["max-age"]))
        except ValueError:
            raise TypeError("max-age: %s must be integer" % (morsel["max-age"],))
    elif morsel["expires"]:
        time_template = "%a, %d-%b-%Y %H:%M:%S GMT"
        expires = calendar.timegm(time.strptime(morsel["expires"], time_template))
    return create_cookie(
        comment=morsel["comment"],
        comment_url=bool(morsel["comment"]),
        discard=False,
        domain=morsel["domain"],
        expires=expires,
        name=morsel.key,
        path=morsel["path"],
        port=None,
        rest={"HttpOnly": morsel["httponly"]},
        rfc2109=False,
        secure=bool(morsel["secure"]),
        value=morsel.value,
        version=morsel["version"] or 0,
    )


def cookiejar_from_dict(cookie_dict, cookiejar=None, overwrite=True):
    """Returns a CookieJar from a key/value dictionary.

    :param cookie_dict: Dict of key/values to insert into CookieJar.
    :param cookiejar: (optional) A cookiejar to add the cookies to.
    :param overwrite: (optional) If False, will not replace cookies already in
        the jar with new ones.
    """
    if cookiejar is None:
        cookiejar = RequestsCookieJar()

    if cookie_dict is not None:
        names_from_jar = [cookie.name for cookie in cookiejar]
        for name in cookie_dict:
            if overwrite or (name not in names_from_jar):
                cookiejar.set_cookie(create_cookie(name, cookie_dict[name]))

    return cookiejar


def merge_cookies(cookiejar, cookies):
    """Add cookies to cookiejar and return a merged CookieJar.

    :param cookiejar: CookieJar object to add the cookies to.
    :param cookies: Dictionary or CookieJar object to be added.
    """
    if not isinstance(cookiejar, CookieJar):
        raise ValueError("You can only merge into CookieJar")

    if isinstance(cookies, dict):
        cookiejar = cookiejar_from_dict(cookies, cookiejar=cookiejar, overwrite=False)
    elif isinstance(cookies, CookieJar):
        try:
            cookiejar.update(cookies)
        except AttributeError:
            for cookie_in_jar in cookies:
                cookiejar.set_cookie(cookie_in_jar)

    return cookiejar


def remove_cookie_by_name(cookiejar, name, domain=None, path=None):
    """Unsets a cookie by name, by default over all domains and paths.

    Wraps CookieJar.clear(), is O(n).
    """
    clearables = []
    for cookie in cookiejar:
        if cookie.name != name:
            continue
        if domain is not None and domain != cookie.domain:
            continue
        if path is not None and path != cookie.path:
            continue
        clearables.append((cookie.domain, cookie.path, cookie.name))

    for domain, path, name in clearables:
        cookiejar.clear(domain, path, name)


def get_cookie_header(jar, request):
    """Produce a Cookie header string for request, or None."""
    r = MockRequest(request)
    jar.add_cookie_header(r)
    return r.get_new_headers().get("Cookie")


def extract_cookies_to_jar(jar, request, response):
    """Extract the cookies from the response into a CookieJar.

    :param jar: http.cookiejar.CookieJar (not necessarily a RequestsCookieJar)
    :param request: our own requests.Request object
    :param response: a urllib3-style HTTPResponse object
    """
    if not (hasattr(response, "_original_response") and response._original_response):
        return
    # the _original_response field is the wrapped httplib.HTTPResponse object
    req = MockRequest(request)
    # pull out the HTTPMessage with the headers and put it in the mock:
    res = MockResponse(response._original_response.msg)
    jar.extract_cookies(res, req)


# ---------------------------------------------------------------------------
# tls_client specific helpers
# ---------------------------------------------------------------------------


def cookie_header(jar, url):
    """Return the Cookie header value a jar would send to *url*, or an empty string.

    The Go engine runs with an empty jar of its own, so this jar is the only
    cookie store in play and it has to apply the same policy the standard
    library would: a Secure cookie must not travel over plain http, an expired
    cookie must not be sent, a cookie scoped to another domain or to a path the
    request does not reach must stay behind.  Delegating to
    ``CookieJar.add_cookie_header`` is what guarantees that.
    """
    request = MockRequest(_UrlOnlyRequest(url))
    try:
        jar.add_cookie_header(request)
    except Exception:
        # A malformed cookie or an exotic custom jar must not break the request;
        # fall back to sending nothing rather than guessing.
        return ""
    return request.get_new_headers().get("Cookie") or ""


class _UrlOnlyRequest:
    """Minimal PreparedRequest stand-in for the cookie policy machinery.

    ``add_cookie_header`` needs ``url`` and ``headers``; nothing else is read.
    """

    __slots__ = ("headers", "url")

    def __init__(self, url):
        self.url = url
        self.headers = {}


def extract_cookies(headers, url):
    """Build a RequestsCookieJar from raw response headers and the request URL.

    The Set-Cookie attributes are interpreted by ``CookieJar.extract_cookies``
    rather than assigned directly, because that is what enforces the policy:
    a Domain attribute naming a host the response did not come from is rejected
    (otherwise any site could plant cookies for any other site), a Max-Age=0 or
    past Expires deletes instead of resurrecting, and Secure/HttpOnly land in
    the cookie's flags.
    """
    jar = RequestsCookieJar()

    values = []
    for name, value in (headers or {}).items():
        if str(name).lower() == "set-cookie":
            values = value
            break
    if not isinstance(values, (list, tuple)):
        values = [values]

    # RFC 6265 allows repeated Set-Cookie headers; fold them into one
    # HTTPMessage so the policy sees each cookie separately.  Header values may
    # arrive as bytes (urllib3 does that for some transports) and the email
    # module only accepts str.
    message = HTTPMessage()
    for value in values:
        if not value:
            continue
        message.add_header("Set-Cookie", to_native_string(value))
    if not message.get_all("Set-Cookie"):
        return jar

    try:
        jar.extract_cookies(MockResponse(message), MockRequest(_UrlOnlyRequest(url)))
    except Exception:
        # The policy rejected something malformed; the jar keeps what it took.
        pass
    return jar


def dict_from_cookiejar(jar):
    """Returns a key/value dictionary from a CookieJar."""
    if hasattr(jar, "get_dict"):
        return jar.get_dict()
    return {cookie.name: cookie.value for cookie in jar}


def add_dict_to_cookiejar(cj, cookie_dict):
    """Returns a CookieJar from a key/value dictionary."""
    return cookiejar_from_dict(cookie_dict, cj)

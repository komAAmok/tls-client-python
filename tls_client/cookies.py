"""Dependency-free Requests-style cookie jar."""

from collections.abc import MutableMapping
from http.cookies import SimpleCookie
from urllib.parse import urlsplit


class CookieConflictError(RuntimeError):
    pass


class RequestsCookieJar(MutableMapping):
    def __init__(self):
        self._cookies = {}

    def set(self, name, value, **kwargs):
        domain = kwargs.get("domain") or ""
        path = kwargs.get("path") or "/"
        key = (domain.lower(), path, str(name))
        if value is None:
            self._cookies.pop(key, None)
        else:
            self._cookies[key] = str(value)
        return value

    def set_cookie(self, cookie, *args, **kwargs):
        return self.set(
            cookie.name,
            cookie.value,
            domain=getattr(cookie, "domain", ""),
            path=getattr(cookie, "path", "/"),
        )

    def get(self, name, default=None, domain=None, path=None):
        matches = []
        for (item_domain, item_path, item_name), value in self._cookies.items():
            if item_name != name:
                continue
            if domain is not None and item_domain != domain.lower():
                continue
            if path is not None and item_path != path:
                continue
            matches.append(value)
        if not matches:
            return default
        if len(set(matches)) > 1:
            raise CookieConflictError("multiple cookies exist with name %r" % name)
        return matches[0]

    def get_dict(self, domain=None, path=None):
        result = {}
        for (item_domain, item_path, name), value in self._cookies.items():
            if domain is not None and item_domain != domain.lower():
                continue
            if path is not None and item_path != path:
                continue
            result[name] = value
        return result

    def update(self, other=None, **kwargs):
        if isinstance(other, RequestsCookieJar):
            self._cookies.update(other._cookies)
        elif other:
            for name, value in dict(other).items():
                self.set(name, value)
        for name, value in kwargs.items():
            self.set(name, value)

    def copy(self):
        jar = RequestsCookieJar()
        jar._cookies.update(self._cookies)
        return jar

    def list_domains(self):
        return sorted(set(key[0] for key in self._cookies))

    def list_paths(self):
        return sorted(set(key[1] for key in self._cookies))

    def multiple_domains(self):
        return len(set(key[0] for key in self._cookies)) > 1

    def clear(self, domain=None, path=None, name=None):
        if domain is None and path is None and name is None:
            self._cookies.clear()
            return
        for key in list(self._cookies):
            item_domain, item_path, item_name = key
            if domain is not None and item_domain != domain.lower():
                continue
            if path is not None and item_path != path:
                continue
            if name is not None and item_name != name:
                continue
            del self._cookies[key]

    def __getitem__(self, name):
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def __setitem__(self, name, value):
        self.set(name, value)

    def __delitem__(self, name):
        found = False
        for key in list(self._cookies):
            if key[2] == name:
                del self._cookies[key]
                found = True
        if not found:
            raise KeyError(name)

    def __iter__(self):
        seen = set()
        for _, _, name in self._cookies:
            if name not in seen:
                seen.add(name)
                yield name

    def __len__(self):
        return len(set(key[2] for key in self._cookies))

    def __repr__(self):
        return "<RequestsCookieJar %r>" % self.get_dict()


CookieJar = RequestsCookieJar


def cookiejar_from_dict(cookie_dict, cookiejar=None, overwrite=True):
    jar = cookiejar or RequestsCookieJar()
    for name, value in (cookie_dict or {}).items():
        if overwrite or jar.get(name) is None:
            jar.set(name, value)
    return jar


def dict_from_cookiejar(jar):
    return jar.get_dict() if hasattr(jar, "get_dict") else dict(jar)


def merge_cookies(cookiejar, cookies):
    cookiejar.update(cookies or {})
    return cookiejar


def cookie_header(jar, url):
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    pairs = []
    for (domain, cookie_path, name), value in jar._cookies.items():
        if domain:
            bare_domain = domain.lstrip(".")
            if host != bare_domain and not host.endswith("." + bare_domain):
                continue
        if not path.startswith(cookie_path):
            continue
        pairs.append("%s=%s" % (name, value))
    return "; ".join(pairs)


def extract_cookies(headers, url):
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    jar = RequestsCookieJar()
    values = []
    for name, value in headers.items():
        if str(name).lower() == "set-cookie":
            values = value
            break
    if not isinstance(values, (list, tuple)):
        values = [values]
    for value in values:
        parsed_cookie = SimpleCookie()
        try:
            parsed_cookie.load(value)
        except Exception:
            continue
        for name, morsel in parsed_cookie.items():
            jar.set(
                name,
                morsel.value,
                domain=morsel["domain"] or host,
                path=morsel["path"] or "/",
            )
    return jar

"""Authentication helpers compatible with the common Requests API."""

import base64


class AuthBase(object):
    def __call__(self, request):
        raise NotImplementedError("authentication classes must implement __call__")


class HTTPBasicAuth(AuthBase):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __call__(self, request):
        raw = ("%s:%s" % (self.username, self.password)).encode("latin1")
        request.headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        return request

    def __eq__(self, other):
        return (
            isinstance(other, HTTPBasicAuth)
            and self.username == other.username
            and self.password == other.password
        )


class HTTPProxyAuth(HTTPBasicAuth):
    def __call__(self, request):
        raw = ("%s:%s" % (self.username, self.password)).encode("latin1")
        request.headers["Proxy-Authorization"] = (
            "Basic " + base64.b64encode(raw).decode("ascii")
        )
        return request


class HTTPDigestAuth(AuthBase):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __call__(self, request):
        raise NotImplementedError("HTTP Digest authentication requires challenge replay")


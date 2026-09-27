"""The Requests API, mirroring requests.api."""

from typing import Any, Optional

from tls_client.sessions import Session

__all__ = [
    "delete",
    "get",
    "head",
    "options",
    "patch",
    "post",
    "put",
    "request",
]


def request(method: str, url: Any, **kwargs: Any):
    """Constructs and sends a Request.

    :param method: method for the new Request object: GET, OPTIONS, HEAD, POST,
        PUT, PATCH, or DELETE.
    :param url: URL for the new Request object.
    :param params: (optional) Dictionary, list of tuples or bytes to send in
        the query string for the Request.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the Request.
    :param json: (optional) A JSON serializable Python object to send in the
        body of the Request.
    :param headers: (optional) Dictionary of HTTP Headers to send with the
        Request.
    :param cookies: (optional) Dict or CookieJar object to send with the
        Request.
    :param files: (optional) Dictionary of name: file-like-objects (or
        {'name': file-tuple}) for multipart encoding upload.
    :param auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
    :param timeout: (optional) How many seconds to wait for the server to send
        data before giving up, as a float, or a (connect timeout, read timeout)
        tuple.
    :param allow_redirects: (optional) Boolean.  Enable/disable redirection.
        Defaults to True.
    :param proxies: (optional) Dictionary mapping protocol to the URL of the
        proxy.
    :param verify: (optional) Either a boolean, in which case it controls
        whether we verify the server's TLS certificate, or a string, in which
        case it must be a path to a CA bundle to use.  Defaults to True.
    :param stream: (optional) if False, the response content will be
        immediately downloaded.
    :param cert: (optional) if String, path to ssl client cert file (.pem).
        If Tuple, ('cert', 'key') pair.
    :return: Response object

    Any TLS-client knob may be passed as well (client_identifier, tcp_ttl,
    tcp_mss, ...); it overrides the session value for this one call.

    Usage::

      >>> import tls_client as requests
      >>> req = requests.request('GET', 'https://example.com/')
      >>> req
      <Response [200]>
    """
    # By using the 'with' statement we are sure the session is closed, thus we
    # avoid leaving sockets open which can trigger a ResourceWarning in some
    # cases, and look like a memory leak in others.
    with Session() as session:
        return session.request(method=method, url=url, **kwargs)


def get(url: Any, params: Optional[Any] = None, **kwargs: Any):
    r"""Sends a GET request.

    :param url: URL for the new Request object.
    :param params: (optional) Dictionary, list of tuples or bytes to send in
        the query string for the Request.
    :param **kwargs: Optional arguments that request takes.
    :return: Response object
    """
    return request("get", url, params=params, **kwargs)


def options(url: Any, **kwargs: Any):
    r"""Sends an OPTIONS request.

    :param url: URL for the new Request object.
    :param **kwargs: Optional arguments that request takes.
    :return: Response object
    """
    return request("options", url, **kwargs)


def head(url: Any, **kwargs: Any):
    r"""Sends a HEAD request.

    :param url: URL for the new Request object.
    :param **kwargs: Optional arguments that request takes.  If
        allow_redirects is not provided, it will be set to False (as opposed to
        the default request behavior).
    :return: Response object
    """
    kwargs.setdefault("allow_redirects", False)
    return request("head", url, **kwargs)


def post(url: Any, data: Optional[Any] = None, json: Optional[Any] = None, **kwargs: Any):
    r"""Sends a POST request.

    :param url: URL for the new Request object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the Request.
    :param json: (optional) A JSON serializable Python object to send in the
        body of the Request.
    :param **kwargs: Optional arguments that request takes.
    :return: Response object
    """
    return request("post", url, data=data, json=json, **kwargs)


def put(url: Any, data: Optional[Any] = None, **kwargs: Any):
    r"""Sends a PUT request.

    :param url: URL for the new Request object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the Request.
    :param **kwargs: Optional arguments that request takes.
    :return: Response object
    """
    return request("put", url, data=data, **kwargs)


def patch(url: Any, data: Optional[Any] = None, **kwargs: Any):
    r"""Sends a PATCH request.

    :param url: URL for the new Request object.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the Request.
    :param **kwargs: Optional arguments that request takes.
    :return: Response object
    """
    return request("patch", url, data=data, **kwargs)


def delete(url: Any, **kwargs: Any):
    r"""Sends a DELETE request.

    :param url: URL for the new Request object.
    :param **kwargs: Optional arguments that request takes.
    :return: Response object
    """
    return request("delete", url, **kwargs)

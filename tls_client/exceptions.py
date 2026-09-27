"""Requests-compatible exception hierarchy."""

from json import JSONDecodeError as _JSONDecodeError

__all__ = [
    "BaseHTTPError",
    "ChunkedEncodingError",
    "CompatJSONDecodeError",
    "ConnectTimeout",
    "ConnectionError",
    "ContentDecodingError",
    "FileModeWarning",
    "HTTPError",
    "InvalidHeader",
    "InvalidJSONError",
    "InvalidProxyURL",
    "InvalidSchema",
    "InvalidURL",
    "JSONDecodeError",
    "MissingSchema",
    "ProxyError",
    "ReadTimeout",
    "RequestException",
    "RequestsDependencyWarning",
    "RequestsJSONDecodeError",
    "RequestsSSLError",
    "RequestsWarning",
    "RetryError",
    "SSLError",
    "StreamConsumedError",
    "Timeout",
    "TooManyRedirects",
    "URLRequired",
    "UnrewindableBodyError",
]


class RequestException(IOError):
    """There was an ambiguous exception that occurred while handling a request."""

    def __init__(self, *args, **kwargs):
        """Initialize RequestException with response and request."""
        self.response = kwargs.pop("response", None)
        self.request = kwargs.pop("request", None)
        if self.response is not None and self.request is None:
            self.request = getattr(self.response, "request", None)
        super(RequestException, self).__init__(*args)


#: Aliases requests keeps for the urllib3 base error and the stdlib decoder.
BaseHTTPError = Exception
CompatJSONDecodeError = _JSONDecodeError


class InvalidJSONError(RequestException):
    """A JSON error occurred."""


class JSONDecodeError(InvalidJSONError, _JSONDecodeError):
    """Couldn't decode the text into json.

    Kept compatible with requests >= 2.27, which mixes the requests base class
    into the stdlib exception so 'except requests.RequestException' catches
    decoding failures too.
    """

    def __init__(self, *args, **kwargs) -> None:
        """Build the JSON error first, then the IOError side.

        The json-specific positional arguments must not reach IOError, whose
        single-argument form would swallow them and lose the message.
        """
        _JSONDecodeError.__init__(self, *args)
        InvalidJSONError.__init__(self, *self.args, **kwargs)

    def __reduce__(self):
        """Pickle through the stdlib class, which knows its own arguments.

        The MRO would otherwise pick IOError's single-argument reduce.
        """
        return _JSONDecodeError.__reduce__(self)


class HTTPError(RequestException):
    """An HTTP error occurred."""


class ConnectionError(RequestException):
    """A Connection error occurred."""


class ProxyError(ConnectionError):
    """A proxy error occurred."""


class SSLError(ConnectionError):
    """An SSL error occurred."""


class Timeout(RequestException):
    """The request timed out.

    Catching this error also catches ConnectTimeout and ReadTimeout.
    """


class ConnectTimeout(ConnectionError, Timeout):
    """The request timed out while trying to connect to the remote server.

    Requests that produced this error are safe to retry.
    """


class ReadTimeout(Timeout):
    """The server did not send any data in the allotted amount of time."""


class URLRequired(RequestException):
    """A valid URL is required to make a request."""


class TooManyRedirects(RequestException):
    """Too many redirects."""


class MissingSchema(RequestException, ValueError):
    """The URL scheme (e.g. http or https) is missing."""


class InvalidSchema(RequestException, ValueError):
    """The URL scheme provided is either invalid or unsupported."""


class InvalidURL(RequestException, ValueError):
    """The URL provided was somehow invalid."""


class InvalidHeader(RequestException, ValueError):
    """The header value provided was somehow invalid."""


class InvalidProxyURL(InvalidURL):
    """The proxy URL provided is invalid."""


class ChunkedEncodingError(RequestException):
    """The server declared chunked encoding but sent an invalid chunk."""


class RequestsJSONDecodeError(JSONDecodeError):
    """The name requests uses internally for a decode failure."""


class RequestsSSLError(SSLError):
    """The name requests uses for an SSL failure on a urllib3 response."""


class ContentDecodingError(RequestException, BaseHTTPError):
    """Failed to decode response content."""


class StreamConsumedError(RequestException, TypeError):
    """The content for this response was already consumed."""


class RetryError(RequestException):
    """Custom retries logic failed."""


class UnrewindableBodyError(RequestException):
    """Requests encountered an error when trying to rewind a body."""


class RequestsWarning(Warning):
    """Base warning for Requests."""


class FileModeWarning(RequestsWarning, DeprecationWarning):
    """A file was opened in text mode but its binary length was used."""


class RequestsDependencyWarning(RequestsWarning):
    """An imported dependency doesn't match the expected version range."""

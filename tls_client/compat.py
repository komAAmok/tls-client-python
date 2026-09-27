"""A minimal stand-in for requests.compat.

The original module smooths over Python 2/3 differences and exposes the
vendored or optional third-party modules.  Only the Python 3 surface is
meaningful here; every name requests code commonly imports is re-exported so
imports such as 'from tls_client.compat import urlparse' keep working.
"""

import io
import json
import sys
from base64 import b64decode, b64encode
from collections import OrderedDict
from collections.abc import Callable, Mapping, MutableMapping
from http import cookiejar as cookielib
from http.client import HTTPConnection, HTTPResponse, HTTPSConnection
from http.cookies import Morsel, SimpleCookie
from io import StringIO
from json import JSONDecodeError
from urllib.parse import (
    quote,
    quote_plus,
    unquote,
    unquote_plus,
    urlencode,
    urljoin,
    urlparse,
    urlsplit,
    urlunparse,
    urlunsplit,
)
from urllib.request import (
    getproxies,
    getproxies_environment,
    parse_http_list,
    proxy_bypass,
    proxy_bypass_environment,
)

builtin_str = str
str = str
bytes = bytes
basestring = (str, bytes)
numeric_types = (int, float)
integer_types = (int,)
unicode = str

#: Python 2/3 feature probes requests.compat historically exposed.
is_py2 = False
is_py3 = True
has_simplejson = False

#: True while the installed urllib3 is the 1.x line.  requests uses it to pick
#: between str and bytes handling; the native engine does its own encoding, so
#: the value is informational here.
is_urllib3_1 = False
try:  # pragma: no cover - depends on the environment
    import urllib3 as _urllib3

    is_urllib3_1 = _urllib3.__version__.split(".")[0] == "1"
except ImportError:  # pragma: no cover
    pass

#: True while the installed urllib3 is the 1.x line.  requests uses it to pick
#: between str and bytes handling; the native engine does its own encoding, so
#: the value is informational here.
is_urllib3_1 = False
try:  # pragma: no cover - depends on the environment
    import urllib3 as _urllib3

    is_urllib3_1 = _urllib3.__version__.split(".")[0] == "1"
except ImportError:  # pragma: no cover
    pass


def isdigit(value):
    return value.isdigit()


urllib3 = None
chardet = None
charset_normalizer = None
cryptography = None
pyopenssl = None
OpenSSL = None
ssl = None
ssl_match_hostname = None

try:
    import ssl
except ImportError:  # pragma: no cover - ssl is always present on Py3
    ssl = None

try:  # pragma: no cover - optional dependency
    import urllib3  # type: ignore[no-redef]
except ImportError:
    pass

try:  # pragma: no cover - optional dependency
    import chardet  # type: ignore[no-redef]
except ImportError:
    pass

try:  # pragma: no cover - optional dependency
    import charset_normalizer  # type: ignore[no-redef]
except ImportError:
    pass

try:  # pragma: no cover - optional dependency
    import cryptography  # type: ignore[no-redef]
    import OpenSSL  # type: ignore[no-redef]
    from urllib3.contrib import pyopenssl  # type: ignore[no-redef]
except ImportError:
    pyopenssl = None
    cryptography = None
    OpenSSL = None

try:  # pragma: no cover - stdlib match_hostname, removed in 3.12
    from ssl import match_hostname as ssl_match_hostname  # type: ignore[no-redef]
except ImportError:
    try:  # pragma: no cover - backport for 3.12+
        from backports.ssl_match_hostname import (  # type: ignore[no-redef]
            match_hostname as ssl_match_hostname,
        )
    except ImportError:
        ssl_match_hostname = None

if sys.version_info < (3, 12):  # pragma: no cover - old runtimes only
    try:
        from distutils.version import LooseVersion  # type: ignore[no-redef]
    except ImportError:
        LooseVersion = None
else:
    LooseVersion = None

__all__ = [
    "Callable",
    "HTTPConnection",
    "HTTPResponse",
    "HTTPSConnection",
    "JSONDecodeError",
    "LooseVersion",
    "Mapping",
    "Morsel",
    "MutableMapping",
    "OpenSSL",
    "OrderedDict",
    "SimpleCookie",
    "StringIO",
    "b64decode",
    "b64encode",
    "basestring",
    "builtin_str",
    "bytes",
    "chardet",
    "charset_normalizer",
    "cookielib",
    "cryptography",
    "getproxies",
    "getproxies_environment",
    "has_simplejson",
    "integer_types",
    "io",
    "is_py2",
    "is_py3",
    "is_urllib3_1",
    "isdigit",
    "json",
    "numeric_types",
    "parse_http_list",
    "proxy_bypass",
    "proxy_bypass_environment",
    "pyopenssl",
    "quote",
    "quote_plus",
    "ssl",
    "ssl_match_hostname",
    "str",
    "unicode",
    "unquote",
    "unquote_plus",
    "urlencode",
    "urljoin",
    "urllib3",
    "urlparse",
    "urlsplit",
    "urlunparse",
    "urlunsplit",
]

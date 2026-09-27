"""Module containing bug report helper(s), mirroring requests.help."""

import json
import platform
import ssl
import sys

import tls_client
from tls_client import __version__ as package_version

try:
    import charset_normalizer
except ImportError:  # pragma: no cover - optional dependency
    charset_normalizer = None

try:
    import chardet
except ImportError:  # pragma: no cover - optional dependency
    chardet = None

try:  # pragma: no cover - optional dependency
    from urllib3.contrib import pyopenssl
except ImportError:
    pyopenssl = None
    OpenSSL = None
    cryptography = None
else:  # pragma: no cover - optional dependency
    import cryptography
    import OpenSSL


def _implementation():
    """Return a dict with the Python implementation and version.

    Provide both the name and the version of the Python implementation
    currently running.  For example, on CPython 3.10.3 it returns
    {'name': 'CPython', 'version': '3.10.3'}.
    """
    implementation = platform.python_implementation()

    if implementation == "CPython":
        implementation_version = platform.python_version()
    elif implementation == "PyPy":
        pypy = sys.pypy_version_info
        implementation_version = "%s.%s.%s" % (pypy.major, pypy.minor, pypy.micro)
        if pypy.releaselevel != "final":
            implementation_version = "".join(
                [implementation_version, pypy.releaselevel]
            )
    elif implementation in ("Jython", "IronPython"):
        implementation_version = platform.python_version()  # Complete guess
    else:
        implementation_version = "Unknown"

    return {"name": implementation, "version": implementation_version}


def info():
    """Generate information for a bug report."""
    try:
        platform_info = {
            "system": platform.system(),
            "release": platform.release(),
        }
    except OSError:  # pragma: no cover - platform quirk
        platform_info = {
            "system": "Unknown",
            "release": "Unknown",
        }

    implementation_info = _implementation()
    charset_normalizer_info = {"version": None}
    chardet_info = {"version": None}
    if charset_normalizer:
        charset_normalizer_info = {"version": charset_normalizer.__version__}
    if chardet:
        chardet_info = {"version": chardet.__version__}

    system_ssl = ssl.OPENSSL_VERSION_NUMBER
    system_ssl_info = {"version": "%x" % system_ssl if system_ssl is not None else ""}

    return {
        "platform": platform_info,
        "implementation": implementation_info,
        "system_ssl": system_ssl_info,
        "using_pyopenssl": pyopenssl is not None,
        "using_charset_normalizer": chardet is None,
        "pyOpenSSL": {
            "version": getattr(OpenSSL, "__version__", None),
            "openssl_version": (
                "%x" % OpenSSL.SSL.OPENSSL_VERSION_NUMBER if OpenSSL else ""
            ),
        },
        "cryptography": {"version": getattr(cryptography, "__version__", "")},
        "charset_normalizer": charset_normalizer_info,
        "chardet": chardet_info,
        "tls_client": {
            "version": getattr(package_version, "__version__", str(package_version)),
            "location": getattr(tls_client, "__file__", ""),
        },
    }


def main():
    """Pretty-print the bug information as JSON."""
    print(json.dumps(info(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()

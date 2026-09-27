"""
tls_client.certs
~~~~~~~~~~~~~~~~

Returns the preferred default CA certificate bundle.

Unlike requests, this package does not vendor certifi: the Go engine ships its
own trust store.  When certifi *is* installed its bundle is returned so
"verify=<path to CA bundle>" style call sites keep working; otherwise the
function falls back to the interpreter's own default verify path.
"""

import ssl

__all__ = ["where"]


def where() -> str:
    """Return the path of the default CA bundle used for TLS verification."""
    try:
        from certifi import where as _certifi_where

        return _certifi_where()
    except ImportError:
        pass

    paths = ssl.get_default_verify_paths()
    for candidate in (paths.cafile, paths.openssl_cafile):
        if candidate:
            return candidate
    return ""


if __name__ == "__main__":
    print(where())

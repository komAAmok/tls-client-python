"""Backwards-compatibility shims, mirroring requests.packages.

Historical code does 'from requests.packages.urllib3.util import ...'.  The
sub-modules are only aliased when the third-party distribution is actually
installed; the names always exist so 'tls_client.packages.urllib3' does not
raise AttributeError.
"""

import sys

urllib3 = None
idna = None
chardet = None
charset_normalizer = None

for _package in ("urllib3", "idna"):
    try:
        _module = __import__(_package)
    except ImportError:
        continue

    globals()[_package] = _module

    # This traversal is apparently necessary such that the identities are
    # preserved (requests.packages.urllib3.* is urllib3.*)
    for _mod in list(sys.modules):
        if _mod == _package or _mod.startswith(f"{_package}."):
            sys.modules[f"tls_client.packages.{_mod}"] = sys.modules[_mod]

for _package in ("chardet", "charset_normalizer"):
    try:
        _module = __import__(_package)
    except ImportError:
        continue

    globals()[_package] = _module
    # requests.packages aliases chardet under both its own name and "chardet".
    target = _module.__name__
    for _mod in list(sys.modules):
        if _mod == target or _mod.startswith(f"{target}."):
            _imported = sys.modules[_mod]
            sys.modules[f"tls_client.packages.{_mod}"] = _imported
            sys.modules[f"tls_client.packages.{_mod.replace(target, 'chardet')}"] = (
                _imported
            )

__all__ = ["chardet", "charset_normalizer", "idna", "urllib3"]

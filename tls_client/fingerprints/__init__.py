"""Browser fingerprint presets.

One-stop entry point for coherent browser fingerprints:

    from tls_client.fingerprints import apply, list_presets

    session = Session()
    apply(session, "chrome_152_windows")   # identifier + headers + ordering

A preset bundles the engine client profile (``client_identifier``), the
per-OS coherent header block (``default_headers``), HTTP/2 & HTTP/3
pseudo-header ordering, and header templates for the request-context
layer.  Custom user presets are plain JSON/dict files with optional
``based_on`` inheritance (see ``registry``).
"""

from tls_client.fingerprints import registry as _registry
from tls_client.fingerprints import chrome as _chrome
from tls_client.fingerprints import chrome_full as _chrome_full
from tls_client.fingerprints import firefox as _firefox
from tls_client.fingerprints.chrome_full import header_order_for_dest  # noqa: F401
from tls_client.fingerprints.registry import (  # noqa: F401
    apply,
    list_presets,
    register,
    resolve,
)

_chrome._register(_registry)
_chrome_full._register(_registry)
_firefox._register(_registry)


def load_preset_file(path, *, strict: bool = False) -> str:
    """Register a user preset from a JSON file and return its name."""
    import json

    with open(path, "r", encoding="utf-8") as handle:
        preset = json.load(handle)
    if "name" not in preset:
        raise ValueError("preset file %r lacks a 'name' field" % str(path))
    register(preset, strict=strict)
    return preset["name"]

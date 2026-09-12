"""Preset registry with ``based_on`` inheritance (httpcloak-style).

A preset is a plain dict describing one browser fingerprint bundle:

    {
        "name": "chrome_152_windows",
        "based_on": "chrome_152_base",        # optional inheritance
        "client_identifier": "chrome_152",    # engine TLS/HTTP2 profile
        "default_headers": {...},             # version+OS coherent headers
        "pseudo_header_order": [...],         # HTTP/2 pseudo-header order
        "h3_pseudo_header_order": [...],      # HTTP/3 pseudo-header order
        "header_order": [...],                # navigation header template
        "header_order_xhr": [...],            # XHR header template
        "with_random_tls_extension_order": True,
        "custom_tls_client": None,            # optional full override
        "browser": "chrome",                  # used by the context layer
    }

``resolve()`` walks the ``based_on`` chain (child dict entries win; dict
values merge one level deep, everything else replaces) and returns a
flattened preset.  ``apply()`` writes a resolved preset onto a Session via
the ordinary property setters, so the session-level drift protections and
the Go client-pool cache key behave exactly as for hand-configured
sessions.
"""

from typing import Any, Dict, List, Optional

_PRESETS: Dict[str, Dict[str, Any]] = {}


def register(preset: Dict[str, Any], *, strict: bool = False) -> None:
    """Register a preset.  ``strict=True`` refuses to shadow existing names."""
    name = preset["name"]
    if strict and name in _PRESETS:
        raise ValueError("preset %r already registered" % name)
    _PRESETS[name] = preset


def list_presets() -> List[str]:
    """Return all registered preset names, sorted."""
    return sorted(_PRESETS)


def resolve(name: str) -> Dict[str, Any]:
    """Return the fully-flattened preset *name* (with ``based_on`` applied)."""
    try:
        raw = _PRESETS[name]
    except KeyError:
        raise ValueError(
            "unknown fingerprint preset %r; available: %s"
            % (name, ", ".join(list_presets()))
        ) from None

    chain: List[Dict[str, Any]] = []
    seen = set()
    current: Optional[Dict[str, Any]] = raw
    while current is not None:
        marker = current["name"]
        if marker in seen:
            raise ValueError("based_on cycle at %r" % marker)
        seen.add(marker)
        chain.append(current)
        parent = current.get("based_on")
        current = _PRESETS.get(parent) if parent else None

    resolved: Dict[str, Any] = {}
    for layer in reversed(chain):
        for key, value in layer.items():
            if key == "based_on":
                continue
            if (
                key in resolved
                and isinstance(resolved[key], dict)
                and isinstance(value, dict)
            ):
                merged = dict(resolved[key])
                merged.update(value)
                resolved[key] = merged
            else:
                resolved[key] = value
    resolved.setdefault("name", name)
    resolved.setdefault("browser", "chrome")
    resolved.setdefault("custom_tls_client", None)
    resolved.setdefault("with_random_tls_extension_order", True)
    return resolved


def apply(session: Any, name: str) -> Dict[str, Any]:
    """Apply preset *name* to a ``Session``/``AsyncSession`` and return it.

    Only the keys present in the resolved preset are written; the session
    keeps everything else.  Header templates (``header_order`` /
    ``header_order_xhr``) are stored on the session for use with the
    request-context layer and are NOT sent automatically.
    """
    resolved = resolve(name)

    if resolved.get("with_random_tls_extension_order") is not None:
        session.with_random_tls_extension_order = bool(
            resolved["with_random_tls_extension_order"]
        )
    # client_identifier first: its setter auto-syncs the profile headers
    # when the caller has not customised them, then the preset's explicit
    # per-OS header block (which marks the session as header-managed).
    if resolved.get("client_identifier"):
        session.client_identifier = resolved["client_identifier"]
    if resolved.get("pseudo_header_order"):
        session.pseudo_header_order = list(resolved["pseudo_header_order"])
    if resolved.get("h3_pseudo_header_order"):
        session.h3_pseudo_header_order = list(resolved["h3_pseudo_header_order"])
    if resolved.get("default_headers"):
        session.default_headers = dict(resolved["default_headers"])
    if resolved.get("custom_tls_client"):
        session.custom_tls_client = dict(resolved["custom_tls_client"])

    session._fingerprint_header_order = resolved.get("header_order")
    session._fingerprint_header_order_xhr = resolved.get("header_order_xhr")
    session._fingerprint_preset = name
    return resolved

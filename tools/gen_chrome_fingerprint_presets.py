#!/usr/bin/env python3
"""Generate ``tls_client/fingerprints/chrome_full.py`` from the capture dump.

The Chrome capture dump (``tools/_chrome_captures.json``) holds one record per
Chrome major version 99-153 with the *real* negotiated User-Agent string and
the wire traits recovered from live handshakes.  This script turns that dump
into a self-contained Python module that the ``tls_client.fingerprints``
registry imports, giving every captured major:

* ``chrome_<major>_base``          — client_identifier + wire ordering traits
* ``chrome_<major>_windows``       — Windows header block, based_on the base
* ``chrome_<major>``               — alias of the Windows variant
* ``chrome_<major>_macos``
* ``chrome_<major>_linux``
* ``chrome_<major>_android``
* ``chrome_<major>_ios``

plus the ABI 3 deep-fingerprint knobs (extension permutation, destination-aware
header ordering, PRIORITY-frame suppression and the OS-coherent TCP
fingerprint) so a preset is a *complete* browser bundle rather than just a TLS
ClientHello.

Usage::

    python tools/gen_chrome_fingerprint_presets.py            # write the file
    python tools/gen_chrome_fingerprint_presets.py --check    # CI staleness gate

``--check`` exits non-zero when the checked-in module differs from what the
captures would produce, mirroring ``gen_chrome_profiles.py --check``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CAPTURES = os.path.join(HERE, "_chrome_captures.json")
OUTPUT = os.path.join(REPO, "tls_client", "fingerprints", "chrome_full.py")

# ── OS-coherent TCP fingerprint table ────────────────────────────────────
# Mirrors profiles.DefaultTcpFingerprints on the Go side so the Python preset
# and the engine profile agree byte-for-byte when both are applied.
OS_TCP: Dict[str, Dict[str, Any]] = {
    "windows": {
        "tcp_ttl": 128,
        "tcp_window_size": 64240,
        "tcp_window_scale": 8,
        "tcp_mss": 1460,
        "tcp_dont_fragment": 0,
        "tcp_tos": 0,
        "tcp_no_delay": 1,
        "tcp_window_clamp": 0,
        "tcp_ip_id_mode": "random",
    },
    "macos": {
        "tcp_ttl": 64,
        "tcp_window_size": 65535,
        "tcp_window_scale": 6,
        "tcp_mss": 1460,
        "tcp_dont_fragment": 1,
        "tcp_tos": 0,
        "tcp_no_delay": 1,
        "tcp_window_clamp": 0,
        "tcp_ip_id_mode": "random",
    },
    "linux": {
        "tcp_ttl": 64,
        "tcp_window_size": 65535,
        "tcp_window_scale": 7,
        "tcp_mss": 1460,
        "tcp_dont_fragment": 1,
        "tcp_tos": 0,
        "tcp_no_delay": 1,
        "tcp_window_clamp": 0,
        "tcp_ip_id_mode": "random",
    },
    "android": {
        "tcp_ttl": 64,
        "tcp_window_size": 65535,
        "tcp_window_scale": 7,
        "tcp_mss": 1460,
        "tcp_dont_fragment": 1,
        "tcp_tos": 0,
        "tcp_no_delay": 1,
        "tcp_window_clamp": 0,
        "tcp_ip_id_mode": "random",
    },
    "ios": {
        "tcp_ttl": 64,
        "tcp_window_size": 65535,
        "tcp_window_scale": 6,
        "tcp_mss": 1460,
        "tcp_dont_fragment": 1,
        "tcp_tos": 0,
        "tcp_no_delay": 1,
        "tcp_window_clamp": 0,
        "tcp_ip_id_mode": "random",
    },
}

_UA_PLATFORM: Dict[str, str] = {
    "windows": "Windows NT 10.0; Win64; x64",
    "macos": "Macintosh; Intel Mac OS X 10_15_7",
    "linux": "X11; Linux x86_64",
    "android": "Linux; Android 10; K",
}

_PLATFORM_HINT: Dict[str, str] = {
    "windows": '"Windows"',
    "macos": '"macOS"',
    "linux": '"Linux"',
    "android": '"Android"',
    "ios": '"iOS"',
}

# High-entropy Client Hints — per-OS defaults mirroring Chromium.  A value of
# None means "omit the header" (Chrome does not send sec-ch-ua-wow64 off
# Windows, for example); an empty-quoted string is sent verbatim (Chrome sends
# "" for sec-ch-ua-platform-version on Linux and for sec-ch-ua-arch/bitness on
# mobile).
_HINT_PLATFORM_VERSION: Dict[str, str] = {
    "windows": '"15.0.0"',
    "macos": '"14.5.0"',
    "linux": '""',
    "android": '"14.0.0"',
    "ios": '""',
}

_HINT_ARCH: Dict[str, str] = {
    "windows": '"x86"',
    "macos": '"arm"',
    "linux": '"x86"',
    "android": '""',
    "ios": '""',
}

# Brands that carry the real build; everything else is the GREASE token.
_REAL_BRANDS = {"Chromium", "Google Chrome", "Brave", "Opera"}


def _full_version_list(sec_ch_ua: str, full_version: str) -> str:
    """Expand a low-entropy ``sec-ch-ua`` into ``sec-ch-ua-full-version-list``.

    Brand names, order and the GREASE token are preserved verbatim; real brands
    get the exact capture build while the GREASE brand keeps its major expanded
    to ``<major>.0.0.0`` (matching Chromium's per-brand full version expansion).
    """
    out = []
    for part in sec_ch_ua.split(","):
        part = part.strip()
        if not part:
            continue
        brand, sep, ver = part.partition(";v=")
        brand = brand.strip().strip('"')
        ver = ver.strip().strip('"')
        if not sep:
            out.append(part)
        elif not ver or "." in ver:
            out.append(part)
        elif brand in _REAL_BRANDS:
            out.append('"%s";v="%s"' % (brand, full_version))
        else:
            out.append('"%s";v="%s.0.0.0"' % (brand, ver))
    return ", ".join(out)


def _high_entropy_hints(os_name: str, sec_ch_ua: str, full_version: str) -> Dict[str, str]:
    """Return the six high-entropy Client Hints for an OS (None = omit)."""
    is_mobile = os_name in ("android", "ios")
    hints: Dict[str, str] = {
        "sec-ch-ua-full-version-list": _full_version_list(sec_ch_ua, full_version),
        "sec-ch-ua-platform-version": _HINT_PLATFORM_VERSION[os_name],
        "sec-ch-ua-arch": _HINT_ARCH[os_name],
        "sec-ch-ua-bitness": '""' if is_mobile else '"64"',
        "sec-ch-ua-model": '""',
    }
    # sec-ch-ua-wow64 is Windows-only.
    if os_name == "windows":
        hints["sec-ch-ua-wow64"] = "?0"
    return hints

# Chromium's wire order for the high-entropy block, after the low-entropy trio.
_HIGH_ENTROPY_ORDER = [
    "sec-ch-ua-platform-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-wow64",
]

_ACCEPT_HTML = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/apng,*/*;q=0.8,"
    "application/signed-exchange;v=b3;q=0.7"
)

# Navigation (document) request header order — Chromium emits the
# Sec-Fetch-* block before Accept* on a top-level navigation.  The high-entropy
# Client Hints follow the low-entropy trio when a host advertises Accept-CH.
_NAV_ORDER = [
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-wow64",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-encoding",
    "accept-language",
    "priority",
    "cookie",
]

# Sub-resource (XHR / fetch / image / script) order — no
# Upgrade-Insecure-Requests, no Sec-Fetch-User, Referer instead.
_SUBRESOURCE_ORDER = [
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-wow64",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
    "accept-language",
    "priority",
    "cookie",
]

# Grease-brand rotation.  Chromium rotates the middle GREASE brand token each
# milestone; these are the tokens observed in the captures.  Versions outside
# the table reuse the nearest known token.
_GREASE_BRANDS = [
    '"Not?A_Brand";v="24"',
    '"Not?A_Brand";v="8"',
    '"Not/A)Brand";v="8"',
    '"Not.A/Brand";v="8"',
    '"Not_A Brand";v="8"',
    '"Not)A;Brand";v="99"',
    '"Not(A:Brand";v="24"',
    '"Not;A=Brand";v="24"',
    '"Not?A_Brand";v="99"',
]


def _sec_ch_ua(version: str, index: int) -> str:
    brand = _GREASE_BRANDS[index % len(_GREASE_BRANDS)]
    return '"Chromium";v="%s", %s, "Google Chrome";v="%s"' % (version, brand, version)


def _ios_headers(version: str, sec_ch_ua: str, full_version: str) -> Dict[str, str]:
    headers: Dict[str, str] = {
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)"
            " AppleWebKit/605.1.15 (KHTML, like Gecko)"
            " CriOS/%s.0.0.0 Mobile/15E148 Safari/604.1" % version
        ),
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"iOS"',
        "Accept": _ACCEPT_HTML,
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
    }
    headers.update(_high_entropy_hints("ios", sec_ch_ua, full_version))
    return headers


def _replatform_ua(ua: str, os_name: str, version: str) -> str:
    """Return *ua* with its platform token reshaped for *os_name*.

    The captures only carry a Windows UA, so the macOS / Linux / Android
    variants derive a platform-coherent UA from it by swapping the
    parenthesised platform block while preserving the Chrome build token.
    """
    build = version
    m = re.search(r"Chrome/(\S+)", ua)
    if m:
        build = m.group(1)
    if os_name == "android":
        return (
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36"
            " (KHTML, like Gecko) Chrome/%s Mobile Safari/537.36" % build
        )
    if os_name == "ios":
        base = build.split(".")[0]
        return (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)"
            " AppleWebKit/605.1.15 (KHTML, like Gecko)"
            " CriOS/%s Mobile/15E148 Safari/604.1" % base
        )
    return "Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36" % (
        _UA_PLATFORM[os_name], build,
    )


def _build_headers(
    os_name: str, ua_platform: str, platform_hint: str, sec_ch_ua: str, ua: str, full_version: str
) -> Dict[str, str]:
    """Build the OS-coherent header block, reusing the captured UA verbatim."""
    headers: Dict[str, str] = {
        "User-Agent": ua,
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-mobile": "?1" if ua_platform.startswith("Linux; Android") else "?0",
        "sec-ch-ua-platform": platform_hint,
        "Accept": _ACCEPT_HTML,
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
    }
    headers.update(_high_entropy_hints(os_name, sec_ch_ua, full_version))
    return headers


def _emit_preset(name: str, body: Dict[str, Any], indent: int = 4) -> str:
    pad = " " * indent
    lines = ["%s\"%s\": {" % (pad, name)]
    inner = " " * (indent + 4)
    for key, value in body.items():
        lines.append("%s\"%s\": %s," % (inner, key, _py_literal(value, indent + 4)))
    lines.append("%s}," % pad)
    return "\n".join(lines)


def _py_literal(value: Any, indent: int) -> str:
    if isinstance(value, dict):
        items = ", ".join(
            '"%s": %s' % (k, _py_literal(v, indent)) for k, v in value.items()
        )
        return "{%s}" % items
    if isinstance(value, list):
        if not value:
            return "[]"
        if all(isinstance(v, str) and len(v) < 40 for v in value):
            joined = ", ".join('"%s"' % v for v in value)
            if len(joined) + indent < 96:
                return "[%s]" % joined
        return "[\n" + "".join(
            "%s    %s,\n" % (" " * indent, _py_literal(v, indent + 4)) for v in value
        ) + "%s]" % (" " * indent)
    if isinstance(value, bool):
        return "True" if value else "False"
    if value is None:
        return "None"
    if isinstance(value, str):
        return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')
    return repr(value)


HEADER = '''"""Chrome fingerprint presets — every captured major version (99-153).

GENERATED FILE — do not edit by hand.  Regenerate with::

    python tools/gen_chrome_fingerprint_presets.py

Source of truth: ``tools/_chrome_captures.json``, produced by
``tools/extract_chrome_captures.py`` from live ``tls-results`` captures.

Each captured major exposes a ``chrome_<major>_base`` preset plus per-OS
variants (``_windows`` / ``_macos`` / ``_linux`` / ``_android`` / ``_ios``)
and a bare ``chrome_<major>`` alias for the Windows variant.  Presets carry
the full ABI 3 knob set — extension permutation, destination-aware header
ordering, PRIORITY-frame suppression and the OS-coherent TCP fingerprint —
so applying one yields a byte-level browser bundle, not just a ClientHello.

Header *templates* (``header_order`` / ``header_order_xhr``) are stored for
the request-context layer; the destination-aware order is selected at request
time via ``header_order_by_dest``.
"""

from typing import Any, Dict

# Sec-Fetch-Dest keyed header orders (ABI 3 destination-aware ordering).
_NAV_ORDER = [
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-wow64",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "accept-encoding",
    "accept-language",
    "priority",
    "cookie",
]

_SUBRESOURCE_ORDER = [
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-wow64",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
    "accept-language",
    "priority",
    "cookie",
]

# Destination → header-order template.  Chromium reorders the same header
# set per Sec-Fetch-Dest; navigation and everything else are the two
# distinct shapes observed in captures.
_HEADER_ORDER_BY_DEST: Dict[str, list] = {
    "document": list(_NAV_ORDER),
    "iframe": list(_NAV_ORDER),
    "empty": list(_SUBRESOURCE_ORDER),
    "image": list(_SUBRESOURCE_ORDER),
    "script": list(_SUBRESOURCE_ORDER),
    "style": list(_SUBRESOURCE_ORDER),
    "font": list(_SUBRESOURCE_ORDER),
    "audio": list(_SUBRESOURCE_ORDER),
    "video": list(_SUBRESOURCE_ORDER),
    "track": list(_SUBRESOURCE_ORDER),
    "object": list(_SUBRESOURCE_ORDER),
    "embed": list(_SUBRESOURCE_ORDER),
    "manifest": list(_SUBRESOURCE_ORDER),
    "worker": list(_SUBRESOURCE_ORDER),
    "xhr": list(_SUBRESOURCE_ORDER),
    "fetch": list(_SUBRESOURCE_ORDER),
}


def header_order_for_dest(dest: str) -> list:
    """Return the Chromium header-order template for a Sec-Fetch-Dest value."""
    return list(_HEADER_ORDER_BY_DEST.get((dest or "").lower(), _SUBRESOURCE_ORDER))
'''

FOOTER = '''

def _register(registry) -> None:
    for name, preset in sorted(_PRESETS.items()):
        registry.register(dict(preset))


# Number of captured Chrome majors exposed by this module.
CAPTURED_MAJORS = %d
'''


def build_module(captures: Dict[str, Dict[str, Any]]) -> str:
    majors: List[int] = sorted(int(k) for k in captures)
    presets: Dict[str, Dict[str, Any]] = {}

    for idx, major in enumerate(majors):
        rec = captures[str(major)]
        version = str(major)
        full_version = rec.get("version") or ("%s.0.0.0" % version)
        sec_ch_ua = _sec_ch_ua(version, idx)
        ua = rec.get("user_agent") or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            " (KHTML, like Gecko) Chrome/%s.0.0.0 Safari/537.36" % version
        )

        base: Dict[str, Any] = {
            "name": "chrome_%d_base" % major,
            "browser": "chrome",
            "client_identifier": "chrome_%d" % major,
            "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
            "h3_pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
            "header_order": list(_NAV_ORDER),
            "header_order_xhr": list(_SUBRESOURCE_ORDER),
            "header_order_by_dest": True,
            "extension_permute_mode": 1,
            "extension_permute_prefix": 0,
            "h2_disable_priority_frames": False,
            "with_random_tls_extension_order": True,
            "custom_tls_client": None,
        }
        if rec.get("ja3"):
            base["_captured_ja3"] = rec["ja3"]
        if rec.get("ja4"):
            base["_captured_ja4"] = rec["ja4"]
        presets["chrome_%d_base" % major] = base

        # Per-OS variants.
        for os_name in ("windows", "macos", "linux", "android"):
            headers = _build_headers(
                os_name, _UA_PLATFORM[os_name], _PLATFORM_HINT[os_name], sec_ch_ua,
                _replatform_ua(ua, os_name, version), full_version,
            )
            body: Dict[str, Any] = {
                "name": "chrome_%d_%s" % (major, os_name),
                "based_on": "chrome_%d_base" % major,
                "default_headers": headers,
            }
            body.update(OS_TCP[os_name])
            presets["chrome_%d_%s" % (major, os_name)] = body

        ios_body: Dict[str, Any] = {
            "name": "chrome_%d_ios" % major,
            "based_on": "chrome_%d_base" % major,
            "default_headers": _ios_headers(version, sec_ch_ua, full_version),
        }
        ios_body.update(OS_TCP["ios"])
        presets["chrome_%d_ios" % major] = ios_body

        # Bare alias → Windows variant.
        presets["chrome_%d" % major] = {
            "name": "chrome_%d" % major,
            "based_on": "chrome_%d_windows" % major,
        }

    lines = [HEADER, "\n_PRESETS: Dict[str, Dict[str, Any]] = {"]
    for name in presets:
        lines.append(_emit_preset(name, presets[name]))
    lines.append("}")
    lines.append(FOOTER % len(majors))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero if the module is stale")
    args = parser.parse_args()

    with open(CAPTURES, "r", encoding="utf-8") as handle:
        captures = json.load(handle)

    rendered = build_module(captures)

    if args.check:
        try:
            with open(OUTPUT, "r", encoding="utf-8") as handle:
                current = handle.read()
        except FileNotFoundError:
            print("STALE: %s does not exist" % OUTPUT, file=sys.stderr)
            return 1
        if current != rendered:
            print("STALE: %s differs from the captures" % OUTPUT, file=sys.stderr)
            return 1
        print("OK: %s is up to date (%d majors)" % (OUTPUT, len(captures)))
        return 0

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(rendered)
    print("wrote %s (%d majors)" % (OUTPUT, len(captures)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Chrome fingerprint presets.

Header templates and HTTP/2/HTTP/3 wire traits follow captures of recent
Chrome releases (per-OS UA / platform strings rotate with the release;
brand lists keep the GREASE token verbatim).  The TLS/HTTP2 wire profile
itself comes from the engine's ``chrome_152`` client profile; presets only
layer OS-coherent headers and pseudo-header ordering on top.
"""

from typing import Any, Dict

# Chrome 152 captured brand list — the middle "Not?A_Brand" entry is the
# GREASE brand and rotates every release; keep it verbatim per version.
_SEC_CH_UA_152 = '"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"'
_SEC_CH_UA_133 = '"Chromium";v="133", "Not(A:Brand";v="24", "Google Chrome";v="133"'

_CHROME_NAV_ORDER = [
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
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

_CHROME_XHR_ORDER = [
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
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


def _desktop_headers(version: str, ua_platform: str, platform_hint: str,
                     sec_ch_ua: str) -> Dict[str, str]:
    return {
        "User-Agent": (
            "Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko)"
            " Chrome/%s.0.0.0 Safari/537.36" % (ua_platform, version)
        ),
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": platform_hint,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
    }


def _mobile_headers(version: str, ua_platform: str, platform_hint: str,
                    sec_ch_ua: str) -> Dict[str, str]:
    headers = _desktop_headers(version, ua_platform, platform_hint, sec_ch_ua)
    headers["sec-ch-ua-mobile"] = "?1"
    headers["User-Agent"] = (
        "Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/%s.0.0.0 Mobile Safari/537.36" % (ua_platform, version)
    )
    return headers


_CHROME_152_BASE: Dict[str, Any] = {
    "name": "chrome_152_base",
    "browser": "chrome",
    "client_identifier": "chrome_152",
    "pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
    "h3_pseudo_header_order": [":method", ":authority", ":scheme", ":path"],
    "header_order": list(_CHROME_NAV_ORDER),
    "header_order_xhr": list(_CHROME_XHR_ORDER),
    "with_random_tls_extension_order": True,
    "custom_tls_client": None,
}


def _register(registry) -> None:
    registry.register(dict(_CHROME_152_BASE))

    def win(name):
        return {
            "name": name,
            "based_on": "chrome_152_base",
            "default_headers": _desktop_headers("152", "Windows NT 10.0; Win64; x64",
                                                '"Windows"', _SEC_CH_UA_152),
        }

    registry.register(win("chrome_152_windows"))
    registry.register({
        "name": "chrome_152",
        "based_on": "chrome_152_windows",
    })
    registry.register({
        "name": "chrome_152_macos",
        "based_on": "chrome_152_base",
        "default_headers": _desktop_headers("152", "Macintosh; Intel Mac OS X 10_15_7",
                                            '"macOS"', _SEC_CH_UA_152),
    })
    registry.register({
        "name": "chrome_152_linux",
        "based_on": "chrome_152_base",
        "default_headers": _desktop_headers("152", "X11; Linux x86_64",
                                            '"Linux"', _SEC_CH_UA_152),
    })
    registry.register({
        "name": "chrome_152_android",
        "based_on": "chrome_152_base",
        "default_headers": _mobile_headers("152", "Linux; Android 10; K",
                                           '"Android"', _SEC_CH_UA_152),
    })
    registry.register({
        "name": "chrome_152_ios",
        "based_on": "chrome_152_base",
        "default_headers": {
            "User-Agent": (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X)"
                " AppleWebKit/605.1.15 (KHTML, like Gecko)"
                " CriOS/152.0.0.0 Mobile/15E148 Safari/604.1"
            ),
            "sec-ch-ua": _SEC_CH_UA_152,
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"iOS"',
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7"
            ),
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
        },
    })

    # A shipped-identifier preset (works with pre-152 bundled binaries).
    registry.register({
        "name": "chrome_133_windows",
        "based_on": "chrome_152_base",
        "client_identifier": "chrome_133",
        "default_headers": _desktop_headers("133", "Windows NT 10.0; Win64; x64",
                                            '"Windows"', _SEC_CH_UA_133),
    })

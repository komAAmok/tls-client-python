"""Firefox fingerprint presets.

Firefox emits no Client Hints and uses different HTTP/2 pseudo-header
ordering (``:method,:path,:authority,:scheme`` captured order) and H2
SETTINGS (InitialWindowSize 131072, ConnectionFlow 12517377 — engine
profile territory).  Presets layer per-OS headers and the Firefox
pseudo-header order on top of the engine's ``firefox_148`` profile.
"""

from typing import Any, Dict

_FIREFOX_NAV_ORDER = [
    "host",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "upgrade-insecure-requests",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "te",
    "cookie",
]

_FIREFOX_XHR_ORDER = [
    "host",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "referer",
    "te",
    "cookie",
]


def _headers(version: str, ua_platform: str, mobile: bool = False) -> Dict[str, str]:
    if mobile:
        # Firefox on Android: no AppleWebKit/GeckoBuildSuffix tokens.
        ua = (
            "Mozilla/5.0 (%s; rv:%s.0) Gecko/%s.0 Firefox/%s.0"
            % (ua_platform, version, version, version)
        )
    else:
        ua = (
            "Mozilla/5.0 (%s; rv:%s.0) Gecko/20100101 Firefox/%s.0"
            % (ua_platform, version, version)
        )
    return {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "TE": "Trailers",
    }


_FIREFOX_148_BASE: Dict[str, Any] = {
    "name": "firefox_148_base",
    "browser": "firefox",
    "client_identifier": "firefox_148",
    "pseudo_header_order": [":method", ":path", ":authority", ":scheme"],
    "h3_pseudo_header_order": [":method", ":path", ":authority", ":scheme"],
    "header_order": list(_FIREFOX_NAV_ORDER),
    "header_order_xhr": list(_FIREFOX_XHR_ORDER),
    "with_random_tls_extension_order": False,  # Firefox keeps a fixed order
    "custom_tls_client": None,
}


def _register(registry) -> None:
    registry.register(dict(_FIREFOX_148_BASE))

    registry.register({
        "name": "firefox_148",
        "based_on": "firefox_148_base",
        "default_headers": _headers("148", "Windows NT 10.0; Win64; x64"),
    })
    registry.register({
        "name": "firefox_148_windows",
        "based_on": "firefox_148_base",
        "default_headers": _headers("148", "Windows NT 10.0; Win64; x64"),
    })
    registry.register({
        "name": "firefox_148_linux",
        "based_on": "firefox_148_base",
        "default_headers": _headers("148", "X11; Ubuntu; Linux x86_64"),
    })
    registry.register({
        "name": "firefox_148_macos",
        "based_on": "firefox_148_base",
        "default_headers": _headers("148", "Macintosh; Intel Mac OS X 10.15"),
    })
    registry.register({
        "name": "firefox_148_android",
        "based_on": "firefox_148_base",
        "default_headers": _headers(
            "148", "Android 15; Mobile", mobile=True
        ),
    })

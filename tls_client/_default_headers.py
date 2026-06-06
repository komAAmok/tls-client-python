"""
Default real-world browser headers for every TLS client identifier.

When a Session is created with ``client_identifier="chrome_146"`` and no
``default_headers`` are provided, the session automatically picks up the
correct, version-aligned headers for that browser fingerprint.

Headers are grouped by browser family with helper factories to ensure
consistency across versions.  Every entry in ``ClientIdentifiers`` has a
corresponding key below.
"""

from typing import Dict

# ═══════════════════════════════════════════════════════════════════════════════
# Chrome helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _chrome_ua(version: str) -> str:
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        f" (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36"
    )


def _chrome_headers(version: str, *, zstd: bool = False) -> Dict[str, str]:
    """Standard Chrome desktop headers.  *zstd* is True for Chrome ≥117."""
    enc = "gzip, deflate, br, zstd" if zstd else "gzip, deflate, br"
    return {
        "User-Agent": _chrome_ua(version),
        "sec-ch-ua": (
            f'"Chromium";v="{version}", "Google Chrome";v="{version}",'
            f' "Not?A_Brand";v="99"'
        ),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Encoding": enc,
        "Accept-Language": "en-US,en;q=0.9",
    }


def _chrome_psk(version: str, *, zstd: bool = False) -> Dict[str, str]:
    """Chrome PSK variant — identical desktop headers."""
    return _chrome_headers(version, zstd=zstd)


# ═══════════════════════════════════════════════════════════════════════════════
# Brave  (Chromium fork — prominent "Brave" brand in sec-ch-ua)
# ═══════════════════════════════════════════════════════════════════════════════

def _brave_headers(version: str, *, zstd: bool = True) -> Dict[str, str]:
    enc = "gzip, deflate, br, zstd" if zstd else "gzip, deflate, br"
    return {
        "User-Agent": _chrome_ua(version),
        "sec-ch-ua": (
            f'"Chromium";v="{version}", "Brave";v="{version}",'
            f' "Not?A_Brand";v="99"'
        ),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Encoding": enc,
        "Accept-Language": "en-US,en;q=0.9",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Opera  (Chromium fork — "OPR" in UA, "Opera" in sec-ch-ua)
# ═══════════════════════════════════════════════════════════════════════════════

def _opera_headers(
    opera_ver: str, chromium_ver: str, *, zstd: bool = False
) -> Dict[str, str]:
    enc = "gzip, deflate, br, zstd" if zstd else "gzip, deflate, br"
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            f" (KHTML, like Gecko) Chrome/{chromium_ver}.0.0.0 Safari/537.36"
            f" OPR/{opera_ver}.0.0.0"
        ),
        "sec-ch-ua": (
            f'"Chromium";v="{chromium_ver}", "Opera";v="{opera_ver}",'
            f' "Not?A_Brand";v="99"'
        ),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Encoding": enc,
        "Accept-Language": "en-US,en;q=0.9",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Safari  (macOS)  —  NO Client Hints
# ═══════════════════════════════════════════════════════════════════════════════

def _safari_macos(version: str) -> Dict[str, str]:
    return {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
            f" AppleWebKit/605.1.15 (KHTML, like Gecko)"
            f" Version/{version} Safari/605.1.15"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Safari  (iOS)  —  NO Client Hints
# ═══════════════════════════════════════════════════════════════════════════════

def _safari_ios(ios_ver: str, safari_ver: str) -> Dict[str, str]:
    return {
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS"
            f" {ios_ver.replace('.', '_')} like Mac OS X)"
            f" AppleWebKit/605.1.15 (KHTML, like Gecko)"
            f" Version/{safari_ver} Mobile/15E148 Safari/604.1"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Safari  (iPad)  —  NO Client Hints
# ═══════════════════════════════════════════════════════════════════════════════

def _safari_ipad(ios_ver: str, safari_ver: str) -> Dict[str, str]:
    return {
        "User-Agent": (
            "Mozilla/5.0 (iPad; CPU OS"
            f" {ios_ver.replace('.', '_')} like Mac OS X)"
            f" AppleWebKit/605.1.15 (KHTML, like Gecko)"
            f" Version/{safari_ver} Mobile/15E148 Safari/604.1"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Firefox  (desktop)  —  NO Client Hints; Firefox-specific Accept header
# ═══════════════════════════════════════════════════════════════════════════════

def _firefox_headers(version: str) -> Dict[str, str]:
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:"
            f"{version}.0) Gecko/20100101 Firefox/{version}.0"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "*/*;q=0.8"
        ),
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.5",
    }


def _firefox_psk(version: str) -> Dict[str, str]:
    """Firefox PSK variant — same desktop headers."""
    return _firefox_headers(version)


# ═══════════════════════════════════════════════════════════════════════════════
# Native App — OkHttp (Android)  —  minimal, no browser features
# ═══════════════════════════════════════════════════════════════════════════════

def _okhttp_headers(version: str) -> Dict[str, str]:
    return {
        "User-Agent": f"okhttp/4.{version}.0",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Native App — iOS  (CFNetwork / Darwin)  —  minimal
# ═══════════════════════════════════════════════════════════════════════════════

def _ios_app_headers(app_name: str) -> Dict[str, str]:
    return {
        "User-Agent": (
            f"{app_name}/1.0 (iPhone; iOS 18.0; Scale/3.00)"
        ),
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Native App — Android (Dalvik)  —  minimal
# ═══════════════════════════════════════════════════════════════════════════════

def _android_app_headers(app_name: str) -> Dict[str, str]:
    return {
        "User-Agent": f"{app_name} (Linux; Android 14; en_US)",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Cloudscraper  —  generic Cloudflare-bypass headers
# ═══════════════════════════════════════════════════════════════════════════════

_CLOUDSCRAPER_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        " (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
}


# ═══════════════════════════════════════════════════════════════════════════════
# The complete mapping — every ClientIdentifiers literal → default headers
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_HEADERS: Dict[str, Dict[str, str]] = {
    # ── Chrome 103 – 112  (pre‑zstd) ──────────────────────────────────────
    "chrome_103": _chrome_headers("103"),
    "chrome_104": _chrome_headers("104"),
    "chrome_105": _chrome_headers("105"),
    "chrome_106": _chrome_headers("106"),
    "chrome_107": _chrome_headers("107"),
    "chrome_108": _chrome_headers("108"),
    "chrome_109": _chrome_headers("109"),
    "chrome_110": _chrome_headers("110"),
    "chrome_111": _chrome_headers("111"),
    "chrome_112": _chrome_headers("112"),
    # ── Chrome 116 (PSK / PSK_PQ)  ────────────────────────────────────────
    "chrome_116_PSK": _chrome_psk("116"),
    "chrome_116_PSK_PQ": _chrome_psk("116"),
    # ── Chrome 117+  (zstd in Accept-Encoding) ────────────────────────────
    "chrome_117": _chrome_headers("117", zstd=True),
    "chrome_120": _chrome_headers("120", zstd=True),
    "chrome_124": _chrome_headers("124", zstd=True),
    # ── Chrome 130+  ──────────────────────────────────────────────────────
    "chrome_130_PSK": _chrome_psk("130", zstd=True),
    # ── Chrome 131  ───────────────────────────────────────────────────────
    "chrome_131": _chrome_headers("131", zstd=True),
    "chrome_131_PSK": _chrome_psk("131", zstd=True),
    # ── Chrome 133  ───────────────────────────────────────────────────────
    "chrome_133": _chrome_headers("133", zstd=True),
    "chrome_133_PSK": _chrome_psk("133", zstd=True),
    # ── Chrome 144  ───────────────────────────────────────────────────────
    "chrome_144": _chrome_headers("144", zstd=True),
    "chrome_144_PSK": _chrome_psk("144", zstd=True),
    # ── Chrome 146  ───────────────────────────────────────────────────────
    "chrome_146": _chrome_headers("146", zstd=True),
    "chrome_146_PSK": _chrome_psk("146", zstd=True),
    # ── Brave 146  ────────────────────────────────────────────────────────
    "brave_146": _brave_headers("146"),
    "brave_146_PSK": _brave_headers("146"),
    # ── Safari macOS ──────────────────────────────────────────────────────
    "safari_15_6_1": _safari_macos("15.6.1"),
    "safari_16_0": _safari_macos("16.0"),
    # ── Safari iPad ───────────────────────────────────────────────────────
    "safari_ipad_15_6": _safari_ipad("15.6", "15.6"),
    # ── Safari iOS ────────────────────────────────────────────────────────
    "safari_ios_15_5": _safari_ios("15.5", "15.5"),
    "safari_ios_15_6": _safari_ios("15.6", "15.6"),
    "safari_ios_16_0": _safari_ios("16.0", "16.0"),
    "safari_ios_17_0": _safari_ios("17.0", "17.0"),
    "safari_ios_18_0": _safari_ios("18.0", "18.0"),
    "safari_ios_18_5": _safari_ios("18.5", "18.5"),
    "safari_ios_26_0": _safari_ios("26.0", "26.0"),
    # ── Firefox 102 – 110 ─────────────────────────────────────────────────
    "firefox_102": _firefox_headers("102"),
    "firefox_104": _firefox_headers("104"),
    "firefox_105": _firefox_headers("105"),
    "firefox_106": _firefox_headers("106"),
    "firefox_108": _firefox_headers("108"),
    "firefox_110": _firefox_headers("110"),
    # ── Firefox 117 – 123 ─────────────────────────────────────────────────
    "firefox_117": _firefox_headers("117"),
    "firefox_120": _firefox_headers("120"),
    "firefox_123": _firefox_headers("123"),
    # ── Firefox 132 – 135 ─────────────────────────────────────────────────
    "firefox_132": _firefox_headers("132"),
    "firefox_133": _firefox_headers("133"),
    "firefox_135": _firefox_headers("135"),
    # ── Firefox 146 – 148 ─────────────────────────────────────────────────
    "firefox_146_PSK": _firefox_psk("146"),
    "firefox_147": _firefox_headers("147"),
    "firefox_147_PSK": _firefox_psk("147"),
    "firefox_148": _firefox_headers("148"),
    # ── Opera  (Chromium‑based, Opera‑branded sec‑ch‑ua) ──────────────────
    "opera_89": _opera_headers("89", "103"),
    "opera_90": _opera_headers("90", "104"),
    "opera_91": _opera_headers("91", "105"),
    # ── Zalando  (native mobile apps) ─────────────────────────────────────
    "zalando_android_mobile": _android_app_headers("Zalando"),
    "zalando_ios_mobile": _ios_app_headers("Zalando"),
    # ── Nike  (native mobile apps) ────────────────────────────────────────
    "nike_android_mobile": _android_app_headers("Nike"),
    "nike_ios_mobile": _ios_app_headers("Nike"),
    # ── Cloudscraper ──────────────────────────────────────────────────────
    "cloudscraper": _CLOUDSCRAPER_HEADERS,
    # ── MMS  (native iOS apps) ────────────────────────────────────────────
    "mms_ios": _ios_app_headers("MMS"),
    "mms_ios_1": _ios_app_headers("MMS"),
    "mms_ios_2": _ios_app_headers("MMS"),
    "mms_ios_3": _ios_app_headers("MMS"),
    # ── Mesh  (native mobile apps) ────────────────────────────────────────
    "mesh_ios": _ios_app_headers("Mesh"),
    "mesh_ios_1": _ios_app_headers("Mesh"),
    "mesh_ios_2": _ios_app_headers("Mesh"),
    "mesh_android": _android_app_headers("Mesh"),
    "mesh_android_1": _android_app_headers("Mesh"),
    "mesh_android_2": _android_app_headers("Mesh"),
    # ── Confirmed  (native mobile apps) ───────────────────────────────────
    "confirmed_ios": _ios_app_headers("Confirmed"),
    "confirmed_android": _android_app_headers("Confirmed"),
    # ── OkHttp 4.x  (Android networking library) ──────────────────────────
    "okhttp4_android_7": _okhttp_headers("7"),
    "okhttp4_android_8": _okhttp_headers("8"),
    "okhttp4_android_9": _okhttp_headers("9"),
    "okhttp4_android_10": _okhttp_headers("10"),
    "okhttp4_android_11": _okhttp_headers("11"),
    "okhttp4_android_12": _okhttp_headers("12"),
    "okhttp4_android_13": _okhttp_headers("13"),
}

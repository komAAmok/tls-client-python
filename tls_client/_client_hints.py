"""High-entropy Client Hints for Chromium-family browsers.

Chrome emits these only after a host advertises ``Accept-CH`` (and the user
opts in), but impersonation libraries ship them so the header block is
complete and coherent when the target expects them.  Values mirror Chromium
(verified against httpcloak's captured header logic):

- ``sec-ch-ua-full-version-list`` — each brand's exact build for real brands,
  ``<major>.0.0.0`` for the GREASE brand;
- ``sec-ch-ua-platform-version`` / ``-arch`` / ``-bitness`` / ``-model`` /
  ``-wow64`` — per-platform defaults.

The exact builds come from live handshakes (``tools/_chrome_captures.json``).
"""

from typing import Dict

# Exact Chrome build per major, captured from live handshakes.
CHROME_FULL_VERSIONS: Dict[int, str] = {
    99: "99.0.4844.84",
    100: "100.0.4896.127",
    101: "101.0.4951.67",
    102: "102.0.5005.115",
    103: "103.0.5060.134",
    104: "104.0.5112.102",
    105: "105.0.5195.127",
    106: "106.0.5249.119",
    107: "107.0.5304.122",
    108: "108.0.5359.125",
    109: "109.0.5414.120",
    110: "110.0.5481.178",
    111: "111.0.5563.147",
    112: "112.0.5615.138",
    113: "113.0.5672.127",
    114: "114.0.5735.199",
    115: "115.0.5790.171",
    116: "116.0.5845.188",
    117: "117.0.5938.150",
    118: "118.0.5993.118",
    119: "119.0.6045.200",
    120: "120.0.6099.225",
    121: "121.0.6167.185",
    122: "122.0.6261.129",
    123: "123.0.6312.123",
    124: "124.0.6367.208",
    125: "125.0.6422.142",
    126: "126.0.6478.183",
    127: "127.0.6533.120",
    128: "128.0.6613.138",
    129: "129.0.6668.101",
    130: "130.0.6723.117",
    131: "131.0.6778.265",
    132: "132.0.6834.160",
    133: "133.0.6943.142",
    134: "134.0.6998.178",
    135: "135.0.7049.115",
    136: "136.0.7103.114",
    137: "137.0.7151.120",
    138: "138.0.7204.184",
    139: "139.0.7258.155",
    140: "140.0.7339.208",
    141: "141.0.7390.123",
    142: "142.0.7444.176",
    143: "143.0.7499.193",
    144: "144.0.7559.133",
    145: "145.0.7632.160",
    146: "146.0.7680.178",
    147: "147.0.7727.138",
    148: "148.0.7778.168",
    149: "149.0.7827.201",
    150: "150.0.7871.187",
    151: "151.0.7922.174",
    152: "152.0.7977.83",
    153: "153.0.8010.37",
}

# Brands that carry the real build; everything else is the GREASE token.
_REAL_BRANDS = {"Chromium", "Google Chrome", "Microsoft Edge", "Brave", "Opera"}

# Per-platform defaults, mirroring Chromium (httpcloak-verified).
PLATFORM_VERSION: Dict[str, str] = {
    "windows": '"15.0.0"',
    "macos": '"14.5.0"',
    "linux": '""',
    "android": '"14.0.0"',
    "ios": '""',
}

PLATFORM_ARCH: Dict[str, str] = {
    "windows": '"x86"',
    "macos": '"arm"',
    "linux": '"x86"',
    "android": '""',
    "ios": '""',
}


def full_version_for(major: int) -> str:
    """Return the exact Chrome build for *major*, or a ``<major>.0.0.0`` fallback."""
    return CHROME_FULL_VERSIONS.get(int(major), "%d.0.0.0" % int(major))


def full_version_list(sec_ch_ua: str, full_version: str) -> str:
    """Expand a low-entropy ``sec-ch-ua`` into ``sec-ch-ua-full-version-list``.

    Brand names, order and the GREASE token are preserved verbatim.  When
    *full_version* is given, real brands get the exact build while the GREASE
    brand keeps its major expanded to ``<major>.0.0.0``; when it is empty,
    every brand is expanded to ``<major>.0.0.0`` (the ``ua_full_version=None``
    fallback of ``context.expand_client_hints``).  Example::

        "Chromium";v="99", "Not?A_Brand";v="24", "Google Chrome";v="99"

    becomes (with ``full_version="99.0.4844.84"``)::

        "Chromium";v="99.0.4844.84", "Not?A_Brand";v="24.0.0.0",
        "Google Chrome";v="99.0.4844.84"
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
            out.append(part)  # empty or already a full version — leave as-is
        elif full_version and brand in _REAL_BRANDS:
            out.append('"%s";v="%s"' % (brand, full_version))
        else:
            out.append('"%s";v="%s.0.0.0"' % (brand, ver))
    return ", ".join(out)


def high_entropy_hints(platform: str, sec_ch_ua: str, full_version: str) -> Dict[str, str]:
    """Return the six high-entropy Client Hints for a Chromium platform."""
    platform = (platform or "").lower()
    is_mobile = platform in ("android", "ios")
    return {
        "sec-ch-ua-full-version-list": full_version_list(sec_ch_ua, full_version),
        "sec-ch-ua-platform-version": PLATFORM_VERSION.get(platform, '""'),
        "sec-ch-ua-arch": PLATFORM_ARCH.get(platform, '""'),
        "sec-ch-ua-bitness": '""' if is_mobile else '"64"',
        "sec-ch-ua-model": '""',
        "sec-ch-ua-wow64": "?0",
    }


# Wire order Chromium uses when it emits the high-entropy block, following the
# low-entropy trio.  Kept here so both the preset generator and the default
# headers use one canonical order.
HIGH_ENTROPY_ORDER = [
    "sec-ch-ua-platform-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-wow64",
]

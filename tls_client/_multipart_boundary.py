"""Browser-accurate multipart boundary generators.

Faithful ports of the boundary algorithms real browsers run, so multipart
bodies carry the same boundary shape a genuine browser would emit.  A
UUID-hex boundary (``multipart/form-data; boundary=<32 hex chars>``) is an
immediate automation tell on multipart endpoints.

- Chrome / Chromium: Blink ``FormDataEncoder::GenerateUniqueBoundaryString``
  (``----WebKitFormBoundary`` + 16 chars drawn from a 64-slot map where
  'A' and 'B' appear twice, making them twice as likely — verbatim from
  third_party/blink/renderer/platform/network/form_data_encoder.cc).
- Firefox: Gecko ``HTMLFormSubmission`` (27 dashes + three decimal
  ``uint32`` values, gecko-dev dom/html/HTMLFormSubmission.cpp).
"""

import secrets

_BLINK_PREFIX = "----WebKitFormBoundary"

# The alphanumeric encoding map from Blink.  0x41 ('A') and 0x42 ('B')
# appear twice on purpose — do not "deduplicate" this table.
_BLINK_ENCODING_MAP = (
    bytes(range(0x41, 0x5B))    # A-Z
    + bytes(range(0x61, 0x7B))  # a-z
    + bytes(range(0x30, 0x3A))  # 0-9
    + b"AB"                     # second occurrence of A/B
)

_GECKO_PREFIX = "---------------------------"


def blink_boundary() -> str:
    """Return a Chrome/Chromium style multipart boundary."""
    randomness = secrets.randbits(128)
    chars = [
        _BLINK_ENCODING_MAP[(randomness >> shift) & 0x3F]
        for shift in range(0, 96, 6)
    ]
    return _BLINK_PREFIX + "".join(chr(code) for code in chars)


def gecko_boundary() -> str:
    """Return a Firefox style multipart boundary."""
    parts = []
    for _ in range(3):
        parts.append(str(secrets.randbits(32)))
    return _GECKO_PREFIX + "".join(parts)


def boundary(browser: str = "chrome") -> str:
    """Return a browser-accurate boundary for *browser* ("chrome"/"firefox")."""
    if browser == "firefox":
        return gecko_boundary()
    return blink_boundary()

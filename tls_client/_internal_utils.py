"""Internal helpers shared by the Requests-compatible layer.

Mirrors requests._internal_utils.
"""

import re

builtin_str = str
bytes = bytes
str = str

_VALID_HEADER_NAME_RE_BYTE = re.compile(rb"^[^:\s][^:\r\n]*\Z")
_VALID_HEADER_NAME_RE_STR = re.compile(r"^[^:\s][^:\r\n]*\Z")
_VALID_HEADER_VALUE_RE_BYTE = re.compile(rb"^\S[^\r\n]*\Z|^\Z")
_VALID_HEADER_VALUE_RE_STR = re.compile(r"^\S[^\r\n]*\Z|^\Z")

_HEADER_VALIDATORS_STR = (_VALID_HEADER_NAME_RE_STR, _VALID_HEADER_VALUE_RE_STR)
_HEADER_VALIDATORS_BYTE = (_VALID_HEADER_NAME_RE_BYTE, _VALID_HEADER_VALUE_RE_BYTE)
HEADER_VALIDATORS = {
    bytes: _HEADER_VALIDATORS_BYTE,
    str: _HEADER_VALIDATORS_STR,
}


def to_native_string(string, encoding: str = "ascii") -> str:
    """Return a native (unicode) representation of *string*.

    Assumes ASCII unless told otherwise.
    """
    if isinstance(string, builtin_str):
        return string
    return string.decode(encoding)


def unicode_is_ascii(u_string: str) -> bool:
    """Determine if a unicode string only contains ASCII characters."""
    assert isinstance(u_string, str)
    try:
        u_string.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False

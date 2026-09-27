"""Type aliases used by the Requests-compatible layer.

Mirrors requests._types.  These names are internal: use them only when writing
annotations for code that must accept the same inputs requests does.
"""

from collections.abc import Callable, Mapping
from typing import Any, Protocol, TypeVar, runtime_checkable

_T_co = TypeVar("_T_co", covariant=True)
_KT_co = TypeVar("_KT_co", covariant=True)
_VT_co = TypeVar("_VT_co", covariant=True)


@runtime_checkable
class SupportsRead(Protocol[_T_co]):
    def read(self, length: int = ...) -> _T_co:
        ...


def has_read(obj: Any) -> bool:
    """Check if obj supports read, including __getattr__ based proxies."""
    return hasattr(obj, "read")


@runtime_checkable
class SupportsItems(Protocol[_KT_co, _VT_co]):
    def items(self): ...


# Needed at runtime for default_hooks() return type
HookType = Callable[..., Any]
HooksInputType = Mapping[str, Any]

UriType = Any
ParamsType = Any
KVDataType = Any
RawDataType = Any
StreamDataType = Any
EncodableDataType = Any
DataType = Any
BodyType = Any
HeadersType = Any
CookiesType = Any

__all__ = [
    "BodyType",
    "CookiesType",
    "DataType",
    "EncodableDataType",
    "HeadersType",
    "HookType",
    "HooksInputType",
    "KVDataType",
    "ParamsType",
    "RawDataType",
    "StreamDataType",
    "SupportsItems",
    "SupportsRead",
    "UriType",
    "has_read",
]

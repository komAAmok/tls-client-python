"""Type aliases used by the Requests-compatible layer.

Mirrors requests._types.  These names are internal: use them only when writing
annotations for code that must accept the same inputs requests does.

Import-safe from Python 3.6 through 3.14: PEP 544 (``Protocol``,
``runtime_checkable``) only reached ``typing`` in 3.8, so 3.6-3.7 take both from
``typing_extensions`` - a declared dependency on those versions, see the
``requires-python`` markers in pyproject.toml.  tls_client/__init__.py imports
every submodule eagerly, so an unguarded import here fails the whole package
rather than one feature.
"""

# Callable / Mapping come from typing, NOT collections.abc.  The aliases below
# are subscripted at import time (HookType = Callable[..., Any]), and
# collections.abc classes only gained __class_getitem__ in Python 3.9 (PEP 585).
# With the collections.abc versions, `import tls_client` raised
# "TypeError: 'ABCMeta' object is not subscriptable" on 3.6-3.8 - the very
# versions requires-python advertises.  typing.Callable has been subscriptable
# since 3.5.1, so it works on every supported interpreter.
from typing import Any, Callable, Mapping, TypeVar

try:  # Python >= 3.8
    from typing import Protocol, runtime_checkable
except ImportError:  # Python 3.6-3.7: typing.Protocol is new in 3.8
    from typing_extensions import Protocol, runtime_checkable

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

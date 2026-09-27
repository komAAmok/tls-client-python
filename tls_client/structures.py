"""Small Requests-compatible container types."""

from collections import OrderedDict
from collections.abc import MutableMapping
from typing import Any, Dict, Generic, Iterator, Optional, Tuple, TypeVar

_VT = TypeVar("_VT")
_D = TypeVar("_D")


class CaseInsensitiveDict(MutableMapping, Generic[_VT]):
    """A case-insensitive dict-like object.

    Implements all methods and operations of MutableMapping as well as
    dict's copy.  Also provides lower_items.

    All keys are expected to be strings.  The structure remembers the case of
    the last key to be set, and iter(instance), keys(), items(), iterkeys()
    and iteritems() will contain case-sensitive keys.  However, querying and
    contains testing is case insensitive::

        cid = CaseInsensitiveDict()
        cid['Accept'] = 'application/json'
        cid['aCCEPT'] == 'application/json'  # True
        list(cid) == ['Accept']  # True

    For example, headers['content-encoding'] will return the value of a
    'Content-Encoding' response header, regardless of how the header name was
    originally stored.
    """

    def __init__(self, data: Optional[Any] = None, **kwargs: Any) -> None:
        self._store: "OrderedDict[str, Tuple[str, Any]]" = OrderedDict()
        if data is None:
            data = {}
        self.update(data, **kwargs)

    def __setitem__(self, key: str, value: Any) -> None:
        # Use the lowercased key for lookups, but store the actual
        # key alongside the value.
        self._store[str(key).lower()] = (str(key), value)

    def __getitem__(self, key: str) -> Any:
        return self._store[str(key).lower()][1]

    def __delitem__(self, key: str) -> None:
        del self._store[str(key).lower()]

    def __iter__(self) -> Iterator[str]:
        return (casedkey for casedkey, mappedvalue in self._store.values())

    def __len__(self) -> int:
        return len(self._store)

    def lower_items(self) -> Iterator[Tuple[str, Any]]:
        """Like iteritems(), but with all lowercase keys."""
        return ((lowerkey, keyval[1]) for (lowerkey, keyval) in self._store.items())

    def __eq__(self, other: Any) -> Any:
        if isinstance(other, MutableMapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        # Compare insensitively
        return dict(self.lower_items()) == dict(other.lower_items())

    # Copy is required
    def copy(self) -> "CaseInsensitiveDict[_VT]":
        return CaseInsensitiveDict(self._store.values())

    def __repr__(self) -> str:
        return str(dict(self.items()))


class LookupDict(Dict[str, _VT]):
    """Dictionary lookup object."""

    def __init__(self, name: Any = None) -> None:
        self.name = name
        super().__init__()

    def __repr__(self) -> str:
        return "<lookup '%s'>" % (self.name,)

    def __getitem__(self, key: str) -> Optional[_VT]:  # type: ignore[override]
        # We allow fall-through here, so values default to None
        return self.__dict__.get(key, None)

    def get(self, key: str, default: Any = None) -> Any:
        return self.__dict__.get(key, default)

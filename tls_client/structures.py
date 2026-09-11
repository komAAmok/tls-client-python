"""Small Requests-compatible container types."""

from collections import OrderedDict
from collections.abc import MutableMapping


class CaseInsensitiveDict(MutableMapping):
    """Dictionary with case-insensitive string keys and preserved casing."""

    def __init__(self, data=None, **kwargs):
        self._store = OrderedDict()
        if data is not None or kwargs:
            self.update(data or {}, **kwargs)

    def __setitem__(self, key, value):
        self._store[str(key).lower()] = (str(key), value)

    def __getitem__(self, key):
        return self._store[str(key).lower()][1]

    def __delitem__(self, key):
        del self._store[str(key).lower()]

    def __iter__(self):
        return (item[0] for item in self._store.values())

    def __len__(self):
        return len(self._store)

    def lower_items(self):
        return ((key, value[1]) for key, value in self._store.items())

    def copy(self):
        return CaseInsensitiveDict(self.items())

    def __eq__(self, other):
        if isinstance(other, MutableMapping):
            other = CaseInsensitiveDict(other)
        else:
            return NotImplemented
        return dict(self.lower_items()) == dict(other.lower_items())

    def __repr__(self):
        return str(dict(self.items()))


class LookupDict(dict):
    def __init__(self, name=None):
        self.name = name
        super(LookupDict, self).__init__()

    def __getitem__(self, key):
        return self.__dict__.get(key)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)

    def __repr__(self):
        return "<lookup '%s'>" % self.name


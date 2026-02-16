"""
snekwest.structures
~~~~~~~~~~~~~~~~~~~

Data structures that power snekwest.
"""

import collections.abc

from ._bindings import CaseInsensitiveDict

# Register as MutableMapping so isinstance checks work
collections.abc.MutableMapping.register(CaseInsensitiveDict)


class LookupDict(dict):
    """Dictionary lookup object."""

    def __init__(self, name=None):
        self.name = name
        super().__init__()

    def __repr__(self):
        return f"<lookup '{self.name}'>"

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None

        return self.__dict__.get(key, None)

    def get(self, key, default=None):
        return self.__dict__.get(key, default)

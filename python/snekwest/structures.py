"""
snekwest.structures
~~~~~~~~~~~~~~~~~~~

Data structures that power snekwest.
"""

import collections.abc

from ._bindings import CaseInsensitiveDict, LookupDict  # noqa: F401

# Register as MutableMapping so isinstance checks work
collections.abc.MutableMapping.register(CaseInsensitiveDict)

"""
snekwest.compat
~~~~~~~~~~~~~~~

This module handles import compatibility, mirroring requests.compat.
"""

import importlib
import sys

# snekwest does not use urllib3, so set is_urllib3_1 = False
is_urllib3_1 = False

# -------------------
# Character Detection
# -------------------


def _resolve_char_detection():
    """Find supported character detection libraries."""
    chardet = None
    for lib in ("chardet", "charset_normalizer"):
        if chardet is None:
            try:
                chardet = importlib.import_module(lib)
            except ImportError:
                pass
    return chardet


chardet = _resolve_char_detection()

# -------
# Pythons
# -------

# Syntax sugar.
_ver = sys.version_info

#: Python 3.x?
is_py3 = _ver[0] == 3

# json/simplejson module import resolution
has_simplejson = False
try:
    import simplejson as json

    has_simplejson = True
except ImportError:
    import json  # noqa: F401

if has_simplejson:
    from simplejson import JSONDecodeError  # noqa: F401
else:
    from json import JSONDecodeError  # noqa: F401

# Keep OrderedDict for backwards compatibility.
from collections import OrderedDict  # noqa: E402, F401
from collections.abc import Callable, Mapping, MutableMapping  # noqa: E402, F401
from http import cookiejar as cookielib  # noqa: E402, F401
from http.cookies import Morsel  # noqa: E402, F401
from io import StringIO  # noqa: E402, F401

# --------------
# Legacy Imports
# --------------
from urllib.parse import (  # noqa: E402, F401
    quote,
    quote_plus,
    unquote,
    unquote_plus,
    urldefrag,
    urlencode,
    urljoin,
    urlparse,
    urlsplit,
    urlunparse,
)
from urllib.request import (  # noqa: E402, F401
    getproxies,
    getproxies_environment,
    parse_http_list,
    proxy_bypass,
    proxy_bypass_environment,
)

builtin_str = str
str = str  # noqa: A001 — re-export for conftest module swap compatibility
bytes = bytes  # noqa: A001 — re-export for conftest module swap compatibility
basestring = (str, bytes)
numeric_types = (int, float)
integer_types = (int,)

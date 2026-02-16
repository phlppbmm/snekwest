"""
snekwest._internal_utils
~~~~~~~~~~~~~~

Provides utility functions that are consumed internally by snekwest
which depend on extremely few external helpers (such as compat)
"""

import re


_VALID_HEADER_NAME_RE_BYTE = re.compile(rb"^[^:\s][^:\r\n]*$")
_VALID_HEADER_NAME_RE_STR = re.compile(r"^[^:\s][^:\r\n]*$")
_VALID_HEADER_VALUE_RE_BYTE = re.compile(rb"^\S[^\r\n]*$|^$")
_VALID_HEADER_VALUE_RE_STR = re.compile(r"^\S[^\r\n]*$|^$")

_HEADER_VALIDATORS_STR = (_VALID_HEADER_NAME_RE_STR, _VALID_HEADER_VALUE_RE_STR)
_HEADER_VALIDATORS_BYTE = (_VALID_HEADER_NAME_RE_BYTE, _VALID_HEADER_VALUE_RE_BYTE)
HEADER_VALIDATORS = {
    bytes: _HEADER_VALIDATORS_BYTE,
    str: _HEADER_VALIDATORS_STR,
}


# Re-export from Rust for backwards compatibility (conftest module swap needs this)
from ._bindings import unicode_is_ascii, to_native_string  # noqa: E402, F401

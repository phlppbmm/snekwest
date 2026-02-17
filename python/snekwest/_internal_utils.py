"""
snekwest._internal_utils
~~~~~~~~~~~~~~

Provides utility functions that are consumed internally by snekwest
which depend on extremely few external helpers (such as compat)
"""

# Header validation is fully handled in Rust (src/utils.rs check_header_validity).
# These symbols are kept as stubs for backward compat (conftest module swap).
_HEADER_VALIDATORS_STR = None
_HEADER_VALIDATORS_BYTE = None
HEADER_VALIDATORS = {bytes: None, str: None}


# Re-export from Rust for backwards compatibility (conftest module swap needs this)
from ._bindings import unicode_is_ascii, to_native_string  # noqa: E402, F401

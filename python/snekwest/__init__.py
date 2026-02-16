"""snekwest — a Rust-backed, requests-compatible HTTP client for Python."""

import logging
import warnings
from logging import NullHandler

from . import packages, utils  # noqa: F401
from .__version__ import (  # noqa: F401
    __author__,
    __author_email__,
    __build__,
    __cake__,
    __copyright__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
)
from .api import delete, get, head, options, patch, post, put, request  # noqa: F401
from .exceptions import (  # noqa: F401  # pylint: disable=redefined-builtin
    ConnectionError,
    ConnectTimeout,
    FileModeWarning,
    HTTPError,
    JSONDecodeError,
    ReadTimeout,
    RequestException,
    Timeout,
    TooManyRedirects,
    URLRequired,
)
from .models import PreparedRequest, Request, Response  # noqa: F401
from .sessions import Session, session  # noqa: F401
from .status_codes import codes  # noqa: F401

logging.getLogger(__name__).addHandler(NullHandler())

# FileModeWarnings go off per the default.
warnings.simplefilter("default", FileModeWarning, append=True)

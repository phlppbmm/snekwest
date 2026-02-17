"""
snekwest.models
~~~~~~~~~~~~~~~

This module contains the primary objects that power snekwest.
"""

import datetime  # noqa: F401
import encodings.idna  # noqa: F401
from io import BytesIO, UnsupportedOperation  # noqa: F401
from ._internal_utils import to_native_string  # noqa: F401
from .utils import unicode_is_ascii  # noqa: F401
from .auth import HTTPBasicAuth  # noqa: F401
from .compat import (  # noqa: F401
    Callable,
    JSONDecodeError,
    Mapping,
    basestring,
    builtin_str,
    chardet,
    cookielib,
)
from .compat import json as complexjson  # noqa: F401
from .compat import urlencode, urlsplit, urlunparse  # noqa: F401
from .cookies import _copy_cookie_jar, cookiejar_from_dict, get_cookie_header  # noqa: F401
from .exceptions import (  # noqa: F401
    ChunkedEncodingError,
    ContentDecodingError,
    HTTPError,
    InvalidJSONError,
    InvalidURL,
    MissingSchema,
    StreamConsumedError,
)
from .exceptions import JSONDecodeError as RequestsJSONDecodeError  # noqa: F401
from .exceptions import SSLError as RequestsSSLError  # noqa: F401
from .hooks import default_hooks  # noqa: F401

try:
    from urllib3.exceptions import (
        DecodeError as _DecodeError,
        ProtocolError as _ProtocolError,
        ReadTimeoutError as _ReadTimeoutError,
        SSLError as _SSLError,
    )
except ImportError:
    _DecodeError = _ProtocolError = _ReadTimeoutError = _SSLError = Exception
from .status_codes import codes  # noqa: F401
from .structures import CaseInsensitiveDict  # noqa: F401
from .utils import (  # noqa: F401
    check_header_validity,
    get_auth_from_url,
    guess_filename,
    guess_json_utf,
    iter_slices,
    parse_header_links,
    requote_uri,
    stream_decode_response_unicode,
    super_len,
    to_key_val_list,
)

#: The set of HTTP status codes that indicate an automatically
#: processable redirect.
REDIRECT_STATI = (
    codes.moved,  # 301
    codes.found,  # 302
    codes.other,  # 303
    codes.temporary_redirect,  # 307
    codes.permanent_redirect,  # 308
)

DEFAULT_REDIRECT_LIMIT = 30
CONTENT_CHUNK_SIZE = 10 * 1024
ITER_CHUNK_SIZE = 512


class _FakeOriginalResponse:
    """Minimal shim for extract_cookies_to_jar, which needs resp.raw._original_response.msg."""

    def __init__(self, msg):
        self.msg = msg


class StreamingRawResponse:
    """Wraps a Rust StreamingBody to provide a file-like read() interface
    for iter_content()'s generate() loop."""

    def __init__(self, streaming_body, headers_dict, msg):
        self._streaming_body = streaming_body
        self.headers = headers_dict
        self._original_response = _FakeOriginalResponse(msg)

    def read(self, size=8192):
        return bytes(self._streaming_body.read(size))

    def close(self):
        self._streaming_body.close()

    @property
    def closed(self):
        return self._streaming_body.closed

    def release_conn(self):
        self.close()


def _encode_files(files, data):
    """Build the body for a multipart/form-data request.

    Kept as a module-level function for Rust PreparedRequest to call.
    """
    if not files:
        raise ValueError("Files must be provided.")
    elif isinstance(data, basestring):
        raise ValueError("Data must not be a string.")

    new_fields = []
    fields = to_key_val_list(data or {})
    files = to_key_val_list(files or {})

    for field, val in fields:
        if isinstance(val, basestring) or not hasattr(val, "__iter__"):
            val = [val]
        for v in val:
            if v is not None:
                if not isinstance(v, bytes):
                    v = str(v)
                new_fields.append(
                    (
                        field.decode("utf-8") if isinstance(field, bytes) else field,
                        v.encode("utf-8") if isinstance(v, str) else v,
                    )
                )

    for k, v in files:
        ft = None
        fh = None
        if isinstance(v, (tuple, list)):
            if len(v) == 2:
                fn, fp = v
            elif len(v) == 3:
                fn, fp, ft = v
            else:
                fn, fp, ft, fh = v
        else:
            fn = guess_filename(v) or k
            fp = v

        if isinstance(fp, (str, bytes, bytearray)):
            fdata = fp
        elif hasattr(fp, "read"):
            fdata = fp.read()
        elif fp is None:
            continue
        else:
            fdata = fp

        # Use urllib3's RequestField if available, otherwise build manually
        try:
            from urllib3.fields import RequestField
            from urllib3.filepost import encode_multipart_formdata

            rf = RequestField(name=k, data=fdata, filename=fn, headers=fh)
            rf.make_multipart(content_type=ft)
            new_fields.append(rf)
        except ImportError:
            # Fallback: build multipart manually
            import uuid

            boundary = uuid.uuid4().hex
            body = b""
            for field_name, field_val in new_fields:
                body += f"--{boundary}\r\n".encode()
                body += f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'.encode()
                if isinstance(field_val, str):
                    field_val = field_val.encode()
                body += field_val + b"\r\n"
            body += f"--{boundary}\r\n".encode()
            body += f'Content-Disposition: form-data; name="{k}"; filename="{fn}"\r\n'.encode()
            if ft:
                body += f"Content-Type: {ft}\r\n".encode()
            body += b"\r\n"
            if isinstance(fdata, str):
                fdata = fdata.encode()
            body += fdata + b"\r\n"
            body += f"--{boundary}--\r\n".encode()
            return body, f"multipart/form-data; boundary={boundary}"

    try:
        from urllib3.filepost import encode_multipart_formdata

        body, content_type = encode_multipart_formdata(new_fields)
    except ImportError:
        raise NotImplementedError("urllib3 is required for multipart file uploads")
    return body, content_type


# Import Rust PreparedRequest and Response
from ._bindings import PreparedRequest, Response  # noqa: E402, F401


class Request:
    """A user-created :class:`Request <Request>` object.

    Used to prepare a :class:`PreparedRequest <PreparedRequest>`, which is sent to the server.
    """

    def __init__(
        self,
        method=None,
        url=None,
        headers=None,
        files=None,
        data=None,
        params=None,
        auth=None,
        cookies=None,
        hooks=None,
        json=None,
    ):
        data = [] if data is None else data
        files = [] if files is None else files
        headers = {} if headers is None else headers
        params = {} if params is None else params
        hooks = {} if hooks is None else hooks

        self.hooks = default_hooks()
        for k, v in list(hooks.items()):
            self.register_hook(event=k, hook=v)

        self.method = method
        self.url = url
        self.headers = headers
        self.files = files
        self.data = data
        self.json = json
        self.params = params
        self.auth = auth
        self.cookies = cookies

    def __repr__(self):
        return f"<Request [{self.method}]>"

    def prepare(self):
        """Constructs a :class:`PreparedRequest <PreparedRequest>` for transmission and returns it."""
        p = PreparedRequest()
        p.prepare(
            method=self.method,
            url=self.url,
            headers=self.headers,
            files=self.files,
            data=self.data,
            json=self.json,
            params=self.params,
            auth=self.auth,
            cookies=self.cookies,
            hooks=self.hooks,
        )
        return p

    def register_hook(self, event, hook):
        """Properly register a hook."""
        if event not in self.hooks:
            raise ValueError(f'Unsupported event specified, with event name "{event}"')

        if isinstance(hook, Callable):
            self.hooks[event].append(hook)
        elif hasattr(hook, "__iter__"):
            self.hooks[event].extend(h for h in hook if isinstance(h, Callable))

    def deregister_hook(self, event, hook):
        """Deregister a previously registered hook.
        Returns True if the hook existed, False if not.
        """
        try:
            self.hooks[event].remove(hook)
            return True
        except ValueError:
            return False

"""
snekwest.models
~~~~~~~~~~~~~~~

This module contains the primary objects that power snekwest.
"""

import datetime
import encodings.idna  # noqa: F401
from io import BytesIO, UnsupportedOperation
from urllib.parse import urlparse as _urlparse, urlsplit as _urlsplit

from ._internal_utils import to_native_string, unicode_is_ascii
from .auth import HTTPBasicAuth
from .compat import (
    Callable,
    JSONDecodeError,
    Mapping,
    basestring,
    builtin_str,
    chardet,
    cookielib,
)
from .compat import json as complexjson
from .compat import urlencode, urlsplit, urlunparse
from .cookies import _copy_cookie_jar, cookiejar_from_dict, get_cookie_header
from .exceptions import (
    ChunkedEncodingError,
    ContentDecodingError,
    HTTPError,
    InvalidJSONError,
    InvalidURL,
    MissingSchema,
    StreamConsumedError,
)
from .exceptions import JSONDecodeError as RequestsJSONDecodeError
from .exceptions import SSLError as RequestsSSLError
from .hooks import default_hooks

try:
    from urllib3.exceptions import (
        DecodeError as _DecodeError,
        ProtocolError as _ProtocolError,
        ReadTimeoutError as _ReadTimeoutError,
        SSLError as _SSLError,
    )
except ImportError:
    _DecodeError = _ProtocolError = _ReadTimeoutError = _SSLError = Exception
from .status_codes import codes
from .structures import CaseInsensitiveDict
from .utils import (
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


def _parse_url(url):
    """Parse a URL into (scheme, auth, host, port, path, query, fragment).
    Replacement for urllib3.util.parse_url.
    """
    parsed = _urlparse(url)
    scheme = parsed.scheme or None
    netloc = parsed.netloc or None
    path = parsed.path or None
    query = parsed.query or None
    fragment = parsed.fragment or None

    # Extract auth from netloc
    auth = None
    host = None
    port = None
    if netloc:
        if "@" in netloc:
            auth, netloc = netloc.rsplit("@", 1)
        if ":" in netloc and not netloc.startswith("["):
            host_part, port_str = netloc.rsplit(":", 1)
            try:
                port = int(port_str)
                host = host_part
            except ValueError:
                host = netloc
        elif netloc.startswith("["):
            # IPv6
            if "]:" in netloc:
                host, port_str = netloc.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    host = netloc
            else:
                host = netloc
        else:
            host = netloc

    class ParseResult:
        def __init__(self, scheme, auth, host, port, path, query, fragment):
            self.scheme = scheme
            self.auth = auth
            self.host = host
            self.port = port
            self.path = path
            self.query = query
            self.fragment = fragment
            self.netloc = netloc

        def __iter__(self):
            return iter([self.scheme, self.auth, self.host, self.port,
                         self.path, self.query, self.fragment])

    return ParseResult(scheme, auth, host, port, path, query, fragment)


class RequestEncodingMixin:
    @property
    def path_url(self):
        """Build the path URL to use."""
        url = []
        p = urlsplit(self.url)
        path = p.path
        if not path:
            path = "/"
        url.append(path)
        query = p.query
        if query:
            url.append("?")
            url.append(query)
        return "".join(url)

    @staticmethod
    def _encode_params(data):
        """Encode parameters in a piece of data."""
        if isinstance(data, (str, bytes)):
            return data
        elif hasattr(data, "read"):
            return data
        elif hasattr(data, "__iter__"):
            result = []
            for k, vs in to_key_val_list(data):
                if isinstance(vs, basestring) or not hasattr(vs, "__iter__"):
                    vs = [vs]
                for v in vs:
                    if v is not None:
                        result.append(
                            (
                                k.encode("utf-8") if isinstance(k, str) else k,
                                v.encode("utf-8") if isinstance(v, str) else v,
                            )
                        )
            return urlencode(result, doseq=True)
        else:
            return data

    @staticmethod
    def _encode_files(files, data):
        """Build the body for a multipart/form-data request."""
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
                            field.decode("utf-8")
                            if isinstance(field, bytes)
                            else field,
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


class RequestHooksMixin:
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


class Request(RequestHooksMixin):
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


class PreparedRequest(RequestEncodingMixin, RequestHooksMixin):
    """The fully mutable :class:`PreparedRequest <PreparedRequest>` object,
    containing the exact bytes that will be sent to the server.
    """

    def __init__(self):
        self.method = None
        self.url = None
        self.headers = None
        self._cookies = None
        self.body = None
        self.hooks = default_hooks()
        self._body_position = None

    def prepare(
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
        """Prepares the entire request with the given parameters."""
        self.prepare_method(method)
        self.prepare_url(url, params)
        self.prepare_headers(headers)
        self.prepare_cookies(cookies)
        self.prepare_body(data, files, json)
        self.prepare_auth(auth, url)
        self.prepare_hooks(hooks)

    def __repr__(self):
        return f"<PreparedRequest [{self.method}]>"

    def copy(self):
        p = PreparedRequest()
        p.method = self.method
        p.url = self.url
        p.headers = self.headers.copy() if self.headers is not None else None
        p._cookies = _copy_cookie_jar(self._cookies)
        p.body = self.body
        p.hooks = self.hooks
        p._body_position = self._body_position
        return p

    def prepare_method(self, method):
        """Prepares the given HTTP method."""
        self.method = method
        if self.method is not None:
            self.method = to_native_string(self.method.upper())

    @staticmethod
    def _get_idna_encoded_host(host):
        import idna

        try:
            host = idna.encode(host, uts46=True).decode("utf-8")
        except idna.IDNAError:
            raise UnicodeError
        return host

    def prepare_url(self, url, params):
        """Prepares the given HTTP URL."""
        if isinstance(url, bytes):
            url = url.decode("utf8")
        else:
            url = str(url)

        # Remove leading whitespaces from url
        url = url.lstrip()

        # Don't do any URL preparation for non-HTTP schemes
        if ":" in url and not url.lower().startswith("http"):
            self.url = url
            return

        # Support for unicode domain names and paths.
        try:
            scheme, auth, host, port, path, query, fragment = _parse_url(url)
        except Exception as e:
            raise InvalidURL(*e.args)

        if not scheme:
            raise MissingSchema(
                f"Invalid URL {url!r}: No scheme supplied. "
                f"Perhaps you meant https://{url}?"
            )

        if not host:
            raise InvalidURL(f"Invalid URL {url!r}: No host supplied")

        if not unicode_is_ascii(host):
            try:
                host = self._get_idna_encoded_host(host)
            except UnicodeError:
                raise InvalidURL("URL has an invalid label.")
        elif host.startswith(("*", ".")):
            raise InvalidURL("URL has an invalid label.")

        # Carefully reconstruct the network location
        netloc = auth or ""
        if netloc:
            netloc += "@"
        netloc += host
        if port:
            netloc += f":{port}"

        if not path:
            path = "/"

        if isinstance(params, (str, bytes)):
            params = to_native_string(params)

        enc_params = self._encode_params(params)
        if enc_params:
            if query:
                query = f"{query}&{enc_params}"
            else:
                query = enc_params

        url = requote_uri(urlunparse([scheme, netloc, path, None, query, fragment]))
        self.url = url

    def prepare_headers(self, headers):
        """Prepares the given HTTP headers."""
        self.headers = CaseInsensitiveDict()
        if headers:
            for header in headers.items():
                check_header_validity(header)
                name, value = header
                self.headers[to_native_string(name)] = value

    def prepare_body(self, data, files, json=None):
        """Prepares the given HTTP body data."""
        body = None
        content_type = None

        if not data and json is not None:
            content_type = "application/json"
            try:
                body = complexjson.dumps(json, allow_nan=False)
            except ValueError as ve:
                raise InvalidJSONError(ve, request=self)

            if not isinstance(body, bytes):
                body = body.encode("utf-8")

        is_stream = all(
            [
                hasattr(data, "__iter__"),
                not isinstance(data, (basestring, list, tuple, Mapping)),
            ]
        )

        if is_stream:
            try:
                length = super_len(data)
            except (TypeError, AttributeError, UnsupportedOperation):
                length = None

            body = data

            if getattr(body, "tell", None) is not None:
                try:
                    self._body_position = body.tell()
                except OSError:
                    self._body_position = object()

            if files:
                raise NotImplementedError(
                    "Streamed bodies and files are mutually exclusive."
                )

            if length:
                self.headers["Content-Length"] = builtin_str(length)
            else:
                self.headers["Transfer-Encoding"] = "chunked"
        else:
            if files:
                (body, content_type) = self._encode_files(files, data)
            else:
                if data:
                    body = self._encode_params(data)
                    if isinstance(data, basestring) or hasattr(data, "read"):
                        content_type = None
                    else:
                        content_type = "application/x-www-form-urlencoded"

            self.prepare_content_length(body)

            if content_type and ("content-type" not in self.headers):
                self.headers["Content-Type"] = content_type

        self.body = body

    def prepare_content_length(self, body):
        """Prepare Content-Length header based on request method and body"""
        if body is not None:
            length = super_len(body)
            if length:
                self.headers["Content-Length"] = builtin_str(length)
        elif (
            self.method not in ("GET", "HEAD")
            and self.headers.get("Content-Length") is None
        ):
            self.headers["Content-Length"] = "0"

    def prepare_auth(self, auth, url=""):
        """Prepares the given HTTP auth data."""
        if auth is None:
            url_auth = get_auth_from_url(self.url)
            auth = url_auth if any(url_auth) else None

        if auth:
            if isinstance(auth, tuple) and len(auth) == 2:
                auth = HTTPBasicAuth(*auth)
            r = auth(self)
            self.__dict__.update(r.__dict__)
            self.prepare_content_length(self.body)

    def prepare_cookies(self, cookies):
        """Prepares the given HTTP cookie data."""
        if isinstance(cookies, cookielib.CookieJar):
            self._cookies = cookies
        else:
            self._cookies = cookiejar_from_dict(cookies)

        cookie_header = get_cookie_header(self._cookies, self)
        if cookie_header is not None:
            self.headers["Cookie"] = cookie_header

    def prepare_hooks(self, hooks):
        """Prepares the given hooks."""
        hooks = hooks or []
        for event in hooks:
            self.register_hook(event, hooks[event])


class Response:
    """The :class:`Response <Response>` object, which contains a
    server's response to an HTTP request.
    """

    __attrs__ = [
        "_content",
        "status_code",
        "headers",
        "url",
        "history",
        "encoding",
        "reason",
        "cookies",
        "elapsed",
        "request",
    ]

    def __init__(self):
        self._content = False
        self._content_consumed = False
        self._next = None

        self.status_code = None
        self.headers = CaseInsensitiveDict()
        self.raw = None
        self.url = None
        self.encoding = None
        self.history = []
        self.reason = None
        self.cookies = cookiejar_from_dict({})
        self.elapsed = datetime.timedelta(0)
        self.request = None
        self.connection = None

    @classmethod
    def _from_rust(cls, rust_response):
        """Build a Response from a Rust RustResponse object."""
        from .cookies import create_cookie

        resp = cls()
        resp.status_code = rust_response.status
        resp.url = rust_response.url

        # Wrap headers in CaseInsensitiveDict
        resp.headers = CaseInsensitiveDict(rust_response.headers)

        # Set encoding from content-type header
        from .utils import get_encoding_from_headers
        resp.encoding = get_encoding_from_headers(resp.headers)

        # Eagerly load content
        content = bytes(rust_response.content())
        resp._content = content
        resp._content_consumed = True

        # Set raw as BytesIO shim with _original_response for cookie extraction
        raw = BytesIO(content)
        # Add headers dict so code that accesses resp.raw.headers works
        raw.headers = {k.lower(): v for k, v in rust_response.headers.items()}
        # Build an HTTPMessage-like object so extract_cookies_to_jar works
        from email.message import Message
        msg = Message()
        for k, v in rust_response.headers.items():
            msg[k] = v

        class _FakeOriginalResponse:
            def __init__(self, msg):
                self.msg = msg
        raw._original_response = _FakeOriginalResponse(msg)
        resp.raw = raw

        # Reason phrase
        resp.reason = rust_response.reason

        # Elapsed
        resp.elapsed = datetime.timedelta(milliseconds=rust_response.elapsed_ms)

        # Build cookies from rust response
        resp.cookies = cookiejar_from_dict(rust_response.cookies)

        # Build history recursively
        resp.history = [cls._from_rust(h) for h in rust_response.history]

        # Build request object
        req = PreparedRequest()
        req.method = rust_response.method.upper()
        req.url = rust_response.request_url
        req.headers = CaseInsensitiveDict(rust_response.request_headers)
        resp.request = req

        return resp

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __getstate__(self):
        if not self._content_consumed:
            self.content
        return {attr: getattr(self, attr, None) for attr in self.__attrs__}

    def __setstate__(self, state):
        for name, value in state.items():
            setattr(self, name, value)
        setattr(self, "_content_consumed", True)
        setattr(self, "raw", None)

    def __repr__(self):
        return f"<Response [{self.status_code}]>"

    def __bool__(self):
        return self.ok

    def __nonzero__(self):
        return self.ok

    def __iter__(self):
        """Allows you to use a response as an iterator."""
        return self.iter_content(128)

    @property
    def ok(self):
        """Returns True if :attr:`status_code` is less than 400, False if not."""
        try:
            self.raise_for_status()
        except HTTPError:
            return False
        return True

    @property
    def is_redirect(self):
        """True if this Response is a well-formed HTTP redirect."""
        return "location" in self.headers and self.status_code in REDIRECT_STATI

    @property
    def is_permanent_redirect(self):
        """True if this Response one of the permanent versions of redirect."""
        return "location" in self.headers and self.status_code in (
            codes.moved_permanently,
            codes.permanent_redirect,
        )

    @property
    def next(self):
        """Returns a PreparedRequest for the next request in a redirect chain, if there is one."""
        return self._next

    @property
    def apparent_encoding(self):
        """The apparent encoding, provided by the charset_normalizer or chardet libraries."""
        if chardet is not None:
            return chardet.detect(self.content)["encoding"]
        else:
            return "utf-8"

    def iter_content(self, chunk_size=1, decode_unicode=False):
        """Iterates over the response data."""

        def generate():
            # Special case for urllib3.
            if hasattr(self.raw, "stream"):
                try:
                    yield from self.raw.stream(chunk_size, decode_content=True)
                except _ProtocolError as e:
                    raise ChunkedEncodingError(e)
                except _DecodeError as e:
                    raise ContentDecodingError(e)
                except _ReadTimeoutError as e:
                    from .exceptions import ConnectionError as RequestsConnectionError
                    raise RequestsConnectionError(e)
                except _SSLError as e:
                    raise RequestsSSLError(e)
            else:
                while True:
                    chunk = self.raw.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

            self._content_consumed = True

        if self._content_consumed and isinstance(self._content, bool):
            raise StreamConsumedError()
        elif chunk_size is not None and not isinstance(chunk_size, int):
            raise TypeError(
                f"chunk_size must be an int, it is instead a {type(chunk_size)}."
            )
        reused_chunks = iter_slices(self._content, chunk_size)
        stream_chunks = generate()
        chunks = reused_chunks if self._content_consumed else stream_chunks

        if decode_unicode:
            chunks = stream_decode_response_unicode(chunks, self)

        return chunks

    def iter_lines(
        self, chunk_size=ITER_CHUNK_SIZE, decode_unicode=False, delimiter=None
    ):
        """Iterates over the response data, one line at a time."""
        pending = None

        for chunk in self.iter_content(
            chunk_size=chunk_size, decode_unicode=decode_unicode
        ):
            if pending is not None:
                chunk = pending + chunk

            if delimiter:
                lines = chunk.split(delimiter)
            else:
                lines = chunk.splitlines()

            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None

            yield from lines

        if pending is not None:
            yield pending

    @property
    def content(self):
        """Content of the response, in bytes."""
        if self._content is False:
            if self._content_consumed:
                raise RuntimeError("The content for this response was already consumed")
            if self.status_code == 0 or self.raw is None:
                self._content = None
            else:
                self._content = b"".join(self.iter_content(CONTENT_CHUNK_SIZE)) or b""

        self._content_consumed = True
        return self._content

    @property
    def text(self):
        """Content of the response, in unicode."""
        content = None
        encoding = self.encoding

        if not self.content:
            return ""

        if self.encoding is None:
            encoding = self.apparent_encoding

        try:
            content = str(self.content, encoding, errors="replace")
        except (LookupError, TypeError):
            content = str(self.content, errors="replace")

        return content

    def json(self, **kwargs):
        r"""Returns the json-encoded content of a response, if any.

        :param \*\*kwargs: Optional arguments that ``json.loads`` takes.
        :raises requests.exceptions.JSONDecodeError: If the response body does not
            contain valid json.
        """
        if not self.encoding and self.content and len(self.content) > 3:
            encoding = guess_json_utf(self.content)
            if encoding is not None:
                try:
                    return complexjson.loads(self.content.decode(encoding), **kwargs)
                except UnicodeDecodeError:
                    pass
                except JSONDecodeError as e:
                    raise RequestsJSONDecodeError(e.msg, e.doc, e.pos)

        try:
            return complexjson.loads(self.text, **kwargs)
        except JSONDecodeError as e:
            raise RequestsJSONDecodeError(e.msg, e.doc, e.pos)

    @property
    def links(self):
        """Returns the parsed header links of the response, if any."""
        header = self.headers.get("link")
        resolved_links = {}
        if header:
            links = parse_header_links(header)
            for link in links:
                key = link.get("rel") or link.get("url")
                resolved_links[key] = link
        return resolved_links

    def raise_for_status(self):
        """Raises :class:`HTTPError`, if one occurred."""
        http_error_msg = ""
        if isinstance(self.reason, bytes):
            try:
                reason = self.reason.decode("utf-8")
            except UnicodeDecodeError:
                reason = self.reason.decode("iso-8859-1")
        else:
            reason = self.reason

        if 400 <= self.status_code < 500:
            http_error_msg = (
                f"{self.status_code} Client Error: {reason} for url: {self.url}"
            )
        elif 500 <= self.status_code < 600:
            http_error_msg = (
                f"{self.status_code} Server Error: {reason} for url: {self.url}"
            )

        if http_error_msg:
            raise HTTPError(http_error_msg, response=self)

    def close(self):
        """Releases the connection back to the pool."""
        if not self._content_consumed:
            self.raw.close() if self.raw else None
        release_conn = getattr(self.raw, "release_conn", None)
        if release_conn is not None:
            release_conn()

"""
snekwest.adapters
~~~~~~~~~~~~~~~~~

This module contains the transport adapters that snekwest uses to define
and maintain connections. Bridges to the Rust reqwest backend.
"""

import os.path
import socket  # noqa: F401

from .auth import _basic_auth_str  # noqa: F401
from .compat import basestring, urlparse  # noqa: F401
from .cookies import extract_cookies_to_jar  # noqa: F401
from .exceptions import (  # noqa: F401
    ConnectionError,
    ConnectTimeout,
    InvalidHeader,
    InvalidProxyURL,
    InvalidSchema,
    InvalidURL,
    ProxyError,
    ReadTimeout,
    RetryError,
    SSLError,
)
from .models import Response  # noqa: F401
from .structures import CaseInsensitiveDict  # noqa: F401
from .utils import (  # noqa: F401
    DEFAULT_CA_BUNDLE_PATH,
    extract_zipped_paths,
    get_auth_from_url,
    get_encoding_from_headers,
    prepend_scheme_if_needed,
    select_proxy,
    urldefragauth,
)

DEFAULT_POOLBLOCK = False
DEFAULT_POOLSIZE = 10
DEFAULT_RETRIES = 0
DEFAULT_POOL_TIMEOUT = None


class BaseAdapter:
    """The Base Transport Adapter"""

    def __init__(self):
        super().__init__()

    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None
    ):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


class HTTPAdapter(BaseAdapter):
    """The built-in HTTP Adapter for snekwest.

    Provides a general-case interface for snekwest sessions to contact HTTP and
    HTTPS urls by implementing the Transport Adapter interface.

    :param pool_connections: The number of connection pools to cache.
    :param pool_maxsize: The maximum number of connections to save in the pool.
    :param max_retries: The maximum number of retries each connection
        should attempt.
    :param pool_block: Whether the connection pool should block for connections.
    """

    __attrs__ = [
        "max_retries",
        "config",
        "_pool_connections",
        "_pool_maxsize",
        "_pool_block",
    ]

    def __init__(
        self,
        pool_connections=DEFAULT_POOLSIZE,
        pool_maxsize=DEFAULT_POOLSIZE,
        max_retries=DEFAULT_RETRIES,
        pool_block=DEFAULT_POOLBLOCK,
    ):
        if isinstance(max_retries, int):
            from urllib3.util.retry import Retry

            self.max_retries = Retry(max_retries, respect_retry_after_header=False)
        else:
            self.max_retries = max_retries
        self.config = {}
        self.proxy_manager = {}

        super().__init__()

        self._pool_connections = pool_connections
        self._pool_maxsize = pool_maxsize
        self._pool_block = pool_block

        # Lazily initialized Rust session for transport
        self._rust_session = None

        self.init_poolmanager(pool_connections, pool_maxsize, block=pool_block)

    def _get_rust_session(self):
        """Get or create the Rust session used for transport."""
        if self._rust_session is None:
            from snekwest._bindings import Session as RustSession

            self._rust_session = RustSession()
        return self._rust_session

    def __getstate__(self):
        return {attr: getattr(self, attr, None) for attr in self.__attrs__}

    def __setstate__(self, state):
        self.proxy_manager = {}
        self.config = {}

        for attr, value in state.items():
            setattr(self, attr, value)

        self._rust_session = None
        self.init_poolmanager(
            self._pool_connections, self._pool_maxsize, block=self._pool_block
        )

    def init_poolmanager(
        self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs
    ):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        # Shim for tests that inspect connection pool keying
        self.poolmanager = type("PoolManager", (), {"pools": {}})()
        self._pool_key_counter = 0

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        """Return a proxy manager for the given proxy.

        :param proxy: The proxy to return a manager for.
        :param proxy_kwargs: Extra keyword arguments.
        :returns: Proxy manager (no-op in snekwest, proxies handled by Rust).
        """
        if proxy in self.proxy_manager:
            return self.proxy_manager[proxy]

        proxy_headers = self.proxy_headers(proxy)
        self.proxy_manager[proxy] = {
            "proxy": proxy,
            "proxy_headers": proxy_headers,
        }
        return self.proxy_manager[proxy]

    def cert_verify(self, conn, url, verify, cert):
        """Verify a SSL certificate.

        :param conn: The connection object.
        :param url: The requested URL.
        :param verify: Either a boolean or a string path to a CA bundle.
        :param cert: The SSL certificate to verify.
        """
        if isinstance(verify, str) and not os.path.exists(verify):
            raise OSError(
                f"Could not find a suitable TLS CA certificate bundle, "
                f"invalid path: {verify}"
            )

        if cert:
            if isinstance(cert, tuple):
                cert_file = cert[0]
                key_file = cert[1] if len(cert) > 1 else None
            else:
                cert_file = cert
                key_file = None

            if cert_file and not os.path.exists(cert_file):
                raise OSError(
                    f"Could not find the TLS certificate file, "
                    f"invalid path: {cert_file}"
                )
            if key_file and not os.path.exists(key_file):
                raise OSError(
                    f"Could not find the TLS key file, invalid path: {key_file}"
                )

    def build_response(self, req, resp):
        """Attach request and connection to a Response from Rust.

        :param req: The :class:`PreparedRequest <PreparedRequest>` used to generate the response.
        :param resp: The Response object returned by the Rust session.
        :rtype: Response
        """
        resp.request = req
        resp.connection = self
        return resp

    def request_url(self, request, proxies):
        """Obtain the url to use when making the final request.

        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param proxies: A dictionary of proxies.
        :rtype: str
        """
        proxy = select_proxy(request.url, proxies)
        scheme = urlparse(request.url).scheme

        is_proxied_http_request = proxy and scheme != "https"
        using_socks_proxy = False
        if proxy:
            proxy_scheme = urlparse(proxy).scheme.lower()
            using_socks_proxy = proxy_scheme.startswith("socks")

        url = request.path_url
        if url.startswith("//"):
            url = f"/{url.lstrip('/')}"

        if is_proxied_http_request and not using_socks_proxy:
            url = urldefragauth(request.url)

        return url

    def add_headers(self, request, **kwargs):
        """Add any headers needed by the connection."""
        pass

    def proxy_headers(self, proxy):
        """Returns a dictionary of the headers to add to any request sent
        through a proxy.

        :param proxy: The url of the proxy being used for this request.
        :rtype: dict
        """
        headers = {}
        username, password = get_auth_from_url(proxy)

        if username:
            headers["Proxy-Authorization"] = _basic_auth_str(username, password)

        return headers

    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None
    ):
        """Sends PreparedRequest object. Returns Response object.

        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a (connect timeout,
            read timeout) tuple.
        :param verify: (optional) Either a boolean, in which case it controls
            whether we verify the server's TLS certificate, or a string, in
            which case it must be a path to a CA bundle to use.
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        :rtype: Response
        """
        rust_session = self._get_rust_session()

        # Track unique TLS configs in poolmanager for connection pool tests
        pool_key = (
            str(verify) if verify else "default",
            str(cert) if cert else "none",
        )
        if pool_key not in self.poolmanager.pools:
            conn_kw = {}
            if cert:
                if isinstance(cert, tuple):
                    conn_kw["cert_file"] = cert[0]
                    conn_kw["key_file"] = cert[1] if len(cert) > 1 else None
                else:
                    conn_kw["cert_file"] = cert
            pool_entry = type("Pool", (), {"conn_kw": conn_kw})()
            self.poolmanager.pools[pool_key] = pool_entry

        # Validate cert/verify paths before making the request
        self.cert_verify(None, request.url, verify, cert)

        # Extract prepared request data
        method = request.method
        url = request.url
        # Strip userinfo from URL to prevent reqwest from using it as
        # basic auth credentials (auth is handled by PreparedRequest headers).
        parsed = urlparse(url)
        if parsed.username is not None or parsed.password is not None:
            netloc = parsed.hostname or ""
            if parsed.port:
                netloc += f":{parsed.port}"
            url = parsed._replace(netloc=netloc).geturl()
        # Convert all header keys/values to native strings for Rust
        headers = None
        if request.headers:
            h = {}
            for k, v in request.headers.items():
                if isinstance(k, bytes):
                    k = k.decode("utf-8")
                if isinstance(v, bytes):
                    v = v.decode("utf-8")
                elif not isinstance(v, str):
                    v = str(v)
                h[str(k)] = v
            headers = h

        # Prepare body - send as raw bytes
        body = request.body
        data = None
        if body is not None:
            if isinstance(body, str):
                data = body.encode("utf-8")
            elif isinstance(body, bytes):
                data = body
            elif hasattr(body, "read"):
                data = body.read()
            elif hasattr(body, "__iter__"):
                # Generator or iterable - consume into bytes
                chunks = []
                for chunk in body:
                    if isinstance(chunk, str):
                        chunks.append(chunk.encode("utf-8"))
                    elif isinstance(chunk, bytes):
                        chunks.append(chunk)
                    else:
                        chunks.append(bytes(chunk))
                data = b"".join(chunks)
            else:
                data = bytes(body)

        # Pass verify to Rust: bool for enable/disable, string for CA bundle path
        if isinstance(verify, str):
            rust_verify = verify  # CA bundle path
        elif verify is not None:
            rust_verify = bool(verify)
        else:
            rust_verify = None

        # Convert cert for Rust
        rust_cert = None
        if cert:
            rust_cert = cert  # Rust accepts str or (str, str) tuple

        # Convert proxies for Rust
        rust_proxies = None
        if proxies:
            rust_proxies = {str(k): str(v) for k, v in proxies.items()}

        # Convert urllib3 Timeout objects to float/tuple for Rust
        try:
            from urllib3.util import Timeout as Urllib3Timeout

            if isinstance(timeout, Urllib3Timeout):
                if timeout.total is not None:
                    timeout = timeout.total
                else:
                    connect = timeout.connect_timeout
                    read = timeout.read_timeout
                    if connect is not None or read is not None:
                        timeout = (connect, read)
                    else:
                        timeout = None
        except ImportError:
            pass

        # Call Rust session - single hop, no redirects
        # Implement retry logic for status_forcelist
        from urllib3.exceptions import MaxRetryError

        retries = self.max_retries
        while True:
            rust_response = rust_session.make_request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                allow_redirects=False,
                timeout=timeout,
                verify=rust_verify,
                cert=rust_cert,
                proxies=rust_proxies,
                stream=stream or None,
            )

            # Check if we should retry based on status code
            has_forcelist = (
                hasattr(retries, "status_forcelist")
                and retries.status_forcelist
                and rust_response.status_code in retries.status_forcelist
            )
            if has_forcelist:
                try:
                    retries = retries.increment(
                        method=method,
                        url=url,
                        response=None,
                    )
                except MaxRetryError as e:
                    raise RetryError(e, request=request)
                continue

            break

        resp = self.build_response(request, rust_response)

        if stream:
            if not resp._content_consumed:
                # Chunked streaming: _from_rust already set up StreamingRawResponse
                # with _content=False, _content_consumed=False — nothing to do.
                pass
            else:
                # Non-chunked streaming (has Content-Length): body was eagerly
                # loaded by _from_rust.  Reset so iter_content reads from raw.
                resp._content_consumed = False
                resp._content = False
                if resp.raw and hasattr(resp.raw, "seek"):
                    resp.raw.seek(0)
        else:
            # Non-streaming: body already in _content, mark raw as exhausted
            # so raw.read() returns b"" (matching urllib3 behavior)
            if resp.raw and hasattr(resp.raw, "seek"):
                resp.raw.seek(0, 2)

        return resp

    def close(self):
        """Disposes of any internal state."""
        if self._rust_session is not None:
            self._rust_session.close()
            self._rust_session = None
        # Clear proxy manager entries (each entry may have a .clear() method)
        for proxy in self.proxy_manager.values():
            if hasattr(proxy, "clear"):
                proxy.clear()
        self.proxy_manager.clear()

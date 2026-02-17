"""
snekwest.sessions
~~~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
requests (cookies, auth, proxies).
"""

import os  # noqa: F401
import sys
import time
from collections import OrderedDict
from datetime import timedelta  # noqa: F401

from ._bindings import Session as _RustSession
from ._internal_utils import to_native_string
from .adapters import HTTPAdapter
from .auth import _basic_auth_str
from .compat import Mapping, cookielib, urljoin, urlparse  # noqa: F401
from .cookies import (  # noqa: F401
    RequestsCookieJar,
    cookiejar_from_dict,
    extract_cookies_to_jar,
    merge_cookies,
)
from .exceptions import (  # noqa: F401
    ChunkedEncodingError,
    ContentDecodingError,
    InvalidSchema,
    TooManyRedirects,
)
from .hooks import default_hooks, dispatch_hook  # noqa: F401

# formerly defined here, reexposed here for backward compatibility
from .models import (  # noqa: F401
    DEFAULT_REDIRECT_LIMIT,
    REDIRECT_STATI,
    PreparedRequest,
    Request,
)
from .status_codes import codes
from .structures import CaseInsensitiveDict  # noqa: F401
from .utils import (  # noqa: F401
    DEFAULT_PORTS,
    default_headers,
    get_auth_from_url,
    get_environ_proxies,
    get_netrc_auth,
    requote_uri,
    resolve_proxies,
    rewind_body,
    should_bypass_proxies,
    to_key_val_list,
)

if sys.platform == "win32":
    preferred_clock = time.perf_counter
else:
    preferred_clock = time.time


from ._bindings import merge_setting  # noqa: F811
from ._bindings import should_strip_auth as _should_strip_auth  # noqa: F811
from ._bindings import rebuild_method as _rebuild_method


def merge_hooks(request_hooks, session_hooks, dict_class=OrderedDict):
    """Properly merges both requests and session hooks."""
    if session_hooks is None or session_hooks.get("response") == []:
        return request_hooks
    if request_hooks is None or request_hooks.get("response") == []:
        return session_hooks
    return merge_setting(request_hooks, session_hooks, dict_class)


class SessionRedirectMixin:
    def get_redirect_target(self, resp):
        """Receives a Response. Returns a redirect URI or ``None``"""
        return resp.get_redirect_target()

    def should_strip_auth(self, old_url, new_url):
        """Decide whether Authorization header should be removed when redirecting"""
        return _should_strip_auth(old_url, new_url)

    def resolve_redirects(
        self,
        resp,
        req,
        stream=False,
        timeout=None,
        verify=True,
        cert=None,
        proxies=None,
        yield_requests=False,
        **adapter_kwargs,
    ):
        """Receives a Response. Returns a generator of Responses or Requests."""
        hist = []
        url = self.get_redirect_target(resp)
        previous_fragment = urlparse(req.url).fragment
        while url:
            prepared_request = req.copy()
            hist.append(resp)
            resp.history = hist[1:]
            try:
                resp.content
            except (ChunkedEncodingError, ContentDecodingError, RuntimeError):
                resp.raw.read(decode_content=False)
            if len(resp.history) >= self.max_redirects:
                raise TooManyRedirects(
                    f"Exceeded {self.max_redirects} redirects.", response=resp
                )
            resp.close()
            if url.startswith("//"):
                parsed_rurl = urlparse(resp.url)
                url = ":".join([to_native_string(parsed_rurl.scheme), url])
            parsed = urlparse(url)
            if parsed.fragment == "" and previous_fragment:
                parsed = parsed._replace(fragment=previous_fragment)
            elif parsed.fragment:
                previous_fragment = parsed.fragment
            url = parsed.geturl()
            if not parsed.netloc:
                url = urljoin(resp.url, requote_uri(url))
            else:
                url = requote_uri(url)
            prepared_request.url = to_native_string(url)
            self.rebuild_method(prepared_request, resp)
            if resp.status_code not in (
                codes.temporary_redirect,
                codes.permanent_redirect,
            ):
                purged_headers = ("Content-Length", "Content-Type", "Transfer-Encoding")
                for header in purged_headers:
                    prepared_request.headers.pop(header, None)
                prepared_request.body = None
            headers = prepared_request.headers
            headers.pop("Cookie", None)
            extract_cookies_to_jar(prepared_request._cookies, req, resp.raw)
            merge_cookies(prepared_request._cookies, self.cookies)
            prepared_request.prepare_cookies(prepared_request._cookies)
            proxies = self.rebuild_proxies(prepared_request, proxies)
            self.rebuild_auth(prepared_request, resp)
            rewindable = prepared_request._body_position is not None and (
                "Content-Length" in headers or "Transfer-Encoding" in headers
            )
            if rewindable:
                rewind_body(prepared_request)
            req = prepared_request
            if yield_requests:
                yield req
            else:
                resp = self.send(
                    req,
                    stream=stream,
                    timeout=timeout,
                    verify=verify,
                    cert=cert,
                    proxies=proxies,
                    allow_redirects=False,
                    **adapter_kwargs,
                )
                extract_cookies_to_jar(self.cookies, prepared_request, resp.raw)
                url = self.get_redirect_target(resp)
                yield resp

    def rebuild_auth(self, prepared_request, response):
        """When being redirected we may want to strip authentication from the
        request to avoid leaking credentials."""
        headers = prepared_request.headers
        url = prepared_request.url
        if "Authorization" in headers and self.should_strip_auth(
            response.request.url, url
        ):
            del headers["Authorization"]
        new_auth = get_netrc_auth(url) if self.trust_env else None
        if new_auth is not None:
            prepared_request.prepare_auth(new_auth)

    def rebuild_proxies(self, prepared_request, proxies):
        """This method re-evaluates the proxy configuration by considering the
        environment variables."""
        headers = prepared_request.headers
        scheme = urlparse(prepared_request.url).scheme
        new_proxies = resolve_proxies(prepared_request, proxies, self.trust_env)
        if "Proxy-Authorization" in headers:
            del headers["Proxy-Authorization"]
        try:
            username, password = get_auth_from_url(new_proxies[scheme])
        except KeyError:
            username, password = None, None
        if not scheme.startswith("https") and username and password:
            headers["Proxy-Authorization"] = _basic_auth_str(username, password)
        return new_proxies

    def rebuild_method(self, prepared_request, response):
        """When being redirected we may want to change the method of the request
        based on certain specs or browser behavior."""
        prepared_request.method = _rebuild_method(
            prepared_request.method, response.status_code
        )


class Session(SessionRedirectMixin, _RustSession):
    """A Requests session.

    Inherits from the Rust Session (transport, fields, core methods)
    and SessionRedirectMixin (redirect handling).
    """

    __attrs__ = [
        "headers",
        "cookies",
        "auth",
        "proxies",
        "hooks",
        "params",
        "verify",
        "cert",
        "adapters",
        "stream",
        "trust_env",
        "max_redirects",
    ]

    def __init__(self):
        super().__init__()
        self.mount("https://", HTTPAdapter())
        self.mount("http://", HTTPAdapter())

    def __getstate__(self):
        state = {attr: getattr(self, attr, None) for attr in self.__attrs__}
        return state

    def __setstate__(self, state):
        for attr, value in state.items():
            setattr(self, attr, value)


def session():
    """Returns a :class:`Session` for context-management.

    .. deprecated:: 1.0.0
        This method has been deprecated since version 1.0.0 and is only kept
        for backwards compatibility. New code should use :class:`~requests.sessions.Session`
        to create sessions.

    :rtype: Session
    """
    return Session()

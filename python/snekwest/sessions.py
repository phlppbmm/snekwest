"""Session management for snekwest, providing persistent connections and cookies."""

from typing import Any, Optional, Union
from urllib.parse import urlencode

from snekwest._bindings import Response as RustResponse  # pylint: disable=no-name-in-module
from snekwest._bindings import Session as RustSession  # pylint: disable=no-name-in-module

from .models import Response


class _CookieProxy:
    """Dict-like proxy for session cookies stored in Rust."""

    def __init__(self, rust_session: RustSession) -> None:
        self._rust_session = rust_session

    def __getitem__(self, key: str) -> str:
        cookies = self._rust_session.get_cookies()
        return cookies[key]

    def __setitem__(self, key: str, value: str) -> None:
        self._rust_session.set_cookie(key, value)

    def __delitem__(self, key: str) -> None:
        self._rust_session.remove_cookie(key)

    def __contains__(self, key: object) -> bool:
        cookies = self._rust_session.get_cookies()
        return key in cookies

    def __bool__(self) -> bool:
        return bool(self._rust_session.get_cookies())

    def __len__(self) -> int:
        return len(self._rust_session.get_cookies())

    def __iter__(self):
        return iter(self._rust_session.get_cookies())

    def __repr__(self) -> str:
        return repr(self._rust_session.get_cookies())

    def get(self, key: str, default=None):
        """Return the cookie value for key, or default."""
        cookies = self._rust_session.get_cookies()
        return cookies.get(key, default)

    def items(self):
        """Return cookie (name, value) pairs."""
        return self._rust_session.get_cookies().items()

    def keys(self):
        """Return cookie names."""
        return self._rust_session.get_cookies().keys()

    def values(self):
        """Return cookie values."""
        return self._rust_session.get_cookies().values()

    def update(self, other=None, **kwargs):
        """Update cookies from a mapping or keyword arguments."""
        if other:
            self._rust_session.set_cookies(dict(other))
        if kwargs:
            self._rust_session.set_cookies(kwargs)


class Session:
    """A requests-compatible HTTP session with persistent cookies and defaults."""

    def __init__(self) -> None:
        self._rust_session = RustSession()
        self.cookies = _CookieProxy(self._rust_session)
        self.headers: dict[str, str] = {}
        self.auth: Optional[tuple[str, str]] = None
        self.params: dict[str, str] = {}
        self.max_redirects: int = 30

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def close(self) -> None:
        """Close the session and release resources."""
        self._rust_session.close()

    def _sync_session_defaults(self) -> None:
        """Push Python-side defaults into the Rust session."""
        self._rust_session.default_headers = self.headers if self.headers else None
        self._rust_session.default_auth = self.auth
        self._rust_session.default_params = self.params if self.params else None
        self._rust_session.max_redirects = self.max_redirects

    def request(  # pylint: disable=too-many-arguments,too-many-locals  # requests-compatible API
        self,
        method: str,
        url: str,
        *,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        timeout: Optional[Union[float, tuple]] = None,
        allow_redirects: bool = True,
        proxies=None,
        hooks=None,
        stream: Optional[bool] = None,
        verify: Optional[bool] = None,
        cert: Optional[Union[str, tuple[str, str]]] = None,
        json: Optional[Any] = None,
    ) -> Response:
        """Send an HTTP request with the given method and URL."""
        _ = hooks

        # Handle bytes method (e.g. b"GET")
        if isinstance(method, bytes):
            method = method.decode("utf-8")

        # Expand list/tuple params values into repeated keys
        # e.g. {"test": ["foo", "baz"]} -> {"test": "foo", "test": "baz"}
        # Since HashMap can't hold duplicates, we encode them into the URL
        if params is not None and isinstance(params, dict):
            has_list = any(isinstance(v, (list, tuple)) for v in params.values())
            if has_list:
                # Build query string with repeated keys
                parts = []
                for k, v in params.items():
                    if isinstance(v, (list, tuple)):
                        for item in v:
                            parts.append((str(k), str(item)))
                    else:
                        parts.append((str(k), str(v)))
                # Append to URL directly
                separator = "&" if "?" in url else "?"
                url = url + separator + urlencode(parts)
                params = None
            else:
                params = {str(k): str(v) for k, v in params.items()}

        # Sync session-level defaults to Rust
        self._sync_session_defaults()

        rust_response: RustResponse = self._rust_session.make_request(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            stream=stream,
            verify=verify,
            cert=cert,
            json=json,
        )

        return Response(rust_response)

    def get(self, url: str, **kwargs) -> Response:
        """Send a GET request."""
        kwargs.setdefault("allow_redirects", True)
        return self.request("GET", url, **kwargs)

    def options(self, url: str, **kwargs) -> Response:
        """Send an OPTIONS request."""
        kwargs.setdefault("allow_redirects", True)
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs) -> Response:
        """Send a HEAD request."""
        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, data=None, json=None, **kwargs) -> Response:
        """Send a POST request."""
        return self.request("POST", url, data=data, json=json, **kwargs)

    def put(self, url: str, data=None, **kwargs) -> Response:
        """Send a PUT request."""
        return self.request("PUT", url, data=data, **kwargs)

    def patch(self, url: str, data=None, **kwargs) -> Response:
        """Send a PATCH request."""
        return self.request("PATCH", url, data=data, **kwargs)

    def delete(self, url: str, **kwargs) -> Response:
        """Send a DELETE request."""
        return self.request("DELETE", url, **kwargs)

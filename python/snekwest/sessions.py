from typing import Any, Optional, Union

from snekwest._bindings import Response as RustResponse
from snekwest._bindings import Session as RustSession

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
        cookies = self._rust_session.get_cookies()
        return cookies.get(key, default)

    def items(self):
        return self._rust_session.get_cookies().items()

    def keys(self):
        return self._rust_session.get_cookies().keys()

    def values(self):
        return self._rust_session.get_cookies().values()

    def update(self, other=None, **kwargs):
        if other:
            self._rust_session.set_cookies(dict(other))
        if kwargs:
            self._rust_session.set_cookies(kwargs)


class Session:
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
        self._rust_session.close()

    def _sync_session_defaults(self) -> None:
        """Push Python-side defaults into the Rust session."""
        self._rust_session.default_headers = self.headers if self.headers else None
        self._rust_session.default_auth = self.auth
        self._rust_session.default_params = self.params if self.params else None
        self._rust_session.max_redirects = self.max_redirects

    def request(
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
        _ = hooks

        # Handle bytes method (e.g. b"GET")
        if isinstance(method, bytes):
            method = method.decode("utf-8")

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
        kwargs.setdefault("allow_redirects", True)
        return self.request("GET", url, **kwargs)

    def options(self, url: str, **kwargs) -> Response:
        kwargs.setdefault("allow_redirects", True)
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs) -> Response:
        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, data=None, json=None, **kwargs) -> Response:
        return self.request("POST", url, data=data, json=json, **kwargs)

    def put(self, url: str, data=None, **kwargs) -> Response:
        return self.request("PUT", url, data=data, **kwargs)

    def patch(self, url: str, data=None, **kwargs) -> Response:
        return self.request("PATCH", url, data=data, **kwargs)

    def delete(self, url: str, **kwargs) -> Response:
        return self.request("DELETE", url, **kwargs)

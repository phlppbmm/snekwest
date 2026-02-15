from datetime import timedelta

from snekwest._bindings import Response as RustResponse
from snekwest.exceptions import HTTPError


class Request:
    """Minimal Request object attached to Response, similar to requests.Request."""

    def __init__(self, method: str, url: str, headers: dict[str, str]) -> None:
        self.method: str = method.upper()
        self.url: str = url
        self.headers: dict[str, str] = headers

    def __repr__(self) -> str:
        return f"<Request [{self.method}]>"


class Response:
    def __init__(self, rust_response: RustResponse) -> None:
        self._rust_response = rust_response

        self.status_code: int = rust_response.status
        self.url: str = rust_response.url
        self.headers: dict[str, str] = rust_response.headers
        self.cookies: dict[str, str] = rust_response.cookies
        self.reason: str | None = rust_response.reason
        self.encoding: str | None = None

        # Elapsed time
        self.elapsed: timedelta = timedelta(milliseconds=rust_response.elapsed_ms)

        # Build history from Rust response history
        self.history: list[Response] = [
            Response(h) for h in rust_response.history
        ]

        # Request object
        self.request: Request = Request(
            method=rust_response.method,
            url=rust_response.request_url,
            headers=rust_response.request_headers,
        )

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)

    @property
    def is_permanent_redirect(self) -> bool:
        return self.status_code in (301, 308)

    @property
    def text(self) -> str:
        return self._rust_response.text()

    @property
    def content(self) -> bytes:
        return bytes(self._rust_response.content())

    def json(self, **kwargs):
        return self._rust_response.json()

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise HTTPError(
                f"{self.status_code} Client Error: {self.reason} for url: {self.url}"
                if self.status_code < 500
                else f"{self.status_code} Server Error: {self.reason} for url: {self.url}",
                response=self,
            )

    def close(self) -> None:
        pass

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"

    def __bool__(self) -> bool:
        return self.ok

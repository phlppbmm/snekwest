"""Tests cherry-picked from python-requests/tests/test_requests.py.

Only tests that exercise the public API are included here.
Excluded: PreparedRequest, HTTPAdapter, CaseInsensitiveDict, hooks,
urllib3 internals, iter_content/iter_lines, pickle, Digest Auth.
"""

import pytest

import snekwest
from snekwest import exceptions
from snekwest.exceptions import (
    ConnectionError,
    ConnectTimeout,
    HTTPError,
    InvalidSchema,
    InvalidURL,
    MissingSchema,
    ReadTimeout,
    SSLError,
    Timeout,
    TooManyRedirects,
)
from snekwest.sessions import Session

# Requests to this URL should always fail with a connection timeout
# (nothing listening on that port)
TARPIT = "http://10.255.255.1"


class TestHTTPMethods:
    """HTTP methods and basic status codes."""

    def test_HTTP_200_OK_GET_WITH_PARAMS(self, httpbin):
        heads = {"User-agent": "Mozilla/5.0"}

        r = snekwest.get(httpbin("user-agent"), headers=heads)

        assert heads["User-agent"] in r.text
        assert r.status_code == 200

    def test_HTTP_200_OK_GET_WITH_MIXED_PARAMS(self, httpbin):
        heads = {"User-agent": "Mozilla/5.0"}

        r = snekwest.get(
            httpbin("get") + "?test=true", params={"q": "test"}, headers=heads
        )
        assert r.status_code == 200

    def test_HTTP_200_OK_HEAD(self, httpbin):
        r = snekwest.head(httpbin("get"))
        assert r.status_code == 200

    def test_HTTP_200_OK_PUT(self, httpbin):
        r = snekwest.put(httpbin("put"))
        assert r.status_code == 200

    @pytest.mark.parametrize(
        "url, params",
        (
            ("/get", {"foo": "føø"}),
            ("/get", {"føø": "føø"}),
            ("/get", {"føø": "føø"}),
            ("/get", {"foo": "foo"}),
            ("ø", {"foo": "foo"}),
        ),
    )
    def test_unicode_get(self, httpbin, url, params):
        snekwest.get(httpbin(url), params=params)

    def test_unicode_header_name(self, httpbin):
        snekwest.put(
            httpbin("put"),
            headers={"Content-Type": "application/octet-stream"},
            data="\xff",
        )

    def test_decompress_gzip(self, httpbin):
        r = snekwest.get(httpbin("gzip"))
        r.content.decode("ascii")

    def test_encoded_methods(self, httpbin):
        """See: https://github.com/psf/requests/issues/2316"""
        r = snekwest.request(b"GET", httpbin("get"))
        assert r.ok


class TestExceptions:
    """Exception handling and error conditions."""

    @pytest.mark.parametrize(
        "exception, url",
        (
            (MissingSchema, "hiwpefhipowhefopw"),
            (InvalidSchema, "localhost:3128"),
            (InvalidSchema, "localhost.localdomain:3128/"),
            (InvalidSchema, "10.122.1.1:3128/"),
            (InvalidURL, "http://"),
            (InvalidURL, "http://*example.com"),
            (InvalidURL, "http://.example.com"),
        ),
    )
    def test_invalid_url(self, exception, url):
        with pytest.raises(exception):
            snekwest.get(url)

    @pytest.mark.parametrize(
        "url, exception",
        (
            # Connecting to an unknown domain should raise a ConnectionError
            ("http://doesnotexist.google.com", ConnectionError),
            # Connecting to an invalid port should raise a ConnectionError
            ("http://localhost:1", ConnectionError),
            # Inputing a URL that cannot be parsed should raise an InvalidURL error
            ("http://fe80::5054:ff:fe5a:fc0", InvalidURL),
        ),
    )
    def test_errors(self, url, exception):
        with pytest.raises(exception):
            snekwest.get(url, timeout=1)

    def test_status_raising(self, httpbin):
        r = snekwest.get(httpbin("status", "404"))
        with pytest.raises(HTTPError):
            r.raise_for_status()

        r = snekwest.get(httpbin("status", "500"))
        assert not r.ok

    def test_request_ok_set(self, httpbin):
        r = snekwest.get(httpbin("status", "404"))
        assert not r.ok

    def test_certificate_failure(self, httpbin_secure):
        """When underlying SSL problems occur, an SSLError is raised."""
        with pytest.raises(SSLError):
            # Our local httpbin does not have a trusted CA, so this call will
            # fail if we use our default trust bundle.
            snekwest.get(httpbin_secure("status", "200"))


class TestRedirects:
    """Redirect handling and history tracking."""

    def test_HTTP_302_ALLOW_REDIRECT_GET(self, httpbin):
        r = snekwest.get(httpbin("redirect", "1"))
        assert r.status_code == 200
        assert r.history[0].status_code == 302
        assert r.history[0].is_redirect

    def test_HTTP_307_ALLOW_REDIRECT_POST(self, httpbin):
        r = snekwest.post(
            httpbin("redirect-to"),
            data="test",
            params={"url": "post", "status_code": 307},
        )
        assert r.status_code == 200
        assert r.history[0].status_code == 307
        assert r.history[0].is_redirect
        assert r.json()["data"] == "test"

    def test_HTTP_302_TOO_MANY_REDIRECTS(self, httpbin):
        try:
            snekwest.get(httpbin("relative-redirect", "50"))
        except TooManyRedirects as e:
            url = httpbin("relative-redirect", "20")
            assert e.request.url == url
            assert e.response.url == url
            assert len(e.response.history) == 30
        else:
            pytest.fail("Expected redirect to raise TooManyRedirects but it did not")

    def test_http_301_changes_post_to_get(self, httpbin):
        r = snekwest.post(httpbin("status", "301"))
        assert r.status_code == 200
        assert r.request.method == "GET"
        assert r.history[0].status_code == 301
        assert r.history[0].is_redirect

    def test_http_301_doesnt_change_head_to_get(self, httpbin):
        r = snekwest.head(httpbin("status", "301"), allow_redirects=True)
        assert r.status_code == 200
        assert r.request.method == "HEAD"
        assert r.history[0].status_code == 301
        assert r.history[0].is_redirect

    def test_http_302_changes_post_to_get(self, httpbin):
        r = snekwest.post(httpbin("status", "302"))
        assert r.status_code == 200
        assert r.request.method == "GET"
        assert r.history[0].status_code == 302
        assert r.history[0].is_redirect

    def test_http_303_changes_post_to_get(self, httpbin):
        r = snekwest.post(httpbin("status", "303"))
        assert r.status_code == 200
        assert r.request.method == "GET"
        assert r.history[0].status_code == 303
        assert r.history[0].is_redirect

    def test_fragment_maintained_on_redirect(self, httpbin):
        fragment = "#view=edit&token=hunter2"
        r = snekwest.get(httpbin("redirect-to?url=get") + fragment)

        assert len(r.history) > 0
        assert r.history[0].request.url == httpbin("redirect-to?url=get") + fragment
        assert r.url == httpbin("get") + fragment

    def test_history_is_always_a_list(self, httpbin):
        """Show that even with redirects, Response.history is always a list."""
        resp = snekwest.get(httpbin("get"))
        assert isinstance(resp.history, list)
        resp = snekwest.get(httpbin("redirect/1"))
        assert isinstance(resp.history, list)
        assert not isinstance(resp.history, tuple)

    def test_uppercase_scheme_redirect(self, httpbin):
        try:
            from urllib.parse import urlparse
        except ImportError:
            from urlparse import urlparse

        parts = urlparse(httpbin("html"))
        url = "HTTP://" + parts.netloc + parts.path
        r = snekwest.get(httpbin("redirect-to"), params={"url": url})
        assert r.status_code == 200
        assert r.url.lower() == url.lower()


class TestCookies:
    """Cookie handling across requests and sessions."""

    def test_set_cookie_on_301(self, httpbin):
        s = snekwest.Session()
        url = httpbin("cookies/set?foo=bar")
        s.get(url)
        assert s.cookies["foo"] == "bar"

    def test_cookie_sent_on_redirect(self, httpbin):
        s = snekwest.Session()
        s.get(httpbin("cookies/set?foo=bar"))
        r = s.get(httpbin("redirect/1"))  # redirects to httpbin('get')
        assert "Cookie" in r.json()["headers"]

    def test_cookie_removed_on_expire(self, httpbin):
        s = snekwest.Session()
        s.get(httpbin("cookies/set?foo=bar"))
        assert s.cookies["foo"] == "bar"
        s.get(
            httpbin("response-headers"),
            params={
                "Set-Cookie": "foo=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT"
            },
        )
        assert "foo" not in s.cookies

    def test_cookie_quote_wrapped(self, httpbin):
        s = snekwest.Session()
        s.get(httpbin('cookies/set?foo="bar:baz"'))
        assert s.cookies["foo"] == '"bar:baz"'

    def test_request_cookie_overrides_session_cookie(self, httpbin):
        s = snekwest.Session()
        s.cookies["foo"] = "bar"
        r = s.get(httpbin("cookies"), cookies={"foo": "baz"})
        assert r.json()["cookies"]["foo"] == "baz"
        # Session cookie should not be modified
        assert s.cookies["foo"] == "bar"

    def test_request_cookies_not_persisted(self, httpbin):
        s = snekwest.Session()
        s.get(httpbin("cookies"), cookies={"foo": "baz"})
        # Sending a request with cookies should not add cookies to the session
        assert not s.cookies


class TestAuth:
    """Authentication handling."""

    def test_BASICAUTH_TUPLE_HTTP_200_OK_GET(self, httpbin):
        auth = ("user", "pass")
        url = httpbin("basic-auth", "user", "pass")

        r = snekwest.get(url, auth=auth)
        assert r.status_code == 200

        r = snekwest.get(url)
        assert r.status_code == 401

        s = snekwest.Session()
        s.auth = auth
        r = s.get(url)
        assert r.status_code == 200

    def test_auth_is_retained_for_redirect_on_host(self, httpbin):
        r = snekwest.get(httpbin("redirect/1"), auth=("user", "pass"))
        h1 = r.history[0].request.headers["Authorization"]
        h2 = r.request.headers["Authorization"]

        assert h1 == h2


class TestResponseAttributes:
    """Response object attributes and methods."""

    def test_time_elapsed_blank(self, httpbin):
        r = snekwest.get(httpbin("get"))
        td = r.elapsed
        total_seconds = (
            td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6
        ) / 10**6
        assert total_seconds > 0.0

    def test_json_param_post_content_type_works(self, httpbin):
        r = snekwest.post(httpbin("post"), json={"life": 42})
        assert r.status_code == 200
        assert "application/json" in r.request.headers["Content-Type"]
        assert {"life": 42} == r.json()["json"]

    def test_urlencoded_get_query_multivalued_param(self, httpbin):
        r = snekwest.get(httpbin("get"), params={"test": ["foo", "baz"]})
        assert r.status_code == 200
        assert r.url == httpbin("get?test=foo&test=baz")

    def test_response_context_manager(self, httpbin):
        with snekwest.get(httpbin("get")) as response:
            assert isinstance(response, snekwest.Response)


class TestSession:
    """Session behavior."""

    def test_params_are_merged_case_sensitive(self, httpbin):
        s = snekwest.Session()
        s.params["foo"] = "bar"
        r = s.get(httpbin("get"), params={"FOO": "bar"})
        assert r.json()["args"] == {"foo": "bar", "FOO": "bar"}


class TestTimeout:
    """Timeout handling."""

    def test_stream_timeout(self, httpbin):
        try:
            snekwest.get(httpbin("delay/10"), timeout=2.0)
        except Timeout as e:
            assert "timed out" in str(e).lower()

    def test_connect_timeout(self):
        try:
            snekwest.get(TARPIT, timeout=(0.1, None))
            pytest.fail("The connect() request should time out.")
        except ConnectTimeout as e:
            assert isinstance(e, ConnectionError)
            assert isinstance(e, Timeout)

    def test_read_timeout(self, httpbin):
        try:
            snekwest.get(httpbin("delay/10"), timeout=(None, 0.1))
            pytest.fail("The recv() request should time out.")
        except ReadTimeout:
            pass

    @pytest.mark.parametrize(
        "timeout, error_text",
        (
            ((3, 4, 5), "(connect, read)"),
            ("foo", "must be an int, float or None"),
        ),
    )
    def test_invalid_timeout(self, httpbin, timeout, error_text):
        with pytest.raises(ValueError) as e:
            snekwest.get(httpbin("get"), timeout=timeout)
        assert error_text in str(e)

"""Convenience HTTP methods (get, post, put, etc.) for snekwest."""

import atexit
import threading

from . import sessions
from .models import Response

_thread_local = threading.local()


def _cleanup_session(session):
    """Defensively close a session, ignoring any errors."""
    try:
        session.close()
    except Exception:
        pass


def _get_session():
    """Return a per-thread singleton Session, creating it lazily if needed."""
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = sessions.Session()
        _thread_local.session = session
        atexit.register(_cleanup_session, session)
    return session


def request(method, url, **kwargs) -> Response:
    """Construct and send an HTTP request.

    :param method: HTTP method (GET, OPTIONS, HEAD, POST, PUT,
        PATCH, or DELETE).
    :param url: URL for the request.
    :param params: (optional) Dictionary, list of tuples or bytes
        to send in the query string.
    :param data: (optional) Dictionary, list of tuples, bytes, or
        file-like object to send in the body.
    :param json: (optional) A JSON serializable Python object to
        send in the body.
    :param headers: (optional) Dictionary of HTTP Headers to send.
    :param cookies: (optional) Dict or CookieJar object to send.
    :param files: (optional) Dictionary of ``'name': file-like-objects``
        for multipart encoding upload.
    :param auth: (optional) Auth tuple for Basic/Digest/Custom HTTP Auth.
    :param timeout: (optional) Seconds to wait for the server, as a float
        or a ``(connect timeout, read timeout)`` tuple.
    :type timeout: float or tuple
    :param allow_redirects: (optional) Boolean. Enable/disable
        redirection. Defaults to ``True``.
    :type allow_redirects: bool
    :param proxies: (optional) Dictionary mapping protocol to
        the URL of the proxy.
    :param verify: (optional) Boolean controlling TLS certificate
        verification, or path to a CA bundle. Defaults to ``True``.
    :param stream: (optional) if ``False``, the response content
        will be immediately downloaded.
    :param cert: (optional) Path to ssl client cert file (.pem),
        or ``('cert', 'key')`` tuple.
    :return: :class:`Response <Response>` object
    :rtype: Response
    """

    session = _get_session()
    session.cookies.clear()
    return session.request(method=method, url=url, **kwargs)


def get(url: str, params=None, **kwargs) -> Response:
    r"""Sends a GET request.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary, list of tuples or bytes to send
        in the query string for the :class:`Request`.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """

    return request("get", url, params=params, **kwargs)


def options(url: str, **kwargs) -> Response:
    r"""Sends an OPTIONS request.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """

    return request("options", url, **kwargs)


def head(url: str, **kwargs) -> Response:
    r"""Sends a HEAD request.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes. If
        `allow_redirects` is not provided, it will be set to `False` (as
        opposed to the default :meth:`request` behavior).
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """

    kwargs.setdefault("allow_redirects", False)
    return request("head", url, **kwargs)


def post(url: str, data=None, json=None, **kwargs) -> Response:
    r"""Sends a POST request.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or
        file-like object to send in the body.
    :param json: (optional) A JSON serializable Python object to
        send in the body.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: Response
    """

    return request("post", url, data=data, json=json, **kwargs)


def put(url: str, data=None, **kwargs) -> Response:
    r"""Sends a PUT request.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or
        file-like object to send in the body.
    :param json: (optional) A JSON serializable Python object to
        send in the body.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: Response
    """

    return request("put", url, data=data, **kwargs)


def patch(url: str, data=None, **kwargs) -> Response:
    r"""Sends a PATCH request.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary, list of tuples, bytes, or
        file-like object to send in the body.
    :param json: (optional) A JSON serializable Python object to
        send in the body.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: Response
    """

    return request("patch", url, data=data, **kwargs)


def delete(url: str, **kwargs) -> Response:
    r"""Sends a DELETE request.

    :param url: URL for the new :class:`Request` object.
    :param \*\*kwargs: Optional arguments that ``request`` takes.
    :return: :class:`Response <Response>` object
    :rtype: requests.Response
    """

    return request("delete", url, **kwargs)

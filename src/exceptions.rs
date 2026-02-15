use pyo3::exceptions::PyException;

// Base exception
pyo3::create_exception!(exceptions, RequestException, PyException);

// Direct children of RequestException
pyo3::create_exception!(exceptions, HTTPError, RequestException);
pyo3::create_exception!(exceptions, ConnectionError, RequestException);
// Timeout inherits from ConnectionError (matching python-requests hierarchy)
pyo3::create_exception!(exceptions, Timeout, ConnectionError);
pyo3::create_exception!(exceptions, URLRequired, RequestException);
pyo3::create_exception!(exceptions, TooManyRedirects, RequestException);
pyo3::create_exception!(exceptions, MissingSchema, RequestException);
pyo3::create_exception!(exceptions, InvalidSchema, RequestException);
pyo3::create_exception!(exceptions, InvalidURL, RequestException);
pyo3::create_exception!(exceptions, InvalidHeader, RequestException);
pyo3::create_exception!(exceptions, ChunkedEncodingError, RequestException);
pyo3::create_exception!(exceptions, ContentDecodingError, RequestException);
pyo3::create_exception!(exceptions, StreamConsumedError, RequestException);
pyo3::create_exception!(exceptions, RetryError, RequestException);
pyo3::create_exception!(exceptions, UnrewindableBodyError, RequestException);
pyo3::create_exception!(exceptions, InvalidJSONError, RequestException);

// Children of ConnectionError
pyo3::create_exception!(exceptions, ProxyError, ConnectionError);
pyo3::create_exception!(exceptions, SSLError, ConnectionError);

// Children of Timeout
pyo3::create_exception!(exceptions, ConnectTimeout, Timeout);
pyo3::create_exception!(exceptions, ReadTimeout, Timeout);

// Children of InvalidURL
pyo3::create_exception!(exceptions, InvalidProxyURL, InvalidURL);

// Children of InvalidJSONError
pyo3::create_exception!(exceptions, JSONDecodeError, InvalidJSONError);

// Warnings
pyo3::create_exception!(exceptions, RequestsWarning, pyo3::exceptions::PyWarning);
pyo3::create_exception!(exceptions, FileModeWarning, RequestsWarning);
pyo3::create_exception!(exceptions, RequestsDependencyWarning, RequestsWarning);

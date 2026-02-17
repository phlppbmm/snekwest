use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::PyDict;
use std::collections::HashMap;
use std::sync::Mutex;

/// Cached exception class lookups. Avoids repeated py.import + getattr
/// on every exception raise.
static EXCEPTION_CACHE: PyOnceLock<Mutex<HashMap<&'static str, Py<PyAny>>>> = PyOnceLock::new();

/// All exception class names used from Rust. This allows pre-population
/// and ensures only known names are cached.
const KNOWN_EXCEPTIONS: &[&str] = &[
    "ChunkedEncodingError",
    "ConnectionError",
    "ConnectTimeout",
    "ContentDecodingError",
    "HTTPError",
    "InvalidHeader",
    "InvalidJSONError",
    "InvalidProxyURL",
    "InvalidSchema",
    "InvalidURL",
    "MissingSchema",
    "ProxyError",
    "ReadTimeout",
    "SSLError",
    "TooManyRedirects",
];

fn get_cache(py: Python<'_>) -> &Mutex<HashMap<&'static str, Py<PyAny>>> {
    EXCEPTION_CACHE.get_or_init(py, || Mutex::new(HashMap::new()))
}

/// Helper to get an exception class from the Python `snekwest.exceptions` module.
/// Uses a per-process cache so the module import + getattr only happens once per class.
fn get_exception_class<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    let cache = get_cache(py);
    let guard = cache.lock().unwrap();

    // Try cache first — find the static name that matches
    if let Some(static_name) = KNOWN_EXCEPTIONS.iter().find(|&&n| n == name) {
        if let Some(cached) = guard.get(static_name) {
            return Ok(cached.bind(py).clone());
        }
        drop(guard);

        // Cache miss — import and cache
        let module = py.import("snekwest.exceptions")?;
        let cls = module.getattr(name)?;
        let mut guard = cache.lock().unwrap();
        guard.insert(static_name, cls.clone().unbind());
        return Ok(cls);
    }

    drop(guard);

    // Unknown exception name — fall back to direct import (no caching)
    let module = py.import("snekwest.exceptions")?;
    module.getattr(name)
}

/// Create a PyErr from a Python-defined exception class by name.
pub fn make_exception(py: Python<'_>, class_name: &str, msg: String) -> PyErr {
    make_exception_with_request(py, class_name, msg, None)
}

/// Create a PyErr with an optional `request` kwarg so that
/// `e.request` returns the PreparedRequest that caused the error.
pub fn make_exception_with_request(
    py: Python<'_>,
    class_name: &str,
    msg: String,
    request: Option<&Py<PyAny>>,
) -> PyErr {
    match get_exception_class(py, class_name) {
        Ok(cls) => {
            let kwargs = PyDict::new(py);
            if let Some(req) = request {
                let _ = kwargs.set_item("request", req);
            }
            match cls.call((msg,), Some(&kwargs)) {
                Ok(instance) => PyErr::from_value(instance),
                Err(e) => e,
            }
        }
        Err(e) => e,
    }
}

/// Create a timeout exception with nested args structure and optional request.
/// The outer exception's args[0] is an IOError whose args[0] is the message.
/// This matches requests' pattern: ReadTimeout(urllib3.ReadTimeoutError(msg))
/// so that `e.args[0].args[0]` returns the message string.
pub fn raise_nested_exception(py: Python<'_>, class_name: &str, msg: String) -> PyErr {
    raise_nested_exception_with_request(py, class_name, msg, None)
}

/// Create a timeout exception with nested args structure and optional request kwarg.
pub fn raise_nested_exception_with_request(
    py: Python<'_>,
    class_name: &str,
    msg: String,
    request: Option<&Py<PyAny>>,
) -> PyErr {
    match get_exception_class(py, class_name) {
        Ok(cls) => {
            // Create inner IOError(msg) so that args[0].args[0] works
            let builtins = match py.import("builtins") {
                Ok(b) => b,
                Err(e) => return e,
            };
            let io_error_cls = match builtins.getattr("IOError") {
                Ok(c) => c,
                Err(e) => return e,
            };
            let inner = match io_error_cls.call1((&msg,)) {
                Ok(i) => i,
                Err(e) => return e,
            };
            let kwargs = PyDict::new(py);
            if let Some(req) = request {
                let _ = kwargs.set_item("request", req);
            }
            match cls.call((inner,), Some(&kwargs)) {
                Ok(instance) => PyErr::from_value(instance),
                Err(e) => e,
            }
        }
        Err(e) => e,
    }
}

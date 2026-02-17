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

#[cfg(test)]
mod tests {
    use super::*;

    fn init_python() {
        Python::initialize();
        // Add the python/ source directory to sys.path so snekwest is importable
        Python::attach(|py| {
            let sys = py.import("sys").unwrap();
            let path = sys.getattr("path").unwrap();
            let python_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/python");
            let _ = path.call_method1("insert", (0, python_dir));
        });
    }

    #[test]
    fn test_make_exception_creates_correct_type() {
        init_python();
        Python::attach(|py| {
            let err = make_exception(py, "ConnectionError", "test msg".into());
            let instance = err.value(py);
            let cls = py
                .import("snekwest.exceptions")
                .unwrap()
                .getattr("ConnectionError")
                .unwrap();
            assert!(instance.is_instance(&cls).unwrap());
        });
    }

    #[test]
    fn test_make_exception_message() {
        init_python();
        Python::attach(|py| {
            let err = make_exception(py, "SSLError", "certificate verify failed".into());
            let instance = err.value(py);
            let args: Vec<String> = instance
                .getattr("args")
                .unwrap()
                .extract::<Vec<String>>()
                .unwrap();
            assert_eq!(args[0], "certificate verify failed");
        });
    }

    #[test]
    fn test_make_exception_invalid_class_name() {
        init_python();
        Python::attach(|py| {
            // Should return an error (AttributeError), not panic
            let err = make_exception(py, "NonexistentError", "msg".into());
            let err_str = err.to_string();
            assert!(
                err_str.contains("NonexistentError") || err_str.contains("attribute"),
                "Expected AttributeError, got: {}",
                err_str
            );
        });
    }

    #[test]
    fn test_make_exception_with_request_sets_attribute() {
        init_python();
        Python::attach(|py| {
            let req = py
                .eval(pyo3::ffi::c_str!("'fake_request'"), None, None)
                .unwrap();
            let req_py: Py<PyAny> = req.unbind();
            let err =
                make_exception_with_request(py, "ConnectionError", "msg".into(), Some(&req_py));
            let instance = err.value(py);
            let request_attr = instance.getattr("request").unwrap();
            let val: String = request_attr.extract().unwrap();
            assert_eq!(val, "fake_request");
        });
    }

    #[test]
    fn test_make_exception_without_request_has_none() {
        init_python();
        Python::attach(|py| {
            let err = make_exception(py, "ConnectionError", "msg".into());
            let instance = err.value(py);
            let request_attr = instance.getattr("request").unwrap();
            assert!(request_attr.is_none());
        });
    }

    #[test]
    fn test_raise_nested_exception_args_structure() {
        init_python();
        Python::attach(|py| {
            let err = raise_nested_exception(py, "ReadTimeout", "Read timed out".into());
            let instance = err.value(py);

            // e.args[0] should be an IOError
            let args = instance.getattr("args").unwrap();
            let inner = args.get_item(0).unwrap();
            assert!(inner
                .is_instance(&py.import("builtins").unwrap().getattr("IOError").unwrap())
                .unwrap());

            // e.args[0].args[0] should be the message
            let inner_args = inner.getattr("args").unwrap();
            let msg: String = inner_args.get_item(0).unwrap().extract().unwrap();
            assert_eq!(msg, "Read timed out");
        });
    }

    #[test]
    fn test_exception_cache_returns_same_class() {
        init_python();
        Python::attach(|py| {
            let cls1 = get_exception_class(py, "ConnectionError").unwrap();
            let cls2 = get_exception_class(py, "ConnectionError").unwrap();
            assert!(cls1.is(&cls2));
        });
    }

    #[test]
    fn test_all_known_exceptions_resolve() {
        init_python();
        Python::attach(|py| {
            for name in KNOWN_EXCEPTIONS {
                let result = get_exception_class(py, name);
                assert!(result.is_ok(), "Failed to resolve exception: {}", name);
            }
        });
    }
}

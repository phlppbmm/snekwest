use pyo3::prelude::*;
use pyo3::types::PyDict;

/// Helper to get an exception class from the Python `snekwest.exceptions` module.
/// Returns a Bound<PyType> for use with PyErr::from_type / PyErr::from_value.
fn get_exception_class<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
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

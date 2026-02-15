use pyo3::prelude::*;

/// Helper to get an exception class from the Python `snekwest.exceptions` module.
/// Returns a Bound<PyType> for use with PyErr::from_type / PyErr::from_value.
fn get_exception_class<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    let module = py.import("snekwest.exceptions")?;
    module.getattr(name)
}

/// Create a PyErr from a Python-defined exception class by name.
pub fn make_exception(py: Python<'_>, class_name: &str, msg: String) -> PyErr {
    match get_exception_class(py, class_name) {
        Ok(cls) => match cls.call1((msg,)) {
            Ok(instance) => PyErr::from_value(instance),
            Err(e) => e,
        },
        Err(e) => e,
    }
}

/// Convenience function to raise a specific snekwest exception from Rust.
pub fn raise_exception(py: Python<'_>, class_name: &str, msg: String) -> PyErr {
    make_exception(py, class_name, msg)
}

/// Create a timeout exception with nested args structure.
/// The outer exception's args[0] is an IOError whose args[0] is the message.
/// This matches requests' pattern: ReadTimeout(urllib3.ReadTimeoutError(msg))
/// so that `e.args[0].args[0]` returns the message string.
pub fn raise_nested_exception(py: Python<'_>, class_name: &str, msg: String) -> PyErr {
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
            match cls.call1((inner,)) {
                Ok(instance) => PyErr::from_value(instance),
                Err(e) => e,
            }
        }
        Err(e) => e,
    }
}

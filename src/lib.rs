mod exceptions;
mod request_params;
mod response;
mod session;

use pyo3::prelude::*;
use response::Response;
use session::Session;

#[pymodule]
fn _bindings(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Session>()?;
    m.add_class::<Response>()?;
    Ok(())
}

use pyo3::prelude::*;
use pythonize::pythonize;
use std::collections::HashMap;
use std::sync::Arc;

#[pyclass]
#[derive(Debug, Clone)]
pub struct Response {
    #[pyo3(get)]
    pub status: u16,
    #[pyo3(get)]
    pub url: String,
    #[pyo3(get)]
    pub headers: HashMap<String, String>,
    body: Arc<Vec<u8>>,
    #[pyo3(get)]
    pub elapsed_ms: f64,
    #[pyo3(get)]
    pub history: Vec<Response>,
    #[pyo3(get)]
    pub cookies: HashMap<String, String>,
    #[pyo3(get)]
    pub reason: Option<String>,
    #[pyo3(get)]
    pub is_redirect: bool,
    #[pyo3(get)]
    pub method: String,
    #[pyo3(get)]
    pub request_url: String,
    #[pyo3(get)]
    pub request_headers: HashMap<String, String>,
}

impl Response {
    pub fn new(
        status: u16,
        url: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
        elapsed_ms: f64,
        history: Vec<Response>,
        cookies: HashMap<String, String>,
        reason: Option<String>,
        is_redirect: bool,
        method: String,
        request_url: String,
        request_headers: HashMap<String, String>,
    ) -> Self {
        Self {
            status,
            url,
            headers,
            body: Arc::new(body),
            elapsed_ms,
            history,
            cookies,
            reason,
            is_redirect,
            method,
            request_url,
            request_headers,
        }
    }
}

#[pymethods]
impl Response {
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match serde_json::from_slice::<serde_json::Value>(&self.body) {
            Ok(json_value) => pythonize(py, &json_value)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
            Err(e) => {
                let json_module = py.import("json")?;
                let json_decode_error = json_module.getattr("JSONDecodeError")?;

                let error_msg = format!("Expecting value: {}", e);
                let doc = String::from_utf8_lossy(&self.body);
                let pos = e.column().saturating_sub(1);

                Err(PyErr::from_value(json_decode_error.call1((
                    error_msg,
                    doc.as_ref(),
                    pos,
                ))?))
            }
        }
    }

    fn text(&self) -> PyResult<String> {
        match String::from_utf8(self.body.as_ref().clone()) {
            Ok(text) => Ok(text),
            Err(_) => Ok(String::from_utf8_lossy(self.body.as_ref()).into_owned()),
        }
    }

    fn content(&self) -> Vec<u8> {
        self.body.as_ref().clone()
    }
}

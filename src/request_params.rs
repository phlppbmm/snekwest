use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyFloat, PyInt, PyNone, PyString, PyTuple};
use std::collections::HashMap;

#[derive(Debug, FromPyObject)]
pub struct RequestParams {
    pub method: String,
    pub url: String,
    pub params: Option<HashMap<String, String>>,
    pub data: Option<DataParameter>,
    pub json: Option<Py<PyAny>>,
    pub headers: Option<HashMap<String, String>>,
    pub cookies: Option<HashMap<String, String>>,
    pub files: Option<HashMap<String, String>>,
    pub auth: Option<(String, String)>,
    pub timeout: Option<TimeoutParameter>,
    #[allow(dead_code)]
    pub allow_redirects: bool,
    pub proxies: Option<HashMap<String, String>>,
    pub stream: Option<bool>,
    pub verify: Option<VerifyParameter>,
    pub cert: Option<CertParameter>,
}

impl RequestParams {
    #[allow(clippy::too_many_arguments)]
    pub fn from_args(
        method: String,
        url: String,
        params: Option<HashMap<String, String>>,
        data: Option<DataParameter>,
        json: Option<Py<PyAny>>,
        headers: Option<HashMap<String, String>>,
        cookies: Option<HashMap<String, String>>,
        files: Option<HashMap<String, String>>,
        auth: Option<(String, String)>,
        timeout: Option<TimeoutParameter>,
        allow_redirects: Option<bool>,
        proxies: Option<HashMap<String, String>>,
        stream: Option<bool>,
        verify: Option<VerifyParameter>,
        cert: Option<CertParameter>,
    ) -> Self {
        Self {
            method,
            url,
            params,
            data,
            json,
            headers,
            cookies,
            files,
            auth,
            timeout,
            allow_redirects: allow_redirects.unwrap_or(true),
            proxies,
            stream,
            verify,
            cert,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DataParameter {
    Form(HashMap<String, String>),
    Raw(Vec<u8>),
}

impl<'a, 'py> FromPyObject<'a, 'py> for DataParameter {
    type Error = PyErr;

    fn extract(ob: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(dict) = ob.cast::<PyDict>() {
            let map: HashMap<String, String> = dict.extract()?;
            return Ok(DataParameter::Form(map));
        }

        if let Ok(s) = ob.cast::<PyString>() {
            return Ok(DataParameter::Raw(s.to_string().into_bytes()));
        }

        if let Ok(bytes) = ob.cast::<PyBytes>() {
            return Ok(DataParameter::Raw(bytes.as_bytes().to_vec()));
        }

        Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
            "data must be dict, string, or bytes",
        ))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TimeoutParameter {
    Single(f64),
    Pair(Option<f64>, Option<f64>),
}

impl<'a, 'py> FromPyObject<'a, 'py> for TimeoutParameter {
    type Error = PyErr;

    fn extract(ob: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(f) = ob.cast::<PyFloat>() {
            return Ok(TimeoutParameter::Single(f.extract()?));
        }

        if let Ok(i) = ob.cast::<PyInt>() {
            return Ok(TimeoutParameter::Single(i.extract::<f64>()?));
        }

        if let Ok(tuple) = ob.cast::<PyTuple>() {
            if tuple.len() == 2 {
                let first = tuple.get_item(0)?;
                let second = tuple.get_item(1)?;

                let connect: Option<f64> = if first.cast::<PyNone>().is_ok() {
                    None
                } else {
                    Some(first.extract()?)
                };

                let read: Option<f64> = if second.cast::<PyNone>().is_ok() {
                    None
                } else {
                    Some(second.extract()?)
                };

                return Ok(TimeoutParameter::Pair(connect, read));
            }

            // 3+ element tuple is invalid
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Timeout value connect is invalid. It must be a (connect, read) tuple.",
            ));
        }

        // String or other type
        Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Timeout value must be an int, float or None",
        ))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum VerifyParameter {
    Bool(bool),
    CaBundle(String),
}

impl<'a, 'py> FromPyObject<'a, 'py> for VerifyParameter {
    type Error = PyErr;

    fn extract(ob: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(b) = ob.extract::<bool>() {
            return Ok(VerifyParameter::Bool(b));
        }
        if let Ok(s) = ob.cast::<PyString>() {
            return Ok(VerifyParameter::CaBundle(s.to_string()));
        }
        Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
            "verify must be bool or string path",
        ))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CertParameter {
    Single(String),
    Pair(String, String),
}

impl<'a, 'py> FromPyObject<'a, 'py> for CertParameter {
    type Error = PyErr;

    fn extract(ob: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(s) = ob.cast::<PyString>() {
            return Ok(CertParameter::Single(s.to_string()));
        }

        if let Ok(tuple) = ob.cast::<PyTuple>() {
            if tuple.len() == 2 {
                let first: String = tuple.get_item(0)?.extract()?;
                let second: String = tuple.get_item(1)?.extract()?;
                return Ok(CertParameter::Pair(first, second));
            }
        }

        Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
            "Expected string or tuple of two strings",
        ))
    }
}

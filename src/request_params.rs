use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyFloat, PyInt, PyList, PyNone, PyString, PyTuple};
use std::collections::HashMap;

#[derive(Debug)]
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
            proxies,
            stream,
            verify,
            cert,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DataParameter {
    Form(Vec<(String, String)>),
    Raw(Vec<u8>),
}

impl<'a, 'py> FromPyObject<'a, 'py> for DataParameter {
    type Error = PyErr;

    fn extract(ob: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(dict) = ob.cast::<PyDict>() {
            let pairs: Vec<(String, String)> = dict
                .iter()
                .map(|(k, v)| Ok((k.extract::<String>()?, v.extract::<String>()?)))
                .collect::<PyResult<_>>()?;
            return Ok(DataParameter::Form(pairs));
        }

        if let Ok(list) = ob.cast::<PyList>() {
            let pairs: Vec<(String, String)> = list
                .iter()
                .map(|item| item.extract::<(String, String)>())
                .collect::<PyResult<_>>()?;
            return Ok(DataParameter::Form(pairs));
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

            // Non-2-element tuple is invalid
            let repr: String = ob.repr()?.to_string();
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid timeout {}. Pass a (connect, read) timeout tuple, \
                 or a single float to set both timeouts to the same value.",
                repr
            )));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn init_python() {
        Python::initialize();
    }

    // -- DataParameter tests --

    #[test]
    fn test_data_dict() {
        init_python();
        Python::attach(|py| {
            let dict = PyDict::new(py);
            dict.set_item("key", "value").unwrap();
            let result = DataParameter::extract(dict.as_any().as_borrowed()).unwrap();
            assert_eq!(
                result,
                DataParameter::Form(vec![("key".into(), "value".into())])
            );
        });
    }

    #[test]
    fn test_data_string() {
        init_python();
        Python::attach(|py| {
            let s = PyString::new(py, "hello=world");
            let result = DataParameter::extract(s.as_any().as_borrowed()).unwrap();
            assert_eq!(result, DataParameter::Raw(b"hello=world".to_vec()));
        });
    }

    #[test]
    fn test_data_bytes() {
        init_python();
        Python::attach(|py| {
            let b = PyBytes::new(py, b"\x00\x01\x02");
            let result = DataParameter::extract(b.as_any().as_borrowed()).unwrap();
            assert_eq!(result, DataParameter::Raw(vec![0, 1, 2]));
        });
    }

    #[test]
    fn test_data_list_of_tuples() {
        init_python();
        Python::attach(|py| {
            let list = py
                .eval(pyo3::ffi::c_str!("[('a', 'b'), ('c', 'd')]"), None, None)
                .unwrap();
            let result = DataParameter::extract(list.as_borrowed()).unwrap();
            assert_eq!(
                result,
                DataParameter::Form(vec![("a".into(), "b".into()), ("c".into(), "d".into()),])
            );
        });
    }

    #[test]
    fn test_data_invalid_type() {
        init_python();
        Python::attach(|py| {
            let i = PyInt::new(py, 42);
            let result = DataParameter::extract(i.as_any().as_borrowed());
            assert!(result.is_err());
            let err_str = result.unwrap_err().to_string();
            assert!(err_str.contains("data must be dict, string, or bytes"));
        });
    }

    // -- TimeoutParameter tests --

    #[test]
    fn test_timeout_float() {
        init_python();
        Python::attach(|py| {
            let f = PyFloat::new(py, 3.14);
            let result = TimeoutParameter::extract(f.as_any().as_borrowed()).unwrap();
            assert_eq!(result, TimeoutParameter::Single(3.14));
        });
    }

    #[test]
    fn test_timeout_int() {
        init_python();
        Python::attach(|py| {
            let i = PyInt::new(py, 5);
            let result = TimeoutParameter::extract(i.as_any().as_borrowed()).unwrap();
            assert_eq!(result, TimeoutParameter::Single(5.0));
        });
    }

    #[test]
    fn test_timeout_pair() {
        init_python();
        Python::attach(|py| {
            let t = PyTuple::new(py, &[3.0f64, 10.0f64]).unwrap();
            let result = TimeoutParameter::extract(t.as_any().as_borrowed()).unwrap();
            assert_eq!(result, TimeoutParameter::Pair(Some(3.0), Some(10.0)));
        });
    }

    #[test]
    fn test_timeout_pair_with_none_connect() {
        init_python();
        Python::attach(|py| {
            let t = py
                .eval(pyo3::ffi::c_str!("(None, 10.0)"), None, None)
                .unwrap();
            let result = TimeoutParameter::extract(t.as_borrowed()).unwrap();
            assert_eq!(result, TimeoutParameter::Pair(None, Some(10.0)));
        });
    }

    #[test]
    fn test_timeout_pair_with_none_read() {
        init_python();
        Python::attach(|py| {
            let t = py
                .eval(pyo3::ffi::c_str!("(5.0, None)"), None, None)
                .unwrap();
            let result = TimeoutParameter::extract(t.as_borrowed()).unwrap();
            assert_eq!(result, TimeoutParameter::Pair(Some(5.0), None));
        });
    }

    #[test]
    fn test_timeout_3_element_tuple() {
        init_python();
        Python::attach(|py| {
            let t = PyTuple::new(py, &[3.0f64, 4.0, 5.0]).unwrap();
            let result = TimeoutParameter::extract(t.as_any().as_borrowed());
            assert!(result.is_err());
            let err_str = result.unwrap_err().to_string();
            assert!(err_str.contains("(connect, read)"));
        });
    }

    #[test]
    fn test_timeout_1_element_tuple() {
        init_python();
        Python::attach(|py| {
            let t = py.eval(pyo3::ffi::c_str!("(5,)"), None, None).unwrap();
            let result = TimeoutParameter::extract(t.as_borrowed());
            assert!(result.is_err());
            let err_str = result.unwrap_err().to_string();
            assert!(err_str.contains("(connect, read)"));
        });
    }

    #[test]
    fn test_timeout_string_invalid() {
        init_python();
        Python::attach(|py| {
            let s = PyString::new(py, "foo");
            let result = TimeoutParameter::extract(s.as_any().as_borrowed());
            assert!(result.is_err());
            let err_str = result.unwrap_err().to_string();
            assert!(err_str.contains("must be an int, float or None"));
        });
    }

    // -- VerifyParameter tests --

    #[test]
    fn test_verify_true() {
        init_python();
        Python::attach(|py| {
            let b = py.eval(pyo3::ffi::c_str!("True"), None, None).unwrap();
            let result = VerifyParameter::extract(b.as_borrowed()).unwrap();
            assert_eq!(result, VerifyParameter::Bool(true));
        });
    }

    #[test]
    fn test_verify_false() {
        init_python();
        Python::attach(|py| {
            let b = py.eval(pyo3::ffi::c_str!("False"), None, None).unwrap();
            let result = VerifyParameter::extract(b.as_borrowed()).unwrap();
            assert_eq!(result, VerifyParameter::Bool(false));
        });
    }

    #[test]
    fn test_verify_string() {
        init_python();
        Python::attach(|py| {
            let s = PyString::new(py, "/path/to/ca-bundle.crt");
            let result = VerifyParameter::extract(s.as_any().as_borrowed()).unwrap();
            assert_eq!(
                result,
                VerifyParameter::CaBundle("/path/to/ca-bundle.crt".into())
            );
        });
    }

    // -- CertParameter tests --

    #[test]
    fn test_cert_single() {
        init_python();
        Python::attach(|py| {
            let s = PyString::new(py, "/path/to/cert.pem");
            let result = CertParameter::extract(s.as_any().as_borrowed()).unwrap();
            assert_eq!(result, CertParameter::Single("/path/to/cert.pem".into()));
        });
    }

    #[test]
    fn test_cert_pair() {
        init_python();
        Python::attach(|py| {
            let t = py
                .eval(
                    pyo3::ffi::c_str!("('/path/cert.pem', '/path/key.pem')"),
                    None,
                    None,
                )
                .unwrap();
            let result = CertParameter::extract(t.as_borrowed()).unwrap();
            assert_eq!(
                result,
                CertParameter::Pair("/path/cert.pem".into(), "/path/key.pem".into())
            );
        });
    }

    #[test]
    fn test_cert_invalid_type() {
        init_python();
        Python::attach(|py| {
            let i = PyInt::new(py, 42);
            let result = CertParameter::extract(i.as_any().as_borrowed());
            assert!(result.is_err());
        });
    }
}

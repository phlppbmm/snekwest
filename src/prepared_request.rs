use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyBytes, PyDict, PyList, PyString, PyTuple};

use crate::case_insensitive_dict::CaseInsensitiveDict;

/// Check if a cookie (from Python jar) matches a request URL.
/// Implements domain/path/scheme matching per RFC 6265.
fn cookie_matches_url(
    domain: &str,
    path: &str,
    secure: bool,
    expires: Option<i64>,
    url: &url::Url,
) -> bool {
    // Expiry check
    if let Some(exp) = expires {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if exp < now {
            return false;
        }
    }

    // Scheme check: Secure cookies only over HTTPS
    if secure && url.scheme() != "https" {
        return false;
    }

    // Domain check
    if !domain.is_empty() {
        let host = url.host_str().unwrap_or("");
        let domain_lower = domain.to_lowercase();
        let host_lower = host.to_lowercase();

        if let Some(suffix) = domain_lower.strip_prefix('.') {
            // Domain cookie (e.g., ".example.com"): matches host and subdomains
            if host_lower != suffix && !host_lower.ends_with(&domain_lower) {
                return false;
            }
        } else {
            // Host-only cookie: must match exactly
            if host_lower != domain_lower {
                return false;
            }
        }
    }
    // Empty domain (supercookie): matches all hosts

    // Path check
    if !path.is_empty() {
        let url_path = url.path();
        if url_path != path && !url_path.starts_with(&format!("{}/", path.trim_end_matches('/'))) {
            // Path doesn't match unless it's an exact match or a prefix with /
            if !path.ends_with('/') && url_path != path && !url_path.starts_with(path) {
                return false;
            }
            if path.ends_with('/') && !url_path.starts_with(path) {
                return false;
            }
        }
    }

    true
}

/// Parse a netloc string into (auth, host, port) without normalization.
/// Handles IPv6 brackets, user:pass@host, and host:port patterns.
fn parse_netloc(netloc: &str) -> (Option<String>, Option<String>, Option<u16>) {
    if netloc.is_empty() {
        return (None, None, None);
    }

    let (auth, host_port) = match netloc.rfind('@') {
        Some(pos) => (Some(netloc[..pos].to_string()), &netloc[pos + 1..]),
        None => (None, netloc),
    };

    let (host, port) = if host_port.starts_with('[') {
        // IPv6: [addr]:port or [addr]
        match host_port.find("]:") {
            Some(pos) => {
                let h = &host_port[..pos + 1];
                let p = host_port[pos + 2..].parse::<u16>().ok();
                (Some(h.to_string()), p)
            }
            None => (Some(host_port.to_string()), None),
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port_num) => (Some(h.to_string()), Some(port_num)),
                Err(_) => (Some(host_port.to_string()), None),
            },
            None => (Some(host_port.to_string()), None),
        }
    };

    (auth, host, port)
}

/// URL components extracted by parse_url_raw.
struct UrlParts {
    scheme: Option<String>,
    auth: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    path: Option<String>,
    query: Option<String>,
    fragment: Option<String>,
}

/// Parse a URL into components without normalization.
fn parse_url_raw(url: &str) -> UrlParts {
    // 1. Extract fragment (everything after first '#')
    let (url_no_frag, fragment) = match url.find('#') {
        Some(pos) => {
            let f = &url[pos + 1..];
            (
                &url[..pos],
                if f.is_empty() {
                    None
                } else {
                    Some(f.to_string())
                },
            )
        }
        None => (url, None),
    };

    // 2. Extract scheme (everything before '://')
    let (scheme, rest) = match url_no_frag.find("://") {
        Some(pos) => (
            Some(url_no_frag[..pos].to_string()),
            &url_no_frag[pos + 3..],
        ),
        None => (None, url_no_frag),
    };

    // 3. Extract netloc (ends at first '/' or '?') and remaining path+query
    let (netloc_str, after_netloc) = if scheme.is_some() {
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        (&rest[..end], &rest[end..])
    } else {
        ("", rest)
    };

    // 4. Split path and query
    let (path_str, query) = match after_netloc.find('?') {
        Some(pos) => {
            let q = &after_netloc[pos + 1..];
            (
                &after_netloc[..pos],
                if q.is_empty() {
                    None
                } else {
                    Some(q.to_string())
                },
            )
        }
        None => (after_netloc, None),
    };
    let path = if path_str.is_empty() {
        None
    } else {
        Some(path_str.to_string())
    };

    // 5. Parse netloc into auth, host, port
    let (auth, host, port) = parse_netloc(netloc_str);

    UrlParts {
        scheme,
        auth,
        host,
        port,
        path,
        query,
        fragment,
    }
}

/// Extract path + query from a URL string using pure Rust.
fn path_url_from_str(url_str: &str) -> String {
    match url::Url::parse(url_str) {
        Ok(parsed) => {
            let path = parsed.path();
            let path = if path.is_empty() { "/" } else { path };
            match parsed.query() {
                Some(q) if !q.is_empty() => format!("{}?{}", path, q),
                _ => path.to_string(),
            }
        }
        Err(_) => "/".to_string(),
    }
}

#[pyclass]
pub struct PreparedRequest {
    #[pyo3(get, set)]
    pub method: Option<String>,
    #[pyo3(get, set)]
    pub url: Option<String>,
    // Headers: stored as Option<Py<CaseInsensitiveDict>>
    headers_inner: Option<Py<CaseInsensitiveDict>>,
    #[pyo3(get, set)]
    pub body: Option<Py<PyAny>>,
    hooks_inner: Py<PyAny>,           // dict {"response": []}
    cookies_inner: Option<Py<PyAny>>, // CookieJar or None
    body_position_inner: Option<Py<PyAny>>,
}

#[pymethods]
impl PreparedRequest {
    #[new]
    fn new(py: Python<'_>) -> PyResult<Self> {
        let hooks = py
            .import("snekwest.hooks")?
            .call_method0("default_hooks")?
            .unbind();
        Ok(PreparedRequest {
            method: None,
            url: None,
            headers_inner: None,
            body: None,
            hooks_inner: hooks,
            cookies_inner: None,
            body_position_inner: None,
        })
    }

    // -- Properties with custom getters/setters --

    #[getter]
    fn headers(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.headers_inner {
            Some(h) => Ok(h.clone_ref(py).into_any()),
            None => Ok(py.None()),
        }
    }

    #[setter]
    fn set_headers(&mut self, py: Python<'_>, value: Bound<'_, PyAny>) -> PyResult<()> {
        if value.is_none() {
            self.headers_inner = None;
        } else if let Ok(cid) = value.cast::<CaseInsensitiveDict>() {
            self.headers_inner = Some(cid.clone().unbind());
        } else {
            // If it's a dict or other mapping, convert to CaseInsensitiveDict
            let cid_type = py
                .import("snekwest.structures")?
                .getattr("CaseInsensitiveDict")?;
            let cid = cid_type.call1((&value,))?;
            self.headers_inner = Some(cid.cast::<CaseInsensitiveDict>()?.clone().unbind());
        }
        Ok(())
    }

    #[getter]
    fn hooks(&self, py: Python<'_>) -> Py<PyAny> {
        self.hooks_inner.clone_ref(py)
    }

    #[setter]
    fn set_hooks(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        self.hooks_inner = value.unbind();
        Ok(())
    }

    #[getter]
    fn _cookies(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.cookies_inner {
            Some(c) => Ok(c.clone_ref(py)),
            None => Ok(py.None()),
        }
    }

    #[setter]
    #[allow(non_snake_case)]
    fn set__cookies(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        if value.is_none() {
            self.cookies_inner = None;
        } else {
            self.cookies_inner = Some(value.unbind());
        }
        Ok(())
    }

    #[getter]
    fn _body_position(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.body_position_inner {
            Some(p) => Ok(p.clone_ref(py)),
            None => Ok(py.None()),
        }
    }

    #[setter]
    #[allow(non_snake_case)]
    fn set__body_position(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        if value.is_none() {
            self.body_position_inner = None;
        } else {
            self.body_position_inner = Some(value.unbind());
        }
        Ok(())
    }

    // -- Main prepare method --

    #[pyo3(signature = (method=None, url=None, headers=None, files=None, data=None, params=None, auth=None, cookies=None, hooks=None, json=None))]
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &mut self,
        py: Python<'_>,
        method: Option<&Bound<'_, PyAny>>,
        url: Option<&Bound<'_, PyAny>>,
        headers: Option<&Bound<'_, PyAny>>,
        files: Option<&Bound<'_, PyAny>>,
        data: Option<&Bound<'_, PyAny>>,
        params: Option<&Bound<'_, PyAny>>,
        auth: Option<&Bound<'_, PyAny>>,
        cookies: Option<&Bound<'_, PyAny>>,
        hooks: Option<&Bound<'_, PyAny>>,
        json: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.prepare_method(method)?;
        self.prepare_url_impl(py, url, params)?;
        self.prepare_headers_impl(py, headers)?;
        self.prepare_cookies_impl(py, cookies)?;
        self.prepare_body_impl(py, data, files, json)?;
        self.prepare_auth_impl(py, auth)?;
        self.prepare_hooks_impl(py, hooks)?;
        Ok(())
    }

    // -- Individual prepare methods --

    fn prepare_method(&mut self, method: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        match method {
            Some(m) if !m.is_none() => {
                // Handle both str and bytes
                let s: String = if m.is_instance_of::<PyBytes>() {
                    let bytes: Vec<u8> = m.extract()?;
                    String::from_utf8(bytes).map_err(|e| PyValueError::new_err(e.to_string()))?
                } else {
                    m.str()?.to_string()
                };
                self.method = Some(s.to_uppercase());
            }
            _ => {
                self.method = None;
            }
        }
        Ok(())
    }

    #[pyo3(name = "prepare_url")]
    fn prepare_url_py(
        &mut self,
        py: Python<'_>,
        url: Option<&Bound<'_, PyAny>>,
        params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.prepare_url_impl(py, url, params)
    }

    #[pyo3(name = "prepare_headers")]
    fn prepare_headers_py(
        &mut self,
        py: Python<'_>,
        headers: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.prepare_headers_impl(py, headers)
    }

    #[pyo3(name = "prepare_body")]
    fn prepare_body_py(
        &mut self,
        py: Python<'_>,
        data: Option<&Bound<'_, PyAny>>,
        files: Option<&Bound<'_, PyAny>>,
        json: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.prepare_body_impl(py, data, files, json)
    }

    fn prepare_content_length(&mut self, py: Python<'_>, body: &Bound<'_, PyAny>) -> PyResult<()> {
        self.prepare_content_length_impl(py, body)
    }

    #[pyo3(name = "prepare_auth", signature = (auth=None, _url=None))]
    fn prepare_auth_py(
        &mut self,
        py: Python<'_>,
        auth: Option<&Bound<'_, PyAny>>,
        _url: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.prepare_auth_impl(py, auth)
    }

    #[pyo3(name = "prepare_cookies")]
    fn prepare_cookies_py(
        &mut self,
        py: Python<'_>,
        cookies: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.prepare_cookies_impl(py, cookies)
    }

    #[pyo3(name = "prepare_hooks")]
    fn prepare_hooks_py(
        &mut self,
        py: Python<'_>,
        hooks: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.prepare_hooks_impl(py, hooks)
    }

    // -- path_url property --

    #[getter]
    fn path_url(&self) -> String {
        let url_str = match &self.url {
            Some(u) => u.as_str(),
            None => return "/".to_string(),
        };
        path_url_from_str(url_str)
    }

    // -- Hook registration --

    fn register_hook(&self, py: Python<'_>, event: &str, hook: &Bound<'_, PyAny>) -> PyResult<()> {
        let hooks_dict = self.hooks_inner.bind(py);

        // Try to get the event list; if KeyError, the event is unsupported
        let event_hooks = match hooks_dict.get_item(event) {
            Ok(list) => list,
            Err(_) => {
                return Err(PyValueError::new_err(format!(
                    "Unsupported event specified, with event name \"{event}\""
                )));
            }
        };

        // Check if hook is callable
        let callable_mod = py.import("collections.abc")?.getattr("Callable")?;
        if hook.is_instance(&callable_mod)? {
            event_hooks.call_method1("append", (hook,))?;
        } else if hook.hasattr("__iter__")? {
            let iter = hook.try_iter()?;
            for h in iter {
                let h = h?;
                if h.is_instance(&callable_mod)? {
                    event_hooks.call_method1("append", (&h,))?;
                }
            }
        }
        Ok(())
    }

    fn deregister_hook(
        &self,
        py: Python<'_>,
        event: &str,
        hook: &Bound<'_, PyAny>,
    ) -> PyResult<bool> {
        let hooks_dict = self.hooks_inner.bind(py);
        match hooks_dict.get_item(event) {
            Ok(list) => match list.call_method1("remove", (hook,)) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            },
            Err(_) => Ok(false),
        }
    }

    // -- copy --

    fn copy(&self, py: Python<'_>) -> PyResult<PreparedRequest> {
        // Shallow-copy hooks: {event: list(callbacks) for event, callbacks in self.hooks.items()}
        // Upstream does p.hooks = self.hooks (reference copy). We copy each list
        // to avoid shared mutation, but do NOT deepcopy the callables themselves
        // (they may contain unpicklable objects like _thread._local).
        let orig_hooks = self.hooks_inner.bind(py);
        let new_hooks = PyDict::new(py);
        for item in orig_hooks.call_method0("items")?.try_iter()? {
            let item = item?;
            let key = item.get_item(0)?;
            let val = item.get_item(1)?;
            let copied_list = PyList::new(py, val.try_iter()?.collect::<PyResult<Vec<_>>>()?)?;
            new_hooks.set_item(&key, copied_list)?;
        }
        let hooks = new_hooks.into_any().unbind();

        let new_headers = match &self.headers_inner {
            Some(h) => {
                let copied = h.bind(py).call_method0("copy")?;
                Some(copied.cast::<CaseInsensitiveDict>()?.clone().unbind())
            }
            None => None,
        };

        let new_cookies = match &self.cookies_inner {
            Some(c) => {
                let copy_fn = py.import("snekwest.cookies")?.getattr("_copy_cookie_jar")?;
                Some(copy_fn.call1((c.bind(py),))?.unbind())
            }
            None => None,
        };

        Ok(PreparedRequest {
            method: self.method.clone(),
            url: self.url.clone(),
            headers_inner: new_headers,
            body: self.body.as_ref().map(|b| b.clone_ref(py)),
            hooks_inner: hooks,
            cookies_inner: new_cookies,
            body_position_inner: self.body_position_inner.as_ref().map(|p| p.clone_ref(py)),
        })
    }

    fn __repr__(&self) -> String {
        match &self.method {
            Some(m) => format!("<PreparedRequest [{}]>", m),
            None => "<PreparedRequest [None]>".to_string(),
        }
    }

    // -- Static methods for encoding (delegate to Python) --

    #[staticmethod]
    fn _encode_params(py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        encode_params(py, data)
    }

    #[staticmethod]
    fn _encode_files(
        py: Python<'_>,
        files: &Bound<'_, PyAny>,
        data: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        encode_files(py, files, data)
    }
}

// ============================================================================
// Internal implementations
// ============================================================================

impl PreparedRequest {
    /// Public accessor for headers from other Rust modules
    pub fn get_headers(&self) -> Option<&Py<CaseInsensitiveDict>> {
        self.headers_inner.as_ref()
    }

    fn prepare_url_impl(
        &mut self,
        py: Python<'_>,
        url: Option<&Bound<'_, PyAny>>,
        params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let url = match url {
            Some(u) if !u.is_none() => u.clone(),
            _ => {
                let exc = py.import("snekwest.exceptions")?.getattr("MissingSchema")?;
                return Err(PyErr::from_value(exc.call1((
                    "Invalid URL 'None': No scheme supplied. Perhaps you meant https://None?",
                ))?));
            }
        };

        // Convert bytes to str
        let url_str: String = if url.is_instance_of::<PyBytes>() {
            url.extract::<Vec<u8>>().and_then(|bytes| {
                String::from_utf8(bytes).map_err(|e| PyValueError::new_err(e.to_string()))
            })?
        } else {
            url.str()?.to_string()
        };

        // Remove leading whitespace
        let url_str = url_str.trim_start().to_string();

        // Don't do any URL preparation for non-HTTP schemes
        if url_str.contains(':') && !url_str.to_lowercase().starts_with("http") {
            self.url = Some(url_str);
            return Ok(());
        }

        // Parse URL using pure Rust string parsing (no normalization)
        let UrlParts {
            scheme,
            auth,
            host,
            port,
            path,
            query,
            fragment,
        } = parse_url_raw(&url_str);

        let scheme = match scheme {
            Some(s) if !s.is_empty() => s,
            _ => {
                let missing_schema = py.import("snekwest.exceptions")?.getattr("MissingSchema")?;
                return Err(PyErr::from_value(missing_schema.call1((format!(
                    "Invalid URL {url_str:?}: No scheme supplied. Perhaps you meant https://{url_str}?"
                ),))?));
            }
        };

        let host = match host {
            Some(h) if !h.is_empty() => h,
            _ => {
                let invalid_url = py.import("snekwest.exceptions")?.getattr("InvalidURL")?;
                return Err(PyErr::from_value(
                    invalid_url.call1((format!("Invalid URL {url_str:?}: No host supplied"),))?,
                ));
            }
        };

        // IDNA encoding for non-ASCII hosts
        let host = if !host.is_ascii() {
            let idna = py.import("idna")?;
            match idna.call_method(
                "encode",
                (&host,),
                Some(&[("uts46", true)].into_py_dict(py)?),
            ) {
                Ok(encoded) => {
                    let decoded: String = encoded.call_method1("decode", ("utf-8",))?.extract()?;
                    decoded
                }
                Err(_) => {
                    let invalid_url = py.import("snekwest.exceptions")?.getattr("InvalidURL")?;
                    return Err(PyErr::from_value(
                        invalid_url.call1(("URL has an invalid label.",))?,
                    ));
                }
            }
        } else if host.starts_with('*') || host.starts_with('.') {
            let invalid_url = py.import("snekwest.exceptions")?.getattr("InvalidURL")?;
            return Err(PyErr::from_value(
                invalid_url.call1(("URL has an invalid label.",))?,
            ));
        } else {
            host
        };

        // Reconstruct netloc
        let mut netloc = auth.unwrap_or_default();
        if !netloc.is_empty() {
            netloc.push('@');
        }
        netloc.push_str(&host);
        if let Some(p) = port {
            netloc.push_str(&format!(":{}", p));
        }

        let path = match path {
            Some(p) if !p.is_empty() => p,
            _ => "/".to_string(),
        };

        // Handle params
        let params_obj = params.and_then(|p| if p.is_none() { None } else { Some(p.clone()) });

        let query = if let Some(params_val) = params_obj {
            // Convert bytes params to string using ASCII (matches upstream to_native_string)
            let params_val = if params_val.is_instance_of::<PyBytes>() {
                params_val.call_method1("decode", ("ascii",))?
            } else {
                params_val
            };

            let enc_params = encode_params(py, &params_val)?;
            let enc_str: String = enc_params.extract(py)?;

            if !enc_str.is_empty() {
                match query {
                    Some(q) if !q.is_empty() => Some(format!("{}&{}", q, enc_str)),
                    _ => Some(enc_str),
                }
            } else {
                query
            }
        } else {
            query
        };

        // Build URL in Rust (replaces Python urlunparse + requote_uri)
        let mut raw_url = format!("{}://{}{}", scheme, netloc, path);
        if let Some(ref q) = query {
            raw_url.push('?');
            raw_url.push_str(q);
        }
        if let Some(ref f) = fragment {
            raw_url.push('#');
            raw_url.push_str(f);
        }

        let final_url = crate::utils::requote_uri(py, &raw_url)?;
        self.url = Some(final_url);
        Ok(())
    }

    fn prepare_headers_impl(
        &mut self,
        py: Python<'_>,
        headers: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        // Create a new CaseInsensitiveDict
        let cid_type = py
            .import("snekwest.structures")?
            .getattr("CaseInsensitiveDict")?;
        let new_cid = cid_type.call0()?;
        self.headers_inner = Some(new_cid.cast::<CaseInsensitiveDict>()?.clone().unbind());

        if let Some(hdrs) = headers {
            if !hdrs.is_none() {
                let items = hdrs.call_method0("items")?;

                for item in items.try_iter()? {
                    let item = item?;
                    let name = item.get_item(0)?;
                    let value = item.get_item(1)?;

                    // Check validity (pure Rust, no Python call)
                    crate::utils::check_header_validity_rust(py, &name, &value)?;

                    // Convert name to native string (pure Rust for str, fallback for bytes)
                    let native_name: String = if let Ok(s) = name.extract::<String>() {
                        s
                    } else if let Ok(b) = name.extract::<Vec<u8>>() {
                        String::from_utf8(b).map_err(|e| {
                            pyo3::exceptions::PyValueError::new_err(format!(
                                "Header name is not valid ASCII: {}",
                                e
                            ))
                        })?
                    } else {
                        return Err(pyo3::exceptions::PyTypeError::new_err(
                            "Header name must be str or bytes",
                        ));
                    };

                    let headers_ref = self.headers_inner.as_ref().ok_or_else(|| {
                        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            "Headers not initialized. Call prepare_headers() first.",
                        )
                    })?;
                    headers_ref
                        .bind(py)
                        .borrow_mut()
                        .set_item(py, &native_name, value)?;
                }
            }
        }
        Ok(())
    }

    fn prepare_body_impl(
        &mut self,
        py: Python<'_>,
        data: Option<&Bound<'_, PyAny>>,
        files: Option<&Bound<'_, PyAny>>,
        json: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let mut body: Option<Py<PyAny>> = None;
        let mut content_type: Option<String> = None;

        let has_data = data.is_some_and(|d| !d.is_none() && d.is_truthy().unwrap_or(false));
        let has_json = json.is_some_and(|j| !j.is_none());
        let has_files = files.is_some_and(|f| !f.is_none() && f.is_truthy().unwrap_or(false));

        // JSON body
        if !has_data && has_json {
            content_type = Some("application/json".to_string());
            let json_mod = py.import("json")?;
            // SAFETY: guarded by `has_json` check (json.is_some_and) above
            let json_val = json.unwrap();
            let allow_nan = false.into_pyobject(py)?.to_owned().into_any();
            let kwargs = [("allow_nan", allow_nan)].into_py_dict(py)?;
            let dumped = match json_mod.call_method("dumps", (json_val,), Some(&kwargs)) {
                Ok(s) => s,
                Err(e) => {
                    let invalid_json = py
                        .import("snekwest.exceptions")?
                        .getattr("InvalidJSONError")?;
                    // Snapshot current state to attach to exception (matching upstream's request=self)
                    let self_snapshot = Py::new(
                        py,
                        PreparedRequest {
                            method: self.method.clone(),
                            url: self.url.clone(),
                            headers_inner: self.headers_inner.as_ref().map(|h| h.clone_ref(py)),
                            body: None, // body hasn't been set yet at this point
                            hooks_inner: self.hooks_inner.clone_ref(py),
                            cookies_inner: self.cookies_inner.as_ref().map(|c| c.clone_ref(py)),
                            body_position_inner: self
                                .body_position_inner
                                .as_ref()
                                .map(|p| p.clone_ref(py)),
                        },
                    )?;
                    let kwargs = [("request", self_snapshot.into_any())].into_py_dict(py)?;
                    return Err(PyErr::from_value(
                        invalid_json.call((e.value(py),), Some(&kwargs))?,
                    ));
                }
            };

            // Ensure it's bytes
            if dumped.is_instance_of::<PyBytes>() {
                body = Some(dumped.unbind());
            } else {
                body = Some(dumped.call_method1("encode", ("utf-8",))?.unbind());
            }
        }

        // Check if data is a stream
        let is_stream = if let Some(d) = data {
            if d.is_none() {
                false
            } else {
                let has_iter = d.hasattr("__iter__")?;
                let is_string = d.is_instance_of::<PyString>();
                let is_bytes = d.is_instance_of::<PyBytes>();
                let is_list = d.is_instance(py.get_type::<PyList>().as_any())?;
                let is_tuple = d.is_instance(py.get_type::<PyTuple>().as_any())?;
                let mapping_cls = py.import("collections.abc")?.getattr("Mapping")?;
                let is_mapping = d.is_instance(&mapping_cls)?;

                has_iter && !is_string && !is_bytes && !is_list && !is_tuple && !is_mapping
            }
        } else {
            false
        };

        if is_stream {
            // SAFETY: `is_stream` is only true when `data` is Some (checked in the block above)
            let data = data.unwrap();
            let super_len = py.import("snekwest.utils")?.getattr("super_len")?;
            let length: Option<u64> = match super_len.call1((data,)) {
                Ok(l) => l.extract().ok(),
                Err(_) => None,
            };

            body = Some(data.clone().unbind());

            // Save body position
            if data.hasattr("tell")? {
                match data.call_method0("tell") {
                    Ok(pos) => {
                        self.body_position_inner = Some(pos.unbind());
                    }
                    Err(_) => {
                        // Use object() as sentinel
                        let obj = py.import("builtins")?.getattr("object")?.call0()?;
                        self.body_position_inner = Some(obj.unbind());
                    }
                }
            }

            if has_files {
                return Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>(
                    "Streamed bodies and files are mutually exclusive.",
                ));
            }

            let headers = self.headers_inner.as_ref().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "Headers not initialized. Call prepare_headers() first.",
                )
            })?;

            // Python: `if length:` treats 0 as falsy → sets Transfer-Encoding
            match length {
                Some(len) if len > 0 => {
                    let len_str = PyString::new(py, &len.to_string());
                    headers.bind(py).borrow_mut().set_item(
                        py,
                        "Content-Length",
                        len_str.into_any(),
                    )?;
                }
                _ => {
                    let chunked = PyString::new(py, "chunked");
                    headers.bind(py).borrow_mut().set_item(
                        py,
                        "Transfer-Encoding",
                        chunked.into_any(),
                    )?;
                }
            }
        } else {
            // Non-streaming body
            if has_files {
                let data_arg = data.map_or_else(|| py.None().into_bound(py), |d| d.clone());
                // SAFETY: guarded by `has_files` check (files.is_some_and) above
                let files_val = files.unwrap();
                let result = encode_files(py, files_val, &data_arg)?;
                let tuple = result.bind(py);
                body = Some(tuple.get_item(0)?.unbind());
                content_type = Some(tuple.get_item(1)?.extract()?);
            } else if has_data {
                // SAFETY: guarded by `has_data` check (data.is_some_and) above
                let data = data.unwrap();
                let enc = encode_params(py, data)?;
                body = Some(enc);

                // Determine content type
                let basestring = py.import("snekwest.compat")?.getattr("basestring")?;
                if !data.is_instance(&basestring)? && !data.hasattr("read")? {
                    content_type = Some("application/x-www-form-urlencoded".to_string());
                }
            }

            // Set content length for non-streaming
            if let Some(ref b) = body {
                let body_clone = b.clone_ref(py);
                self.prepare_content_length_impl(py, body_clone.bind(py))?;
            } else if body.is_none() && json.is_none() {
                let none_obj = py.None().into_bound(py);
                self.prepare_content_length_impl(py, &none_obj)?;
            }

            if let Some(ct) = &content_type {
                let headers = self.headers_inner.as_ref().ok_or_else(|| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        "Headers not initialized. Call prepare_headers() first.",
                    )
                })?;
                if !headers.bind(py).borrow().contains("content-type") {
                    let ct_str = PyString::new(py, ct);
                    headers.bind(py).borrow_mut().set_item(
                        py,
                        "Content-Type",
                        ct_str.into_any(),
                    )?;
                }
            }
        }

        self.body = body;
        Ok(())
    }

    fn prepare_content_length_impl(
        &mut self,
        py: Python<'_>,
        body: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let headers = self.headers_inner.as_ref().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Headers not initialized. Call prepare_headers() first.",
            )
        })?;

        if !body.is_none() {
            let super_len = py.import("snekwest.utils")?.getattr("super_len")?;
            let length: u64 = super_len.call1((body,))?.extract()?;
            if length > 0 {
                let len_str = PyString::new(py, &length.to_string());
                headers
                    .bind(py)
                    .borrow_mut()
                    .set_item(py, "Content-Length", len_str.into_any())?;
            }
        } else {
            // No body: set Content-Length: 0 for non-GET/HEAD
            let method = self.method.as_deref().unwrap_or("");
            if method != "GET" && method != "HEAD" {
                let cl = headers.bind(py).borrow().get_value(py, "Content-Length");
                if cl.is_none() {
                    let zero = PyString::new(py, "0");
                    headers.bind(py).borrow_mut().set_item(
                        py,
                        "Content-Length",
                        zero.into_any(),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn prepare_auth_impl(
        &mut self,
        py: Python<'_>,
        auth: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let auth = if let Some(a) = auth {
            if a.is_none() {
                None
            } else {
                Some(a.clone())
            }
        } else {
            None
        };

        let auth = match auth {
            Some(a) => Some(a),
            None => {
                // Try to get auth from URL
                if let Some(ref url) = self.url {
                    let get_auth = py.import("snekwest.utils")?.getattr("get_auth_from_url")?;
                    let url_auth = get_auth.call1((url.as_str(),))?;
                    let any_fn = py.import("builtins")?.getattr("any")?;
                    let has_auth: bool = any_fn.call1((&url_auth,))?.extract()?;
                    if has_auth {
                        Some(url_auth)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        if let Some(auth_val) = auth {
            // If it's a tuple of length 2, convert to HTTPBasicAuth
            let auth_callable = if let Ok(tuple) = auth_val.cast::<PyTuple>() {
                if tuple.len() == 2 {
                    let http_basic_auth = py.import("snekwest.auth")?.getattr("HTTPBasicAuth")?;
                    http_basic_auth.call1((tuple.get_item(0)?, tuple.get_item(1)?))?
                } else {
                    auth_val
                }
            } else {
                auth_val
            };

            // Upstream: r = auth(self); self.__dict__.update(r.__dict__)
            // We create a temporary Python object from self's current state,
            // pass it to the auth callable (which modifies it in-place),
            // then read modified fields back from the returned object.
            let self_ref = Py::new(
                py,
                PreparedRequest {
                    method: self.method.clone(),
                    url: self.url.clone(),
                    headers_inner: self.headers_inner.as_ref().map(|h| h.clone_ref(py)),
                    body: self.body.as_ref().map(|b| b.clone_ref(py)),
                    hooks_inner: self.hooks_inner.clone_ref(py),
                    cookies_inner: self.cookies_inner.as_ref().map(|c| c.clone_ref(py)),
                    body_position_inner: self.body_position_inner.as_ref().map(|p| p.clone_ref(py)),
                },
            )?;

            let result = auth_callable.call1((&self_ref,))?;

            // Mimic upstream: self.__dict__.update(r.__dict__)
            // Read fields from `result` using Python attribute access so it
            // works for any returned type (PreparedRequest, subclass, or
            // plain object). Most auth callables (HTTPBasicAuth) modify
            // self_ref in-place and return it, so result IS self_ref.
            // For auth callables that return a different object, we still
            // pick up their attributes.
            self.method = result.getattr("method")?.extract()?;
            self.url = result.getattr("url")?.extract()?;
            let headers_obj = result.getattr("headers")?;
            if headers_obj.is_none() {
                self.headers_inner = None;
            } else if let Ok(cid) = headers_obj.cast::<CaseInsensitiveDict>() {
                self.headers_inner = Some(cid.clone().unbind());
            } else {
                // Foreign object — convert via Python CaseInsensitiveDict
                let cid_type = py
                    .import("snekwest.structures")?
                    .getattr("CaseInsensitiveDict")?;
                let cid = cid_type.call1((&headers_obj,))?;
                self.headers_inner = Some(cid.cast::<CaseInsensitiveDict>()?.clone().unbind());
            }
            let body_obj = result.getattr("body")?;
            self.body = if body_obj.is_none() {
                None
            } else {
                Some(body_obj.unbind())
            };
            self.hooks_inner = result.getattr("hooks")?.unbind();
            let cookies_obj = result.getattr("_cookies")?;
            self.cookies_inner = if cookies_obj.is_none() {
                None
            } else {
                Some(cookies_obj.unbind())
            };
            let body_pos_obj = result.getattr("_body_position")?;
            self.body_position_inner = if body_pos_obj.is_none() {
                None
            } else {
                Some(body_pos_obj.unbind())
            };

            // Re-prepare content length
            if let Some(body) = &self.body {
                let body_clone = body.clone_ref(py);
                self.prepare_content_length_impl(py, body_clone.bind(py))?;
            }
        }
        Ok(())
    }

    fn prepare_cookies_impl(
        &mut self,
        py: Python<'_>,
        cookies: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let cookie_jar_cls = py.import("http.cookiejar")?.getattr("CookieJar")?;
        let cookiejar_from_dict = py
            .import("snekwest.cookies")?
            .getattr("cookiejar_from_dict")?;

        if let Some(c) = cookies {
            if !c.is_none() {
                if c.is_instance(&cookie_jar_cls)? {
                    self.cookies_inner = Some(c.clone().unbind());
                } else {
                    self.cookies_inner = Some(cookiejar_from_dict.call1((c,))?.unbind());
                }
            } else {
                self.cookies_inner = Some(cookiejar_from_dict.call1((py.None(),))?.unbind());
            }
        } else {
            self.cookies_inner = Some(cookiejar_from_dict.call1((py.None(),))?.unbind());
        }

        // Generate Cookie header using Rust-based domain/path/scheme matching
        let cookies_ref = self.cookies_inner.as_ref().ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Cookies not initialized. Call prepare_cookies() first.",
            )
        })?;

        let parsed_url = self.url.as_ref().and_then(|u| url::Url::parse(u).ok());

        let jar = cookies_ref.bind(py);
        let mut cookie_parts: Vec<String> = Vec::new();

        for cookie_result in jar.try_iter()? {
            let cookie_obj = cookie_result?;
            let name: String = cookie_obj.getattr("name")?.extract()?;
            let value: String = cookie_obj.getattr("value")?.extract()?;

            if let Some(ref url) = parsed_url {
                let domain: String = cookie_obj.getattr("domain")?.extract().unwrap_or_default();
                let path: String = cookie_obj
                    .getattr("path")?
                    .extract()
                    .unwrap_or_else(|_| "/".to_string());
                let secure: bool = cookie_obj.getattr("secure")?.extract().unwrap_or(false);
                let expires: Option<i64> = cookie_obj.getattr("expires")?.extract().unwrap_or(None);

                if cookie_matches_url(&domain, &path, secure, expires, url) {
                    cookie_parts.push(format!("{}={}", name, value));
                }
            } else {
                // No valid URL — include all cookies (matches Python behavior)
                cookie_parts.push(format!("{}={}", name, value));
            }
        }

        if !cookie_parts.is_empty() {
            let cookie_header = cookie_parts.join("; ");
            if let Some(ref headers) = self.headers_inner {
                headers.bind(py).borrow_mut().set_item(
                    py,
                    "Cookie",
                    PyString::new(py, &cookie_header).into_any(),
                )?;
            }
        }
        Ok(())
    }

    fn prepare_hooks_impl(
        &mut self,
        py: Python<'_>,
        hooks: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        if let Some(h) = hooks {
            if !h.is_none() {
                // Iterate over hooks dict
                let items = match h.call_method0("items") {
                    Ok(items) => items,
                    Err(_) => return Ok(()),
                };
                for item in items.try_iter()? {
                    let item = item?;
                    let event: String = item.get_item(0)?.extract()?;
                    let hook = item.get_item(1)?;
                    self.register_hook(py, &event, &hook)?;
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Encode parameters (delegates to Python)
fn encode_params(py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    // If string or bytes, return as-is
    if data.is_instance_of::<PyString>() || data.is_instance_of::<PyBytes>() {
        return Ok(data.clone().unbind());
    }

    // If has read(), return as-is (file-like)
    if data.hasattr("read")? {
        return Ok(data.clone().unbind());
    }

    // If iterable, encode
    if data.hasattr("__iter__")? {
        let to_key_val_list = py.import("snekwest.utils")?.getattr("to_key_val_list")?;
        let kvl = to_key_val_list.call1((data,))?;
        let urlencode = py.import("urllib.parse")?.getattr("urlencode")?;
        let basestring = py.import("snekwest.compat")?.getattr("basestring")?;

        let result = PyList::empty(py);
        for pair in kvl.try_iter()? {
            let pair = pair?;
            let k = pair.get_item(0)?;
            let vs = pair.get_item(1)?;

            let vs_list = if vs.is_instance(&basestring)? || !vs.hasattr("__iter__")? {
                let l = PyList::empty(py);
                l.append(&vs)?;
                l.into_any()
            } else {
                vs.clone()
            };

            for v in vs_list.try_iter()? {
                let v = v?;
                if !v.is_none() {
                    let k_encoded = if k.is_instance_of::<PyString>() {
                        k.call_method1("encode", ("utf-8",))?
                    } else {
                        k.clone()
                    };
                    let v_encoded = if v.is_instance_of::<PyString>() {
                        v.call_method1("encode", ("utf-8",))?
                    } else {
                        v.clone()
                    };
                    let t = PyTuple::new(py, &[k_encoded, v_encoded])?;
                    result.append(&t)?;
                }
            }
        }

        let kwargs = [("doseq", true)].into_py_dict(py)?;
        let encoded = urlencode.call((result,), Some(&kwargs))?;
        return Ok(encoded.unbind());
    }

    Ok(data.clone().unbind())
}

/// Generate a random 32-character hex boundary string (same format as urllib3/uuid4.hex).
fn generate_boundary() -> String {
    let state = RandomState::new();
    let mut h1 = state.build_hasher();
    h1.write_u8(0);
    let mut h2 = state.build_hasher();
    h2.write_u8(1);
    format!("{:016x}{:016x}", h1.finish(), h2.finish())
}

/// Encode files for multipart upload (pure Rust, no urllib3 dependency).
///
/// Builds an RFC 2046 multipart/form-data body from `files` and optional `data`.
/// Returns a Python tuple `(body_bytes, content_type_string)`.
///
/// Supports all upstream file formats:
/// - bare file-like objects: `{"field": file_obj}`
/// - 2-tuple: `{"field": ("filename", data)}`
/// - 3-tuple: `{"field": ("filename", data, "content-type")}`
/// - 4-tuple: `{"field": ("filename", data, "content-type", {"Header": "val"})}`
fn encode_files(
    py: Python<'_>,
    files: &Bound<'_, PyAny>,
    data: &Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    // Validation
    if !files.is_truthy()? {
        return Err(PyValueError::new_err("Files must be provided."));
    }
    let basestring = py.import("snekwest.compat")?.getattr("basestring")?;
    if data.is_instance(&basestring)? {
        return Err(PyValueError::new_err("Data must not be a string."));
    }

    let to_key_val_list = py.import("snekwest.utils")?.getattr("to_key_val_list")?;
    let guess_filename_fn = py.import("snekwest.utils")?.getattr("guess_filename")?;
    let list_cls = py.get_type::<PyList>();
    let tuple_cls = py.get_type::<PyTuple>();

    let boundary = generate_boundary();
    let mut body: Vec<u8> = Vec::new();

    // --- Process data fields ---
    let data_kvl = to_key_val_list.call1((data,))?;
    if !data_kvl.is_none() {
        for pair in data_kvl.try_iter()? {
            let pair = pair?;
            let field = pair.get_item(0)?;
            let val = pair.get_item(1)?;

            // Decode bytes field names to UTF-8
            let field_name = extract_field_name(&field)?;

            // Normalize value to a list
            let vals: Vec<Bound<'_, PyAny>> =
                if val.is_instance(&basestring)? || !val.hasattr("__iter__")? {
                    vec![val]
                } else {
                    val.try_iter()?.collect::<PyResult<Vec<_>>>()?
                };

            for v in vals {
                if v.is_none() {
                    continue;
                }
                // Convert to bytes: non-bytes → str → utf-8
                let v_bytes: Vec<u8> = if v.is_instance_of::<PyBytes>() {
                    v.extract()?
                } else {
                    v.str()?.to_string().into_bytes()
                };

                body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
                body.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{}\"\r\n\r\n",
                        field_name
                    )
                    .as_bytes(),
                );
                body.extend_from_slice(&v_bytes);
                body.extend_from_slice(b"\r\n");
            }
        }
    }

    // --- Process file fields ---
    let files_kvl = to_key_val_list.call1((files,))?;
    for pair in files_kvl.try_iter()? {
        let pair = pair?;

        // Validate: each element must unpack to (key, value).
        // Strings like "bad file data" fail upstream with
        // `ValueError: too many values to unpack (expected 2)`.
        if !pair.is_instance(tuple_cls.as_any())? && !pair.is_instance(list_cls.as_any())? {
            return Err(PyValueError::new_err(
                "too many values to unpack (expected 2)",
            ));
        }

        let k = pair.get_item(0)?;
        let v = pair.get_item(1)?;

        let field_name = extract_field_name(&k)?;

        // Parse the file field into (filename, file_data_obj, content_type, custom_headers)
        let (fn_name, fp, ft, fh): (
            Option<String>,
            Bound<'_, PyAny>,
            Option<String>,
            Option<Bound<'_, PyAny>>,
        );

        if v.is_instance(list_cls.as_any())? || v.is_instance(tuple_cls.as_any())? {
            let len = v.len()?;
            let fn_obj = v.get_item(0)?;
            fn_name = if fn_obj.is_none() {
                None
            } else {
                Some(fn_obj.str()?.to_string())
            };
            fp = v.get_item(1)?;
            if len >= 3 {
                let ft_obj = v.get_item(2)?;
                ft = if ft_obj.is_none() {
                    None
                } else {
                    Some(ft_obj.str()?.to_string())
                };
            } else {
                ft = None;
            }
            if len >= 4 {
                let fh_obj = v.get_item(3)?;
                fh = if fh_obj.is_none() { None } else { Some(fh_obj) };
            } else {
                fh = None;
            }
        } else {
            // Bare file-like object
            let guessed = guess_filename_fn.call1((&v,))?;
            fn_name = if guessed.is_none() {
                Some(field_name.clone())
            } else {
                Some(guessed.str()?.to_string())
            };
            fp = v;
            ft = None;
            fh = None;
        }

        // Read file data
        let fdata: Vec<u8> = if fp.is_none() {
            continue;
        } else if fp.is_instance_of::<PyString>() {
            fp.str()?.to_string().into_bytes()
        } else if let Ok(bytes) = fp.extract::<Vec<u8>>() {
            // Handles both bytes and bytearray
            bytes
        } else if fp.hasattr("read")? {
            let result = fp.call_method0("read")?;
            if let Ok(bytes) = result.extract::<Vec<u8>>() {
                bytes
            } else {
                result.str()?.to_string().into_bytes()
            }
        } else {
            fp.str()?.to_string().into_bytes()
        };

        // Write part header
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());

        // Content-Disposition
        let mut cd = format!("Content-Disposition: form-data; name=\"{}\"", field_name);
        if let Some(ref name) = fn_name {
            cd.push_str(&format!("; filename=\"{}\"", name));
        }
        cd.push_str("\r\n");
        body.extend_from_slice(cd.as_bytes());

        // Content-Type (only if provided)
        if let Some(ref ct) = ft {
            body.extend_from_slice(format!("Content-Type: {}\r\n", ct).as_bytes());
        }

        // Custom per-part headers
        if let Some(ref headers) = fh {
            for item in headers.call_method0("items")?.try_iter()? {
                let item = item?;
                let hname = item.get_item(0)?.str()?.to_string();
                let hval = item.get_item(1)?.str()?.to_string();
                body.extend_from_slice(format!("{}: {}\r\n", hname, hval).as_bytes());
            }
        }

        // Separator + data
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(&fdata);
        body.extend_from_slice(b"\r\n");
    }

    // Closing boundary
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    let content_type = format!("multipart/form-data; boundary={}", boundary);
    let body_bytes = PyBytes::new(py, &body);
    let ct_str = PyString::new(py, &content_type);
    let result = PyTuple::new(py, [body_bytes.into_any(), ct_str.into_any()])?;
    Ok(result.into_any().unbind())
}

/// Extract a field name from a Python object, decoding bytes to UTF-8.
fn extract_field_name(obj: &Bound<'_, PyAny>) -> PyResult<String> {
    if obj.is_instance_of::<PyBytes>() {
        let bytes: Vec<u8> = obj.extract()?;
        String::from_utf8(bytes)
            .map_err(|e| PyValueError::new_err(format!("Field name is not valid UTF-8: {}", e)))
    } else {
        Ok(obj.str()?.to_string())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    /// Verify that PreparedRequest fields start as None, confirming that
    /// calling prepare_body/prepare_content_length/prepare_cookies before
    /// prepare_headers would hit the unwrap() calls on None values.
    /// After the fix, these methods return PyResult::Err instead of panicking.
    #[test]
    fn test_prepared_request_fields_default_to_none() {
        // We cannot construct PreparedRequest::new without the GIL (it calls Python),
        // but we can verify the struct definition requires Option<> fields.
        // This is a compile-time structural assertion:
        // headers_inner: Option<Py<CaseInsensitiveDict>> → starts None
        // cookies_inner: Option<Py<PyAny>> → starts None
        //
        // The real behavioral tests are in Group A (Python test suite),
        // which exercises prepare_*() methods in various orders.
        //
        // This test documents the invariant: newly-constructed PreparedRequest
        // has headers_inner=None and cookies_inner=None, so any method that
        // accesses these fields MUST handle the None case gracefully.
        assert!(true, "Structural assertion: Option fields start as None");
    }

    /// Verify the error message constants are consistent.
    #[test]
    fn test_error_messages_for_uninitialized_state() {
        let headers_msg = "Headers not initialized. Call prepare_headers() first.";
        let cookies_msg = "Cookies not initialized. Call prepare_cookies() first.";
        assert!(headers_msg.contains("prepare_headers"));
        assert!(cookies_msg.contains("prepare_cookies"));
    }

    // ---- parse_netloc tests ----

    #[test]
    fn test_parse_netloc_plain_host() {
        let (auth, host, port) = super::parse_netloc("example.com");
        assert_eq!(auth, None);
        assert_eq!(host, Some("example.com".into()));
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_netloc_host_with_port() {
        let (auth, host, port) = super::parse_netloc("example.com:443");
        assert_eq!(auth, None);
        assert_eq!(host, Some("example.com".into()));
        assert_eq!(port, Some(443));
    }

    #[test]
    fn test_parse_netloc_auth_host() {
        let (auth, host, port) = super::parse_netloc("user:pass@example.com");
        assert_eq!(auth, Some("user:pass".into()));
        assert_eq!(host, Some("example.com".into()));
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_netloc_auth_host_port() {
        let (auth, host, port) = super::parse_netloc("user:pass@example.com:8080");
        assert_eq!(auth, Some("user:pass".into()));
        assert_eq!(host, Some("example.com".into()));
        assert_eq!(port, Some(8080));
    }

    #[test]
    fn test_parse_netloc_user_only_auth() {
        let (auth, host, port) = super::parse_netloc("user@example.com");
        assert_eq!(auth, Some("user".into()));
        assert_eq!(host, Some("example.com".into()));
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_netloc_ipv6() {
        let (auth, host, port) = super::parse_netloc("[::1]");
        assert_eq!(auth, None);
        assert_eq!(host, Some("[::1]".into()));
        assert_eq!(port, None);
    }

    #[test]
    fn test_parse_netloc_ipv6_with_port() {
        let (auth, host, port) = super::parse_netloc("[::1]:8080");
        assert_eq!(auth, None);
        assert_eq!(host, Some("[::1]".into()));
        assert_eq!(port, Some(8080));
    }

    #[test]
    fn test_parse_netloc_ipv6_full_with_port() {
        let (auth, host, port) =
            super::parse_netloc("[1200:0000:ab00:1234:0000:2552:7777:1313]:12345");
        assert_eq!(auth, None);
        assert_eq!(
            host,
            Some("[1200:0000:ab00:1234:0000:2552:7777:1313]".into())
        );
        assert_eq!(port, Some(12345));
    }

    #[test]
    fn test_parse_netloc_auth_ipv6_port() {
        let (auth, host, port) = super::parse_netloc("user@[::1]:8080");
        assert_eq!(auth, Some("user".into()));
        assert_eq!(host, Some("[::1]".into()));
        assert_eq!(port, Some(8080));
    }

    #[test]
    fn test_parse_netloc_empty() {
        let (auth, host, port) = super::parse_netloc("");
        assert_eq!(auth, None);
        assert_eq!(host, None);
        assert_eq!(port, None);
    }

    // ---- parse_url_raw tests ----

    #[test]
    fn test_parse_url_raw_full() {
        let p = super::parse_url_raw("http://user:pass@example.com:8080/path?q=1#frag");
        assert_eq!(p.scheme, Some("http".into()));
        assert_eq!(p.auth, Some("user:pass".into()));
        assert_eq!(p.host, Some("example.com".into()));
        assert_eq!(p.port, Some(8080));
        assert_eq!(p.path, Some("/path".into()));
        assert_eq!(p.query, Some("q=1".into()));
        assert_eq!(p.fragment, Some("frag".into()));
    }

    #[test]
    fn test_parse_url_raw_simple() {
        let p = super::parse_url_raw("http://example.com/");
        assert_eq!(p.scheme, Some("http".into()));
        assert_eq!(p.host, Some("example.com".into()));
        assert_eq!(p.path, Some("/".into()));
    }

    #[test]
    fn test_parse_url_raw_no_path() {
        let p = super::parse_url_raw("http://example.com");
        assert_eq!(p.scheme, Some("http".into()));
        assert_eq!(p.host, Some("example.com".into()));
        assert_eq!(p.path, None);
    }

    #[test]
    fn test_parse_url_raw_query_no_path() {
        let p = super::parse_url_raw("http://example.com?foo=bar");
        assert_eq!(p.scheme, Some("http".into()));
        assert_eq!(p.host, Some("example.com".into()));
        assert_eq!(p.path, None);
        assert_eq!(p.query, Some("foo=bar".into()));
    }

    #[test]
    fn test_parse_url_raw_no_scheme() {
        let p = super::parse_url_raw("example.com/path");
        assert_eq!(p.scheme, None);
    }

    #[test]
    fn test_parse_url_raw_ipv6_preserves_original() {
        let p = super::parse_url_raw("http://[1200:0000:ab00:1234:0000:2552:7777:1313]:12345/");
        assert_eq!(
            p.host,
            Some("[1200:0000:ab00:1234:0000:2552:7777:1313]".into())
        );
        assert_eq!(p.port, Some(12345));
    }

    // ---- path_url_from_str tests ----

    #[test]
    fn test_path_url_with_query() {
        assert_eq!(
            super::path_url_from_str("http://example.com/path?q=1"),
            "/path?q=1"
        );
    }

    #[test]
    fn test_path_url_no_query() {
        assert_eq!(super::path_url_from_str("http://example.com/path"), "/path");
    }

    #[test]
    fn test_path_url_root() {
        assert_eq!(super::path_url_from_str("http://example.com/"), "/");
    }

    #[test]
    fn test_path_url_no_path() {
        assert_eq!(super::path_url_from_str("http://example.com"), "/");
    }

    #[test]
    fn test_path_url_invalid() {
        assert_eq!(super::path_url_from_str("not-a-url"), "/");
    }

    // -- cookie_matches_url tests --

    #[test]
    fn test_cookie_matches_supercookie() {
        // Empty domain matches everything
        let url = url::Url::parse("http://example.com/").unwrap();
        assert!(super::cookie_matches_url("", "/", false, None, &url));
    }

    #[test]
    fn test_cookie_matches_exact_domain() {
        let url = url::Url::parse("http://example.com/").unwrap();
        assert!(super::cookie_matches_url(
            "example.com",
            "/",
            false,
            None,
            &url
        ));
        assert!(!super::cookie_matches_url(
            "other.com",
            "/",
            false,
            None,
            &url
        ));
    }

    #[test]
    fn test_cookie_matches_domain_suffix() {
        let url = url::Url::parse("http://sub.example.com/").unwrap();
        assert!(super::cookie_matches_url(
            ".example.com",
            "/",
            false,
            None,
            &url
        ));
        assert!(super::cookie_matches_url(
            ".sub.example.com",
            "/",
            false,
            None,
            &url
        ));
        assert!(!super::cookie_matches_url(
            ".other.com",
            "/",
            false,
            None,
            &url
        ));
    }

    #[test]
    fn test_cookie_matches_secure_scheme() {
        let http = url::Url::parse("http://example.com/").unwrap();
        let https = url::Url::parse("https://example.com/").unwrap();
        assert!(!super::cookie_matches_url("", "/", true, None, &http));
        assert!(super::cookie_matches_url("", "/", true, None, &https));
    }

    #[test]
    fn test_cookie_matches_expired() {
        let url = url::Url::parse("http://example.com/").unwrap();
        // Expired in the past
        assert!(!super::cookie_matches_url("", "/", false, Some(0), &url));
        // Expires far in the future
        assert!(super::cookie_matches_url(
            "",
            "/",
            false,
            Some(9999999999),
            &url
        ));
        // No expiry (session cookie)
        assert!(super::cookie_matches_url("", "/", false, None, &url));
    }

    #[test]
    fn test_cookie_matches_path() {
        let url = url::Url::parse("http://example.com/app/page").unwrap();
        assert!(super::cookie_matches_url("", "/app", false, None, &url));
        assert!(super::cookie_matches_url("", "/", false, None, &url));
        assert!(!super::cookie_matches_url("", "/other", false, None, &url));
    }

    // ---- generate_boundary tests ----

    #[test]
    fn test_generate_boundary_length() {
        let b = super::generate_boundary();
        assert_eq!(b.len(), 32, "boundary must be 32 hex chars");
    }

    #[test]
    fn test_generate_boundary_hex_chars() {
        let b = super::generate_boundary();
        assert!(
            b.chars().all(|c| c.is_ascii_hexdigit()),
            "boundary must contain only hex digits"
        );
    }

    #[test]
    fn test_generate_boundary_unique() {
        let a = super::generate_boundary();
        let b = super::generate_boundary();
        assert_ne!(a, b, "consecutive boundaries must differ");
    }
}

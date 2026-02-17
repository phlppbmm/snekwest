use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::sync::Mutex;

use crate::case_insensitive_dict::CaseInsensitiveDict;

const REDIRECT_STATI: [u16; 5] = [301, 302, 303, 307, 308];
const CONTENT_CHUNK_SIZE: usize = 10 * 1024;

// ---------------------------------------------------------------------------
// StreamingInner / StreamingBody (unchanged from before)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct StreamingInner(pub Arc<Mutex<Option<reqwest::blocking::Response>>>);

#[pyclass]
pub struct StreamingBody {
    inner: StreamingInner,
    #[pyo3(get)]
    headers: HashMap<String, String>,
    closed: bool,
}

impl StreamingBody {
    pub fn new(inner: StreamingInner, headers: HashMap<String, String>) -> Self {
        StreamingBody {
            inner,
            headers,
            closed: false,
        }
    }
}

#[pymethods]
impl StreamingBody {
    #[pyo3(signature = (size = 8192))]
    fn read(&mut self, py: Python<'_>, size: usize) -> PyResult<Vec<u8>> {
        if self.closed {
            return Ok(Vec::new());
        }
        let response_opt = {
            let mut guard = self
                .inner
                .0
                .lock()
                .map_err(|e| PyRuntimeError::new_err(format!("Lock poisoned: {}", e)))?;
            guard.take()
        };
        let Some(mut response) = response_opt else {
            return Ok(Vec::new());
        };
        let (response_back, result) = py.detach(move || {
            let mut buf = vec![0u8; size];
            match response.read(&mut buf) {
                Ok(0) => (response, Ok(Vec::new())),
                Ok(n) => {
                    buf.truncate(n);
                    (response, Ok(buf))
                }
                Err(e) => (response, Err(e)),
            }
        });
        let data = result.map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(format!("Stream read error: {}", e))
        })?;
        let mut guard = self
            .inner
            .0
            .lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Lock poisoned: {}", e)))?;
        *guard = Some(response_back);
        Ok(data)
    }

    fn close(&mut self) -> PyResult<()> {
        self.closed = true;
        let mut guard = self
            .inner
            .0
            .lock()
            .map_err(|e| PyRuntimeError::new_err(format!("Lock poisoned: {}", e)))?;
        *guard = None;
        Ok(())
    }

    #[getter]
    fn get_closed(&self) -> bool {
        self.closed
    }
}

// ---------------------------------------------------------------------------
// RawResponseData — internal struct returned by session.rs::do_request
// ---------------------------------------------------------------------------

pub struct RawResponseData {
    pub status: u16,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub elapsed_ms: f64,
    pub history: Vec<RawResponseData>,
    pub cookies: HashMap<String, String>,
    pub reason: Option<String>,
    pub is_redirect: bool,
    pub method: String,
    pub request_url: String,
    pub request_headers: HashMap<String, String>,
    pub streaming_inner: Option<StreamingInner>,
    pub streaming_headers: Option<Vec<(String, String)>>,
}

// ---------------------------------------------------------------------------
// Response — the Python-facing pyclass
// ---------------------------------------------------------------------------

#[pyclass(dict)]
pub struct Response {
    // Content state
    content_bytes: Option<Vec<u8>>,
    content_loaded: bool,
    content_consumed: bool,

    // Core fields
    status_code: Option<u16>,
    url_inner: Option<String>,
    headers_inner: Option<Py<CaseInsensitiveDict>>,
    encoding_inner: Option<Py<PyAny>>,

    // Metadata
    elapsed_inner: Py<PyAny>,
    history_inner: Py<PyAny>,
    reason_inner: Option<Py<PyAny>>,
    cookies_inner: Py<PyAny>,

    // References
    request_inner: Option<Py<PyAny>>,
    next_inner: Option<Py<PyAny>>,
    connection_inner: Option<Py<PyAny>>,
    raw_inner: Option<Py<PyAny>>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

impl Response {
    /// Build a Response from raw data produced by session.rs.
    pub fn from_raw(py: Python<'_>, data: RawResponseData) -> PyResult<Self> {
        // 1. Build CaseInsensitiveDict for headers
        let cid = Py::new(py, CaseInsensitiveDict::new_empty())?;
        for (k, v) in &data.headers {
            let v_str = PyString::new(py, v);
            cid.bind(py)
                .borrow_mut()
                .set_item(py, k, v_str.into_any())?;
        }

        // 2. Encoding from content-type
        let get_encoding = py
            .import("snekwest.utils")?
            .getattr("get_encoding_from_headers")?;
        let enc_result = get_encoding.call1((&cid,))?;
        let encoding: Option<Py<PyAny>> = if enc_result.is_none() {
            None
        } else {
            Some(enc_result.unbind())
        };

        // 3. Elapsed timedelta
        let timedelta_cls = py.import("datetime")?.getattr("timedelta")?;
        let kwargs = PyDict::new(py);
        kwargs.set_item("milliseconds", data.elapsed_ms)?;
        let elapsed = timedelta_cls.call((), Some(&kwargs))?.unbind();

        // 4. Cookies
        let cookiejar_from_dict = py
            .import("snekwest.cookies")?
            .getattr("cookiejar_from_dict")?;
        let py_cookies = PyDict::new(py);
        for (k, v) in &data.cookies {
            py_cookies.set_item(k, v)?;
        }
        let cookies = cookiejar_from_dict.call1((&py_cookies,))?.unbind();

        // 5. Build email.Message for raw._original_response.msg
        let msg_cls = py.import("email.message")?.getattr("Message")?;
        let msg = msg_cls.call0()?;
        for (k, v) in &data.headers {
            msg.call_method1("__setitem__", (k.as_str(), v.as_str()))?;
        }

        // 6. Build headers_dict (lowercase keys) for raw.headers
        let headers_dict = PyDict::new(py);
        for (k, v) in &data.headers {
            headers_dict.set_item(k.to_lowercase(), v)?;
        }

        // 7. Build raw object + content state
        let (content_bytes, content_loaded, content_consumed, raw) =
            if let Some(streaming) = data.streaming_inner {
                // Streaming: wrap in StreamingRawResponse
                let streaming_hdrs_map: HashMap<String, String> = data
                    .streaming_headers
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let sb = Py::new(py, StreamingBody::new(streaming, streaming_hdrs_map))?;
                let streaming_cls = py
                    .import("snekwest.models")?
                    .getattr("StreamingRawResponse")?;
                let raw = streaming_cls.call1((&sb, &headers_dict, &msg))?;
                (None, false, false, Some(raw.unbind()))
            } else {
                // Non-streaming: BytesIO with _original_response
                let io_mod = py.import("io")?;
                let bio = io_mod
                    .getattr("BytesIO")?
                    .call1((PyBytes::new(py, &data.body),))?;
                bio.setattr("headers", &headers_dict)?;
                let ns_cls = py.import("types")?.getattr("SimpleNamespace")?;
                let ns_kwargs = PyDict::new(py);
                ns_kwargs.set_item("msg", &msg)?;
                let fake_resp = ns_cls.call((), Some(&ns_kwargs))?;
                bio.setattr("_original_response", &fake_resp)?;
                (Some(data.body), true, true, Some(bio.unbind()))
            };

        // 8. Build request PreparedRequest
        let prep_cls = py.import("snekwest.models")?.getattr("PreparedRequest")?;
        let req = prep_cls.call0()?;
        req.setattr("method", data.method.to_uppercase())?;
        req.setattr("url", &data.request_url)?;
        let req_cid_cls = py
            .import("snekwest.structures")?
            .getattr("CaseInsensitiveDict")?;
        let req_headers_dict = PyDict::new(py);
        for (k, v) in &data.request_headers {
            req_headers_dict.set_item(k, v)?;
        }
        let req_cid = req_cid_cls.call1((&req_headers_dict,))?;
        req.setattr("headers", &req_cid)?;

        // 9. Build history recursively
        let history_list = PyList::empty(py);
        for h in data.history {
            let hist_resp = Response::from_raw(py, h)?;
            let hist_py = Py::new(py, hist_resp)?;
            history_list.append(&hist_py)?;
        }

        // 10. Reason
        let reason = data
            .reason
            .map(|r| PyString::new(py, &r).into_any().unbind());

        Ok(Response {
            content_bytes,
            content_loaded,
            content_consumed,
            status_code: Some(data.status),
            url_inner: Some(data.url),
            headers_inner: Some(cid),
            encoding_inner: encoding,
            elapsed_inner: elapsed,
            history_inner: history_list.into_any().unbind(),
            reason_inner: reason,
            cookies_inner: cookies,
            request_inner: Some(req.unbind()),
            next_inner: None,
            connection_inner: None,
            raw_inner: raw,
        })
    }

    /// Internal: load content from raw if not already loaded.
    fn ensure_content_loaded(&mut self, py: Python<'_>) -> PyResult<()> {
        if self.content_loaded {
            return Ok(());
        }
        if self.content_consumed {
            return Err(PyRuntimeError::new_err(
                "The content for this response was already consumed",
            ));
        }
        let status = self.status_code.unwrap_or(0);
        if status == 0 || self.raw_inner.is_none() {
            self.content_bytes = None;
            self.content_loaded = true;
            return Ok(());
        }
        // Read all content from raw
        let raw = self.raw_inner.as_ref().unwrap();
        let mut all_bytes: Vec<u8> = Vec::new();
        loop {
            let chunk_obj = raw.bind(py).call_method1("read", (CONTENT_CHUNK_SIZE,))?;
            // raw.read() may return bytes (normal) or str (e.g. StringIO mock)
            let chunk: Vec<u8> = if let Ok(b) = chunk_obj.extract::<Vec<u8>>() {
                b
            } else if let Ok(s) = chunk_obj.extract::<String>() {
                if s.is_empty() {
                    break;
                }
                s.into_bytes()
            } else {
                break;
            };
            if chunk.is_empty() {
                break;
            }
            all_bytes.extend(chunk);
        }
        self.content_bytes = Some(all_bytes);
        self.content_loaded = true;
        Ok(())
    }

    /// Internal: decode content bytes to text string.
    fn decode_text(&self, py: Python<'_>) -> PyResult<String> {
        let bytes = match &self.content_bytes {
            Some(b) if !b.is_empty() => b,
            _ => return Ok(String::new()),
        };

        // Determine encoding
        let encoding: Option<String> = match &self.encoding_inner {
            Some(enc) => enc.extract(py).ok(),
            None => None,
        };

        let encoding = match encoding {
            Some(e) => e,
            None => detect_encoding(py, bytes)?,
        };

        // Decode
        let py_bytes = PyBytes::new(py, bytes);
        match py_bytes.call_method1("decode", (&encoding, "replace")) {
            Ok(s) => s.extract(),
            Err(_) => {
                // Fallback: decode without explicit encoding
                let s = py_bytes.call_method1("decode", ("utf-8", "replace"))?;
                s.extract()
            }
        }
    }
}

/// Detect encoding of byte content using chardet.
/// Single source of truth — used by both `decode_text` and `apparent_encoding`.
fn detect_encoding(py: Python<'_>, bytes: &[u8]) -> PyResult<String> {
    let chardet = py.import("snekwest.compat")?.getattr("chardet")?;
    if !chardet.is_none() {
        let result = chardet.call_method1("detect", (PyBytes::new(py, bytes),))?;
        let enc: Option<String> = result.get_item("encoding")?.extract()?;
        Ok(enc.unwrap_or_else(|| "utf-8".to_string()))
    } else {
        Ok("utf-8".to_string())
    }
}

// ---------------------------------------------------------------------------
// Pure Rust helpers
// ---------------------------------------------------------------------------

/// Re-encode a string from latin1 code points to UTF-8.
///
/// Each character in `input` is treated as a latin1 byte value (0x00–0xFF).
/// The collected bytes are then decoded as UTF-8.
fn latin1_to_utf8(input: &str) -> String {
    let bytes: Vec<u8> = input.chars().map(|c| c as u32 as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ---------------------------------------------------------------------------
// Python methods
// ---------------------------------------------------------------------------

#[pymethods]
#[allow(non_snake_case)]
impl Response {
    #[classattr]
    fn __attrs__() -> Vec<&'static str> {
        vec![
            "_content",
            "status_code",
            "headers",
            "url",
            "history",
            "encoding",
            "reason",
            "cookies",
            "elapsed",
            "request",
        ]
    }

    #[new]
    fn py_new(py: Python<'_>) -> PyResult<Self> {
        let cid = Py::new(py, CaseInsensitiveDict::new_empty())?;
        let cookiejar_from_dict = py
            .import("snekwest.cookies")?
            .getattr("cookiejar_from_dict")?;
        let cookies = cookiejar_from_dict.call1((PyDict::new(py),))?.unbind();
        let timedelta_cls = py.import("datetime")?.getattr("timedelta")?;
        let elapsed = timedelta_cls.call1((0,))?.unbind();
        let history = PyList::empty(py).into_any().unbind();

        Ok(Response {
            content_bytes: None,
            content_loaded: false,
            content_consumed: false,
            status_code: None,
            url_inner: None,
            headers_inner: Some(cid),
            encoding_inner: None,
            elapsed_inner: elapsed,
            history_inner: history,
            reason_inner: None,
            cookies_inner: cookies,
            request_inner: None,
            next_inner: None,
            connection_inner: None,
            raw_inner: None,
        })
    }

    // -- Getters and setters --

    #[getter]
    fn status_code(&self) -> Option<u16> {
        self.status_code
    }
    #[setter]
    fn set_status_code(&mut self, v: Option<u16>) {
        self.status_code = v;
    }

    #[getter]
    fn url(&self, py: Python<'_>) -> Py<PyAny> {
        self.url_inner.as_ref().map_or_else(
            || py.None(),
            |u| u.into_pyobject(py).unwrap().into_any().unbind(),
        )
    }
    #[setter]
    fn set_url(&mut self, v: Option<String>) {
        self.url_inner = v;
    }

    #[getter]
    fn headers(&self, py: Python<'_>) -> Py<PyAny> {
        self.headers_inner
            .as_ref()
            .map_or_else(|| py.None(), |h| h.clone_ref(py).into_any())
    }
    #[setter]
    fn set_headers(&mut self, py: Python<'_>, v: Bound<'_, PyAny>) -> PyResult<()> {
        if v.is_none() {
            self.headers_inner = None;
        } else if let Ok(cid) = v.cast::<CaseInsensitiveDict>() {
            self.headers_inner = Some(cid.clone().unbind());
        } else {
            let cid_cls = py
                .import("snekwest.structures")?
                .getattr("CaseInsensitiveDict")?;
            let cid = cid_cls.call1((&v,))?;
            self.headers_inner = Some(cid.cast::<CaseInsensitiveDict>()?.clone().unbind());
        }
        Ok(())
    }

    #[getter]
    fn encoding(&self, py: Python<'_>) -> Py<PyAny> {
        self.encoding_inner
            .as_ref()
            .map_or_else(|| py.None(), |e| e.clone_ref(py))
    }
    #[setter]
    fn set_encoding(&mut self, _py: Python<'_>, v: Bound<'_, PyAny>) -> PyResult<()> {
        if v.is_none() {
            self.encoding_inner = None;
        } else {
            self.encoding_inner = Some(v.unbind());
        }
        Ok(())
    }

    #[getter]
    fn elapsed(&self, py: Python<'_>) -> Py<PyAny> {
        self.elapsed_inner.clone_ref(py)
    }
    #[setter]
    fn set_elapsed(&mut self, v: Py<PyAny>) {
        self.elapsed_inner = v;
    }

    #[getter]
    fn history(&self, py: Python<'_>) -> Py<PyAny> {
        self.history_inner.clone_ref(py)
    }
    #[setter]
    fn set_history(&mut self, v: Py<PyAny>) {
        self.history_inner = v;
    }

    #[getter]
    fn reason(&self, py: Python<'_>) -> Py<PyAny> {
        self.reason_inner
            .as_ref()
            .map_or_else(|| py.None(), |r| r.clone_ref(py))
    }
    #[setter]
    fn set_reason(&mut self, _py: Python<'_>, v: Bound<'_, PyAny>) -> PyResult<()> {
        if v.is_none() {
            self.reason_inner = None;
        } else {
            self.reason_inner = Some(v.unbind());
        }
        Ok(())
    }

    #[getter]
    fn cookies(&self, py: Python<'_>) -> Py<PyAny> {
        self.cookies_inner.clone_ref(py)
    }
    #[setter]
    fn set_cookies(&mut self, v: Py<PyAny>) {
        self.cookies_inner = v;
    }

    #[getter]
    fn request(&self, py: Python<'_>) -> Py<PyAny> {
        self.request_inner
            .as_ref()
            .map_or_else(|| py.None(), |r| r.clone_ref(py))
    }
    #[setter]
    fn set_request(&mut self, _py: Python<'_>, v: Bound<'_, PyAny>) -> PyResult<()> {
        if v.is_none() {
            self.request_inner = None;
        } else {
            self.request_inner = Some(v.unbind());
        }
        Ok(())
    }

    #[getter(next)]
    fn get_next(&self, py: Python<'_>) -> Py<PyAny> {
        self.next_inner
            .as_ref()
            .map_or_else(|| py.None(), |n| n.clone_ref(py))
    }

    #[getter(_next)]
    fn get__next(&self, py: Python<'_>) -> Py<PyAny> {
        self.next_inner
            .as_ref()
            .map_or_else(|| py.None(), |n| n.clone_ref(py))
    }
    #[setter(_next)]
    fn set__next(&mut self, _py: Python<'_>, v: Bound<'_, PyAny>) -> PyResult<()> {
        if v.is_none() {
            self.next_inner = None;
        } else {
            self.next_inner = Some(v.unbind());
        }
        Ok(())
    }

    #[getter]
    fn connection(&self, py: Python<'_>) -> Py<PyAny> {
        self.connection_inner
            .as_ref()
            .map_or_else(|| py.None(), |c| c.clone_ref(py))
    }
    #[setter]
    fn set_connection(&mut self, _py: Python<'_>, v: Bound<'_, PyAny>) -> PyResult<()> {
        if v.is_none() {
            self.connection_inner = None;
        } else {
            self.connection_inner = Some(v.unbind());
        }
        Ok(())
    }

    #[getter]
    fn raw(&self, py: Python<'_>) -> Py<PyAny> {
        self.raw_inner
            .as_ref()
            .map_or_else(|| py.None(), |r| r.clone_ref(py))
    }
    #[setter]
    fn set_raw(&mut self, _py: Python<'_>, v: Bound<'_, PyAny>) -> PyResult<()> {
        if v.is_none() {
            self.raw_inner = None;
        } else {
            self.raw_inner = Some(v.unbind());
        }
        Ok(())
    }

    #[getter(_content)]
    fn get__content(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        if !self.content_loaded {
            return Ok(false.into_pyobject(py)?.to_owned().into_any().unbind());
        }
        match &self.content_bytes {
            Some(bytes) => Ok(PyBytes::new(py, bytes).into_any().unbind()),
            None => Ok(py.None()),
        }
    }
    #[setter(_content)]
    fn set__content(&mut self, _py: Python<'_>, v: Bound<'_, PyAny>) -> PyResult<()> {
        if v.is_instance_of::<pyo3::types::PyBool>() {
            // _content = False means not loaded
            self.content_loaded = false;
            self.content_bytes = None;
        } else if v.is_none() {
            self.content_loaded = true;
            self.content_bytes = None;
        } else {
            let bytes: Vec<u8> = v.extract()?;
            self.content_loaded = true;
            self.content_bytes = Some(bytes);
        }
        Ok(())
    }

    #[getter(_content_consumed)]
    fn get__content_consumed(&self) -> bool {
        self.content_consumed
    }
    #[setter(_content_consumed)]
    fn set__content_consumed(&mut self, v: bool) {
        self.content_consumed = v;
    }

    // -- Computed properties --

    #[getter]
    fn content(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.ensure_content_loaded(py)?;
        self.content_consumed = true;
        match &self.content_bytes {
            Some(bytes) => Ok(PyBytes::new(py, bytes).into_any().unbind()),
            None => Ok(py.None()),
        }
    }

    #[getter]
    fn text(&mut self, py: Python<'_>) -> PyResult<String> {
        self.ensure_content_loaded(py)?;
        self.content_consumed = true;
        self.decode_text(py)
    }

    #[getter]
    fn ok(&mut self, py: Python<'_>) -> PyResult<bool> {
        match self.raise_for_status_impl(py, None) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    #[getter]
    fn is_redirect(&self, py: Python<'_>) -> bool {
        let has_location = match &self.headers_inner {
            Some(h) => h.bind(py).borrow().contains("location"),
            None => false,
        };
        let status = self.status_code.unwrap_or(0);
        has_location && REDIRECT_STATI.contains(&status)
    }

    /// Return the redirect target URL with latin1-to-utf8 re-encoding, or None.
    fn get_redirect_target(&self, py: Python<'_>) -> Option<String> {
        let has_location = match &self.headers_inner {
            Some(h) => h.bind(py).borrow().contains("location"),
            None => false,
        };
        let status = self.status_code.unwrap_or(0);
        if !(has_location && REDIRECT_STATI.contains(&status)) {
            return None;
        }
        let location: String = self
            .headers_inner
            .as_ref()
            .and_then(|h| h.bind(py).borrow().get_value(py, "location"))
            .and_then(|v| v.extract(py).ok())?;
        Some(latin1_to_utf8(&location))
    }

    #[getter]
    fn is_permanent_redirect(&self, py: Python<'_>) -> bool {
        let has_location = match &self.headers_inner {
            Some(h) => h.bind(py).borrow().contains("location"),
            None => false,
        };
        let status = self.status_code.unwrap_or(0);
        has_location && (status == 301 || status == 308)
    }

    #[getter]
    fn apparent_encoding(&mut self, py: Python<'_>) -> PyResult<String> {
        self.ensure_content_loaded(py)?;
        self.content_consumed = true;
        let bytes = self.content_bytes.as_deref().unwrap_or(b"");
        detect_encoding(py, bytes)
    }

    #[getter]
    fn links(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let header: Option<String> = match &self.headers_inner {
            Some(h) => {
                let val = h.bind(py).borrow().get_value(py, "link");
                match val {
                    Some(v) => v.extract(py).ok(),
                    None => None,
                }
            }
            None => None,
        };
        let dict = PyDict::new(py);
        if let Some(header_str) = header {
            let parse_fn = py.import("snekwest.utils")?.getattr("parse_header_links")?;
            let links_list = parse_fn.call1((&header_str,))?;
            for link_obj in links_list.try_iter()? {
                let link = link_obj?;
                let rel = link.call_method1("get", ("rel",))?;
                let url_val = link.call_method1("get", ("url",))?;
                let key = if rel.is_truthy()? { rel } else { url_val };
                dict.set_item(&key, &link)?;
            }
        }
        Ok(dict.into_any().unbind())
    }

    // -- Methods --

    #[pyo3(signature = (**kwargs))]
    fn json(&mut self, py: Python<'_>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        self.ensure_content_loaded(py)?;
        self.content_consumed = true;

        let bytes = match &self.content_bytes {
            Some(b) => b.clone(),
            None => Vec::new(),
        };

        let json_mod = py.import("json")?;
        let requests_jde = py
            .import("snekwest.exceptions")?
            .getattr("JSONDecodeError")?;

        // Try encoding-specific parsing
        let has_encoding = self
            .encoding_inner
            .as_ref()
            .is_some_and(|e| e.bind(py).is_truthy().unwrap_or(false));
        if !has_encoding && bytes.len() > 3 {
            let guess_fn = py.import("snekwest.utils")?.getattr("guess_json_utf")?;
            let enc: Option<String> = guess_fn.call1((PyBytes::new(py, &bytes),))?.extract()?;
            if let Some(enc) = enc {
                let decoded = PyBytes::new(py, &bytes).call_method1("decode", (&enc,));
                if let Ok(decoded) = decoded {
                    match json_mod.call_method("loads", (&decoded,), kwargs) {
                        Ok(result) => return Ok(result.unbind()),
                        Err(e) => {
                            let jde_cls = json_mod.getattr("JSONDecodeError")?;
                            if e.is_instance(py, &jde_cls) {
                                let v = e.value(py);
                                return Err(PyErr::from_value(requests_jde.call1((
                                    v.getattr("msg")?,
                                    v.getattr("doc")?,
                                    v.getattr("pos")?,
                                ))?));
                            }
                            // UnicodeDecodeError: fall through
                            if !e.is_instance_of::<pyo3::exceptions::PyUnicodeDecodeError>(py) {
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }

        // Fall back to text-based parsing
        let text = self.decode_text(py)?;
        match json_mod.call_method("loads", (&text,), kwargs) {
            Ok(result) => Ok(result.unbind()),
            Err(e) => {
                let jde_cls = json_mod.getattr("JSONDecodeError")?;
                if e.is_instance(py, &jde_cls) {
                    let v = e.value(py);
                    Err(PyErr::from_value(requests_jde.call1((
                        v.getattr("msg")?,
                        v.getattr("doc")?,
                        v.getattr("pos")?,
                    ))?))
                } else {
                    Err(e)
                }
            }
        }
    }

    fn raise_for_status(slf: &Bound<'_, Self>, py: Python<'_>) -> PyResult<()> {
        let this = slf.borrow();
        this.raise_for_status_impl(py, Some(slf.as_any().clone().unbind()))
    }

    /// Iterate over response content in chunks.
    ///
    /// ``chunk_size``: ``int`` (default 1) or ``None`` (all at once).
    /// Passing a non-int type raises ``TypeError``.
    ///
    /// PyO3's ``Option`` conflates omitted and explicit ``None``, so we use
    /// ``Option<isize>`` where ``None`` → no chunking, ``Some(n)`` → n bytes.
    /// The Python-level default is 1 (matching upstream ``requests``).
    #[pyo3(signature = (chunk_size=1, decode_unicode=false))]
    fn iter_content(
        &mut self,
        py: Python<'_>,
        chunk_size: Option<isize>,
        decode_unicode: bool,
    ) -> PyResult<Py<PyAny>> {
        // Validate chunk_size: must be int or None.
        // PyO3 handles the type check: only int and None reach here, anything else
        // (str, float, etc.) raises TypeError automatically.
        let cs: Option<usize> = chunk_size.map(|n| n as usize);

        // Check StreamConsumedError
        if self.content_consumed && !self.content_loaded {
            let exc = py
                .import("snekwest.exceptions")?
                .getattr("StreamConsumedError")?;
            return Err(PyErr::from_value(exc.call0()?));
        }

        // Build ContentIterator
        let iter = if self.content_consumed {
            // Content already loaded — iterate over cached bytes
            ContentIterator {
                content: self.content_bytes.clone(),
                pos: 0,
                raw: None,
                chunk_size: cs.unwrap_or(0),
                done: false,
            }
        } else {
            // Stream from raw — mark consumed eagerly so a second
            // iter_content() call raises StreamConsumedError.
            self.content_consumed = true;
            ContentIterator {
                content: None,
                pos: 0,
                raw: self.raw_inner.as_ref().map(|r| r.clone_ref(py)),
                chunk_size: cs.unwrap_or(0),
                done: false,
            }
        };

        let iter_py = Py::new(py, iter)?;

        if decode_unicode {
            let stream_decode = py
                .import("snekwest.utils")?
                .getattr("stream_decode_response_unicode")?;
            // Need to pass self as the response for encoding detection.
            // Create a SimpleNamespace with encoding info.
            let ns_cls = py.import("types")?.getattr("SimpleNamespace")?;
            let ns_kwargs = PyDict::new(py);
            ns_kwargs.set_item("encoding", self.encoding(py))?;
            let resp_proxy = ns_cls.call((), Some(&ns_kwargs))?;
            Ok(stream_decode.call1((&iter_py, &resp_proxy))?.unbind())
        } else {
            Ok(iter_py.into_any())
        }
    }

    #[pyo3(signature = (chunk_size=512, decode_unicode=false, delimiter=None))]
    fn iter_lines(
        &mut self,
        py: Python<'_>,
        chunk_size: usize,
        decode_unicode: bool,
        delimiter: Option<Py<PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        // Get the content iterator
        let content_iter = self.iter_content(py, Some(chunk_size as isize), decode_unicode)?;

        let iter = LinesIterator {
            content_iter,
            pending: None,
            buffered_lines: Vec::new(),
            buffered_pos: 0,
            delimiter,
            done: false,
        };
        Ok(Py::new(py, iter)?.into_any())
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if !self.content_consumed {
            if let Some(raw) = &self.raw_inner {
                let _ = raw.bind(py).call_method0("close");
            }
        }
        if let Some(raw) = &self.raw_inner {
            let raw_bound = raw.bind(py);
            if raw_bound.hasattr("release_conn")? {
                let _ = raw_bound.call_method0("release_conn");
            }
        }
        Ok(())
    }

    fn __enter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        py: Python<'_>,
        _exc_type: &Bound<'_, PyAny>,
        _exc_val: &Bound<'_, PyAny>,
        _exc_tb: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.close(py)
    }

    fn __bool__(&mut self, py: Python<'_>) -> PyResult<bool> {
        self.ok(py)
    }

    fn __iter__(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.iter_content(py, Some(128), false)
    }

    fn __repr__(&self) -> String {
        match self.status_code {
            Some(s) => format!("<Response [{}]>", s),
            None => "<Response>".to_string(),
        }
    }
}

impl Response {
    fn raise_for_status_impl(
        &self,
        py: Python<'_>,
        response_obj: Option<Py<PyAny>>,
    ) -> PyResult<()> {
        let status = self.status_code.unwrap_or(0);

        let reason: String = match &self.reason_inner {
            Some(r) => {
                let r_bound = r.bind(py);
                if r_bound.is_instance_of::<PyBytes>() {
                    match r_bound.call_method1("decode", ("utf-8",)) {
                        Ok(s) => s.extract()?,
                        Err(_) => r_bound.call_method1("decode", ("iso-8859-1",))?.extract()?,
                    }
                } else {
                    r_bound.str()?.to_string()
                }
            }
            None => String::new(),
        };

        let url = self.url_inner.as_deref().unwrap_or("");

        let msg = if (400..500).contains(&status) {
            Some(format!(
                "{} Client Error: {} for url: {}",
                status, reason, url
            ))
        } else if (500..600).contains(&status) {
            Some(format!(
                "{} Server Error: {} for url: {}",
                status, reason, url
            ))
        } else {
            None
        };

        if let Some(error_msg) = msg {
            let http_error_cls = py.import("snekwest.exceptions")?.getattr("HTTPError")?;
            let kwargs = PyDict::new(py);
            kwargs.set_item(
                "response",
                response_obj
                    .as_ref()
                    .map_or_else(|| py.None(), |r| r.clone_ref(py)),
            )?;
            return Err(PyErr::from_value(
                http_error_cls.call((error_msg,), Some(&kwargs))?,
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ContentIterator
// ---------------------------------------------------------------------------

#[pyclass]
pub struct ContentIterator {
    content: Option<Vec<u8>>,
    pos: usize,
    raw: Option<Py<PyAny>>,
    chunk_size: usize,
    done: bool,
}

#[pymethods]
impl ContentIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        if self.done {
            return Ok(None);
        }

        if let Some(ref content) = self.content {
            // Slicing cached content
            if self.chunk_size == 0 {
                // chunk_size=None: return all at once
                if self.pos > 0 {
                    self.done = true;
                    return Ok(None);
                }
                self.pos = content.len();
                if content.is_empty() {
                    self.done = true;
                    return Ok(None);
                }
                return Ok(Some(PyBytes::new(py, content).into_any().unbind()));
            }
            if self.pos >= content.len() {
                self.done = true;
                return Ok(None);
            }
            let end = (self.pos + self.chunk_size).min(content.len());
            let chunk = &content[self.pos..end];
            self.pos = end;
            Ok(Some(PyBytes::new(py, chunk).into_any().unbind()))
        } else if let Some(ref raw) = self.raw {
            // Streaming from raw
            let chunk = if self.chunk_size == 0 {
                // chunk_size=None: read all remaining content at once
                raw.bind(py).call_method0("read")?
            } else {
                raw.bind(py).call_method1("read", (self.chunk_size,))?
            };
            // raw.read() may return bytes (normal) or str (e.g. StringIO mock)
            let chunk_bytes: Vec<u8> = if let Ok(b) = chunk.extract::<Vec<u8>>() {
                b
            } else if let Ok(s) = chunk.extract::<String>() {
                s.into_bytes()
            } else {
                self.done = true;
                return Ok(None);
            };
            if chunk_bytes.is_empty() {
                self.done = true;
                return Ok(None);
            }
            // After reading all at once, mark done so next call returns None
            if self.chunk_size == 0 {
                self.done = true;
            }
            Ok(Some(PyBytes::new(py, &chunk_bytes).into_any().unbind()))
        } else {
            self.done = true;
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// LinesIterator
// ---------------------------------------------------------------------------

#[pyclass]
pub struct LinesIterator {
    content_iter: Py<PyAny>,
    pending: Option<Py<PyAny>>,
    buffered_lines: Vec<Py<PyAny>>,
    buffered_pos: usize,
    delimiter: Option<Py<PyAny>>,
    done: bool,
}

#[pymethods]
impl LinesIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        loop {
            // Yield buffered lines first
            if self.buffered_pos < self.buffered_lines.len() {
                let line = self.buffered_lines[self.buffered_pos].clone_ref(py);
                self.buffered_pos += 1;
                return Ok(Some(line));
            }

            if self.done {
                return Ok(None);
            }

            // Get next chunk from content iterator
            let next_fn = py.import("builtins")?.getattr("next")?;
            let chunk = match next_fn.call1((&self.content_iter,)) {
                Ok(c) => c,
                Err(e) => {
                    if e.is_instance_of::<pyo3::exceptions::PyStopIteration>(py) {
                        self.done = true;
                        // Yield pending if any
                        if let Some(pending) = self.pending.take() {
                            return Ok(Some(pending));
                        }
                        return Ok(None);
                    }
                    return Err(e);
                }
            };

            // Prepend pending
            let chunk = if let Some(pending) = self.pending.take() {
                pending
                    .bind(py)
                    .call_method1("__add__", (&chunk,))?
                    .unbind()
            } else {
                chunk.unbind()
            };

            // Split into lines
            let chunk_bound = chunk.bind(py);
            let lines = if let Some(ref delim) = self.delimiter {
                chunk_bound.call_method1("split", (delim.bind(py),))?
            } else {
                chunk_bound.call_method0("splitlines")?
            };
            let lines_list: Vec<Py<PyAny>> = lines.extract()?;

            if lines_list.is_empty() {
                continue;
            }

            // Check if last line is incomplete
            let last = &lines_list[lines_list.len() - 1];
            let last_truthy = last.bind(py).is_truthy()?;
            let chunk_truthy = chunk_bound.is_truthy()?;

            let last_incomplete = if last_truthy && chunk_truthy {
                let last_bound = last.bind(py);
                let last_char = last_bound.get_item(-1i64)?;
                let chunk_char = chunk_bound.get_item(-1i64)?;
                last_char.eq(&chunk_char)?
            } else {
                false
            };

            let (to_yield, new_pending) = if last_incomplete {
                let mut v = lines_list;
                let p = v.pop();
                (v, p)
            } else {
                (lines_list, None)
            };

            self.pending = new_pending;
            self.buffered_lines = to_yield;
            self.buffered_pos = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latin1_to_utf8_ascii() {
        // Pure ASCII input should pass through unchanged.
        let input = "https://example.com/path?q=hello";
        let result = latin1_to_utf8(input);
        assert_eq!(result, "https://example.com/path?q=hello");
    }

    #[test]
    fn test_latin1_to_utf8_non_ascii() {
        // Latin1 "caf\u{00e9}" — the single code point U+00E9 maps to
        // the latin1 byte 0xE9, which is *not* valid standalone UTF-8.
        // But as a single byte, 0xE9 is the latin1 encoding of 'e'.
        // The function should collect the byte 0xE9 and attempt to
        // decode it as UTF-8. Since a lone 0xE9 is not valid UTF-8,
        // this tests the latin1→bytes→utf8 pipeline with a byte that
        // happens to be a single latin1 character.
        //
        // For this test we use a string where the latin1 bytes form
        // valid UTF-8: "caf\u{00c3}\u{00a9}" — the two code points
        // U+00C3 and U+00A9 give bytes [0xC3, 0xA9] which is UTF-8
        // for 'e'. So we verify that path in test_latin1_to_utf8_multibyte_utf8
        // and here just check that single-byte latin1 char \u{00e9} (byte 0xE9)
        // produces "caf" + whatever UTF-8 decodes 0xE9 to.
        //
        // Actually the simplest test: "caf\u{00e9}" has bytes [99, 97, 102, 233].
        // 233 alone is not valid UTF-8, so it depends on the implementation
        // (lossy vs strict). The Python reference does `.encode("latin1")` which
        // gives raw bytes, then `.decode("utf8")` which would fail on lone 0xE9.
        //
        // The realistic case: HTTP headers use latin1 encoding, so a URL like
        // "/café" is encoded as latin1 bytes. If those bytes happen to be valid
        // UTF-8, the decode succeeds. Let's test with an input where all chars
        // are in the ASCII range plus characters whose latin1 bytes form valid
        // UTF-8 sequences.
        //
        // Simple check: ASCII-only non-ascii test — use chars 0x80-0xBF which
        // are continuation bytes in UTF-8 (invalid alone). The Python code uses
        // to_native_string which does encode('latin1').decode('utf8') — if it
        // fails, Python would raise. So the realistic scenario is: the "location"
        // header contains UTF-8 bytes stored as latin1 code points.
        //
        // Test: "\u{00c3}\u{00a9}" → bytes [0xC3, 0xA9] → UTF-8 "é"
        // This is covered by test_latin1_to_utf8_multibyte_utf8.
        //
        // For this test, use a URL with a path containing "é" encoded as UTF-8
        // bytes stored in latin1: "/caf\u{00c3}\u{00a9}" → "/café"
        let input = "/caf\u{00c3}\u{00a9}";
        let result = latin1_to_utf8(input);
        assert_eq!(result, "/caf\u{00e9}"); // "/café" in proper UTF-8
    }

    #[test]
    fn test_latin1_to_utf8_empty() {
        // Empty string should produce empty string.
        let input = "";
        let result = latin1_to_utf8(input);
        assert_eq!(result, "");
    }

    #[test]
    fn test_latin1_to_utf8_multibyte_utf8() {
        // UTF-8 bytes for "é" are [0xC3, 0xA9]. When stored as latin1
        // code points, these become the Rust string "\u{00c3}\u{00a9}"
        // (two characters: U+00C3 'Ã' and U+00A9 '©').
        // latin1_to_utf8 should extract bytes [0xC3, 0xA9] and decode
        // them as UTF-8 to produce "é" (U+00E9).
        let input = "\u{00c3}\u{00a9}";
        let result = latin1_to_utf8(input);
        assert_eq!(result, "\u{00e9}"); // "é"
    }
}

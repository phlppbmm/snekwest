use pyo3::prelude::*;
use pythonize::depythonize;
use reqwest::blocking::{Client, ClientBuilder};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use crate::exceptions;
use crate::request_params::CertParameter;
use crate::request_params::{DataParameter, RequestParams, TimeoutParameter};
use crate::response::Response;

const MAX_REDIRECTS: usize = 30;

fn reason_phrase(status: u16) -> Option<String> {
    let phrase = match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => return None,
    };
    Some(phrase.to_string())
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Validate the URL and raise the appropriate Python exception for invalid URLs.
fn validate_url(url: &str) -> PyResult<()> {
    // Empty or whitespace-only
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(PyErr::new::<exceptions::InvalidURL, _>(
            format!("Invalid URL {}: No host supplied", repr_str(url)),
        ));
    }

    // Check for scheme
    if let Some(colon_pos) = trimmed.find(':') {
        let scheme = &trimmed[..colon_pos];
        // Check if scheme is a valid URL scheme (only letters, digits, +, -, .)
        let is_valid_scheme = !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.');

        if is_valid_scheme {
            let lower_scheme = scheme.to_lowercase();
            if lower_scheme != "http" && lower_scheme != "https" {
                return Err(PyErr::new::<exceptions::InvalidSchema, _>(format!(
                    "No connection adapters were found for {:?}",
                    url
                )));
            }

            // Has http/https scheme - check for valid host
            let after_scheme = &trimmed[colon_pos + 1..];
            let after_slashes = after_scheme.trim_start_matches('/');

            if after_slashes.is_empty() {
                return Err(PyErr::new::<exceptions::InvalidURL, _>(
                    format!("Invalid URL {:?}: No host supplied", url),
                ));
            }

            // Check for invalid characters in hostname
            let host = after_slashes.split('/').next().unwrap_or("");

            // Detect bare IPv6 addresses (without brackets)
            // e.g. http://fe80::5054:ff:fe5a:fc0 is invalid, should be http://[fe80::...]/
            if !host.starts_with('[') && host.chars().filter(|c| *c == ':').count() > 1 {
                return Err(PyErr::new::<exceptions::InvalidURL, _>(format!(
                    "Invalid URL {:?}: Invalid IPv6 URL",
                    url
                )));
            }

            let host_no_port = host.split(':').next().unwrap_or("");
            if host_no_port.starts_with('*') || host_no_port.starts_with('.') {
                return Err(PyErr::new::<exceptions::InvalidURL, _>(format!(
                    "Invalid URL {:?}: Invalid host",
                    url
                )));
            }

            return Ok(());
        }
    }

    // No valid scheme found - check if it looks like host:port (InvalidSchema)
    // or just a bare word (MissingSchema)
    if trimmed.contains(':') || trimmed.contains('/') {
        // Looks like host:port or host/path without a scheme
        return Err(PyErr::new::<exceptions::InvalidSchema, _>(format!(
            "No connection adapters were found for {:?}",
            url
        )));
    }

    Err(PyErr::new::<exceptions::MissingSchema, _>(format!(
        "Invalid URL {:?}: No scheme supplied. Perhaps you meant \"https://{}\"?",
        url, url
    )))
}

fn repr_str(s: &str) -> String {
    format!("'{}'", s)
}

fn is_ssl_error_text(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("certificate")
        || lower.contains("ssl")
        || lower.contains("tls")
        || lower.contains("handshake")
        || lower.contains("unknown issuer")
        || lower.contains("self signed")
}

/// Collect the full error chain (including nested source errors) into a single string.
fn full_error_chain(e: &reqwest::Error) -> String {
    use std::error::Error;
    let mut msg = e.to_string();
    let mut source: Option<&dyn Error> = e.source();
    while let Some(s) = source {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        source = s.source();
    }
    msg
}

/// Map a reqwest error to the appropriate Python exception.
/// `had_explicit_connect_timeout` is true when the user passed a (connect, read) timeout tuple
/// with a non-None connect value, signaling that ConnectTimeout should be raised.
fn map_reqwest_error(e: reqwest::Error, had_explicit_connect_timeout: bool) -> PyErr {
    let msg = full_error_chain(&e);

    // Check for SSL/TLS errors first — they may appear as connect errors
    if is_ssl_error_text(&msg) {
        return PyErr::new::<exceptions::SSLError, _>(msg);
    }

    if e.is_timeout() {
        if e.is_connect() {
            if had_explicit_connect_timeout {
                // User explicitly set a connect timeout via (connect, read) tuple
                return PyErr::new::<exceptions::ConnectTimeout, _>(
                    format!("ConnectTimeout: connection timed out. {}", msg),
                );
            }
            // Connection attempt timed out under a general timeout — treat as ConnectionError
            return PyErr::new::<exceptions::ConnectionError, _>(msg);
        }
        // Read / general timeout — ensure message contains "timed out"
        if msg.to_lowercase().contains("timed out") {
            return PyErr::new::<exceptions::ReadTimeout, _>(msg);
        }
        return PyErr::new::<exceptions::ReadTimeout, _>(format!(
            "Read timed out. {}",
            msg
        ));
    }

    if e.is_connect() {
        return PyErr::new::<exceptions::ConnectionError, _>(msg);
    }

    if e.is_redirect() {
        return PyErr::new::<exceptions::TooManyRedirects, _>(msg);
    }

    PyErr::new::<exceptions::ConnectionError, _>(msg)
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct ClientConfig {
    verify: bool,
    cert_hash: Option<String>,
    proxy_hash: Option<String>,
    connect_timeout_ms: Option<u64>,
}

impl ClientConfig {
    fn from_params(params: &RequestParams) -> Self {
        let connect_timeout_ms = match &params.timeout {
            Some(TimeoutParameter::Pair(Some(c), _)) => Some((*c * 1000.0) as u64),
            _ => None,
        };
        Self {
            verify: params.verify.unwrap_or(true),
            cert_hash: params.cert.as_ref().map(|c| format!("{:?}", c)),
            proxy_hash: params.proxies.as_ref().map(|p| format!("{:?}", p)),
            connect_timeout_ms,
        }
    }
}

#[pyclass]
pub struct Session {
    clients: Mutex<HashMap<ClientConfig, Arc<Client>>>,
    cookie_jar: Mutex<HashMap<String, String>>,
    #[pyo3(get, set)]
    max_redirects: usize,
    #[pyo3(get, set)]
    default_headers: Option<HashMap<String, String>>,
    #[pyo3(get, set)]
    default_auth: Option<(String, String)>,
    #[pyo3(get, set)]
    default_params: Option<HashMap<String, String>>,
}

impl Session {
    fn get_or_create_client(&self, params: &RequestParams) -> PyResult<Arc<Client>> {
        let config = ClientConfig::from_params(params);
        let mut clients = self.clients.lock().unwrap();

        if let Some(existing_client) = clients.get(&config) {
            return Ok(existing_client.clone());
        }

        let new_client = self.create_client_for_config(&config)?;
        clients.insert(config, new_client.clone());
        Ok(new_client)
    }

    fn merge_cookies(&self, params: &RequestParams) -> HashMap<String, String> {
        let mut all_cookies = {
            let session_cookies = self.cookie_jar.lock().unwrap();
            session_cookies.clone()
        };

        if let Some(request_cookies) = &params.cookies {
            all_cookies.extend(request_cookies.clone());
        }

        all_cookies
    }

    fn build_request(
        &self,
        client: &Client,
        method: &str,
        url: &str,
        params: &RequestParams,
        cookies: &HashMap<String, String>,
        auth: &Option<(String, String)>,
        extra_headers: &Option<HashMap<String, String>>,
    ) -> PyResult<reqwest::blocking::RequestBuilder> {
        let mut request = client.request(
            method.parse().map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid HTTP method")
            })?,
            url,
        );

        // Merge default params with request params
        let mut merged_params: HashMap<String, String> = HashMap::new();
        if let Some(default_params) = &self.default_params {
            merged_params.extend(default_params.clone());
        }
        if let Some(query_params) = &params.params {
            merged_params.extend(query_params.clone());
        }
        if !merged_params.is_empty() {
            request = request.query(&merged_params);
        }

        // Merge default headers with request headers
        if let Some(default_headers) = extra_headers {
            for (key, value) in default_headers {
                request = request.header(key, value);
            }
        }
        if let Some(headers) = &params.headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        if !cookies.is_empty() {
            let cookie_header = cookies
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("; ");
            request = request.header("Cookie", cookie_header);
        }

        // Use request auth, then session default auth
        if let Some((username, password)) = auth {
            request = request.basic_auth(username, Some(password));
        }

        Ok(request)
    }

    fn apply_body_and_timeout(
        &self,
        mut request: reqwest::blocking::RequestBuilder,
        params: &RequestParams,
    ) -> PyResult<reqwest::blocking::RequestBuilder> {
        if let Some(json_data) = &params.json {
            let json_string = self.serialize_json_body(json_data)?;
            request = request
                .header("Content-Type", "application/json")
                .body(json_string);
        } else if let Some(files) = &params.files {
            let mut form = reqwest::blocking::multipart::Form::new();
            for (field_name, file_path) in files {
                form = form.text(field_name.clone(), file_path.clone());
            }
            request = request.multipart(form);
        } else if let Some(data) = &params.data {
            request = match data {
                DataParameter::Form(form_data) => request.form(form_data),
                DataParameter::Raw(raw_bytes) => request.body(raw_bytes.clone()),
            };
        }

        if let Some(timeout_params) = &params.timeout {
            if let Some(timeout_duration) = self.calculate_timeout(timeout_params) {
                request = request.timeout(timeout_duration);
            }
        }

        Ok(request)
    }

    fn serialize_json_body(&self, json_value: &Py<PyAny>) -> PyResult<String> {
        Python::attach(|py| {
            let rust_value: serde_json::Value = depythonize(json_value.bind(py)).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Failed to convert Python object to JSON: {}",
                    e
                ))
            })?;

            serde_json::to_string(&rust_value).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "JSON serialization error: {}",
                    e
                ))
            })
        })
    }

    /// Returns the read/overall timeout duration for the request builder.
    /// Connect timeout is handled separately on the client builder.
    fn calculate_timeout(
        &self,
        timeout_params: &TimeoutParameter,
    ) -> Option<std::time::Duration> {
        match timeout_params {
            TimeoutParameter::Single(secs) => Some(std::time::Duration::from_secs_f64(*secs)),
            TimeoutParameter::Pair(_, Some(read)) => {
                Some(std::time::Duration::from_secs_f64(*read))
            }
            TimeoutParameter::Pair(_, None) => None, // No read timeout
        }
    }

    fn update_session_cookies(
        &self,
        response: &reqwest::blocking::Response,
        request_had_cookies: bool,
    ) {
        // Don't update session cookies if the request had per-request cookies
        if request_had_cookies {
            return;
        }

        let mut jar = self.cookie_jar.lock().unwrap();

        for (name, value) in response.headers() {
            if name.as_str().to_lowercase() == "set-cookie" {
                if let Ok(cookie_str) = value.to_str() {
                    self.parse_and_store_cookie(&mut jar, cookie_str);
                }
            }
        }
    }

    fn parse_and_store_cookie(&self, jar: &mut HashMap<String, String>, cookie_str: &str) {
        if let Some(cookie_pair) = cookie_str.split(';').next() {
            if let Some((key, val)) = cookie_pair.split_once('=') {
                let key = key.trim().to_string();
                let val = val.trim().to_string();

                // Check for expired cookies
                let lower = cookie_str.to_lowercase();
                if lower.contains("expires=") {
                    // Check if it's an expiry in the past (epoch-ish)
                    if lower.contains("1970") || lower.contains("deleted") {
                        jar.remove(&key);
                        return;
                    }
                }
                if lower.contains("max-age=0") {
                    jar.remove(&key);
                    return;
                }

                jar.insert(key, val);
            }
        }
    }

    fn extract_response_headers(
        response: &reqwest::blocking::Response,
    ) -> HashMap<String, String> {
        response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect()
    }

    fn extract_response_cookies(
        response: &reqwest::blocking::Response,
    ) -> HashMap<String, String> {
        let mut cookies = HashMap::new();
        for (name, value) in response.headers() {
            if name.as_str().to_lowercase() == "set-cookie" {
                if let Ok(cookie_str) = value.to_str() {
                    if let Some(cookie_pair) = cookie_str.split(';').next() {
                        if let Some((key, val)) = cookie_pair.split_once('=') {
                            cookies.insert(key.trim().to_string(), val.trim().to_string());
                        }
                    }
                }
            }
        }
        cookies
    }

    fn create_client_for_config(&self, config: &ClientConfig) -> PyResult<Arc<Client>> {
        let mut builder = ClientBuilder::new();

        if !config.verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        // Always disable automatic redirects - we handle them manually
        builder = builder.redirect(reqwest::redirect::Policy::none());

        if let Some(ct_ms) = config.connect_timeout_ms {
            builder = builder.connect_timeout(std::time::Duration::from_millis(ct_ms));
        }

        let client = builder
            .build()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

        Ok(Arc::new(client))
    }

    /// Perform a single HTTP request (no redirect following).
    /// Releases the GIL during the network call to avoid deadlocks with
    /// Python-based HTTP servers (e.g. httpbin in tests).
    fn execute_single_request(
        &self,
        client: &Client,
        method: &str,
        url: &str,
        params: &RequestParams,
        cookies: &HashMap<String, String>,
        auth: &Option<(String, String)>,
        extra_headers: &Option<HashMap<String, String>>,
        had_explicit_connect_timeout: bool,
    ) -> PyResult<reqwest::blocking::Response> {
        let request =
            self.build_request(client, method, url, params, cookies, auth, extra_headers)?;
        let request = self.apply_body_and_timeout(request, params)?;

        // Release the GIL so Python-based servers (httpbin etc.) can process
        Python::attach(|py| {
            py.detach(|| {
                request
                    .send()
                    .map_err(|e| map_reqwest_error(e, had_explicit_connect_timeout))
            })
        })
    }

    fn do_request(&self, mut params: RequestParams) -> PyResult<Response> {
        let client = self.get_or_create_client(&params)?;
        let start = Instant::now();

        let had_explicit_connect_timeout = matches!(
            &params.timeout,
            Some(TimeoutParameter::Pair(Some(_), _))
        );

        let original_method = params.method.clone();
        let request_url = params.url.clone();
        let has_request_cookies = params.cookies.is_some();

        // Determine auth: request auth overrides session auth
        let auth = params.auth.clone().or_else(|| self.default_auth.clone());

        // Merge default headers
        let extra_headers = self.default_headers.clone();

        // Build merged cookies for the first request
        let merged_cookies = self.merge_cookies(&params);

        // Collect request headers for the Request object on the final response
        // We'll capture them from the first redirect step
        let mut current_method = original_method.clone();
        let mut current_url = request_url.clone();
        let mut history: Vec<Response> = Vec::new();
        let mut current_cookies = merged_cookies;
        let current_auth = auth.clone();
        let max_redirects = if params.allow_redirects {
            self.max_redirects
        } else {
            0
        };

        // Track request headers for each hop
        #[allow(unused_assignments)]
        let mut final_request_headers: HashMap<String, String> = HashMap::new();

        loop {
            // Build the actual request headers we'll send
            let mut req_headers: HashMap<String, String> = HashMap::new();
            if let Some(ref h) = extra_headers {
                req_headers.extend(h.clone());
            }
            if let Some(ref h) = params.headers {
                req_headers.extend(h.clone());
            }
            if let Some((ref u, ref p)) = current_auth {
                // Basic auth header
                use base64::Engine;
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, p));
                req_headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
            }
            // Track Content-Type for json requests
            if params.json.is_some() {
                req_headers.insert("Content-Type".to_string(), "application/json".to_string());
            }

            // Track request headers for each hop
            final_request_headers = req_headers.clone();

            let response = self.execute_single_request(
                &client,
                &current_method,
                &current_url,
                &params,
                &current_cookies,
                &current_auth,
                &extra_headers,
                had_explicit_connect_timeout,
            )?;

            let status = response.status().as_u16();
            let is_redir = is_redirect_status(status);

            // Update session cookies from response
            self.update_session_cookies(&response, has_request_cookies);

            // Update current cookies with any new cookies from this response
            for (name, value) in response.headers() {
                if name.as_str().to_lowercase() == "set-cookie" {
                    if let Ok(cookie_str) = value.to_str() {
                        if let Some(cookie_pair) = cookie_str.split(';').next() {
                            if let Some((key, val)) = cookie_pair.split_once('=') {
                                current_cookies
                                    .insert(key.trim().to_string(), val.trim().to_string());
                            }
                        }
                    }
                }
            }

            if is_redir && params.allow_redirects {
                if history.len() >= max_redirects {
                    // Build a partial response for the TooManyRedirects error
                    return Err(PyErr::new::<exceptions::TooManyRedirects, _>(format!(
                        "Exceeded {} redirects.",
                        max_redirects
                    )));
                }

                // Get redirect location
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let resp_headers = Self::extract_response_headers(&response);
                let resp_cookies = Self::extract_response_cookies(&response);
                let reason = reason_phrase(status);
                let resp_url = response.url().to_string();

                // Read body for intermediate response
                let body = response.bytes().unwrap_or_default().to_vec();

                // Build intermediate response for history
                let intermediate = Response::new(
                    status,
                    resp_url,
                    resp_headers,
                    body,
                    0.0, // elapsed not relevant for intermediates
                    Vec::new(),
                    resp_cookies,
                    reason,
                    true,
                    current_method.clone(),
                    current_url.clone(),
                    req_headers.clone(),
                );
                history.push(intermediate);

                if let Some(loc) = location {
                    // Resolve redirect URL against current URL
                    current_url = if let Ok(base) = url::Url::parse(&current_url) {
                        // Use url::Url::join which handles absolute, relative,
                        // and path-only URLs correctly (preserving port, etc.)
                        base.join(&loc).map(|u| u.to_string()).unwrap_or(loc)
                    } else {
                        loc
                    };

                    // Maintain fragment from original URL
                    if let Some(frag_pos) = request_url.find('#') {
                        let fragment = &request_url[frag_pos..];
                        if !current_url.contains('#') {
                            current_url.push_str(fragment);
                        }
                    }

                    // 301, 302, 303: POST -> GET (but HEAD stays HEAD)
                    if matches!(status, 301 | 302 | 303) && current_method.to_uppercase() != "HEAD"
                    {
                        current_method = "GET".to_string();
                        // Clear body for redirected GET
                        params.data = None;
                        params.json = None;
                    }
                    // 307, 308: method stays the same

                    // Don't re-apply query params on redirect URLs
                    params.params = None;
                } else {
                    // No location header, stop redirecting
                    break;
                }
                continue;
            }

            // Final response
            let resp_headers = Self::extract_response_headers(&response);
            let resp_cookies = Self::extract_response_cookies(&response);
            let reason = reason_phrase(status);
            let resp_url = response.url().to_string();

            let body = response
                .bytes()
                .map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())
                })?
                .to_vec();

            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

            // For the final response, update final_request_headers
            final_request_headers = req_headers;

            // Append fragment to URL if present in original request
            let mut final_url = resp_url;
            if let Some(frag_pos) = request_url.find('#') {
                let fragment = &request_url[frag_pos..];
                if !final_url.contains('#') {
                    final_url.push_str(fragment);
                }
            }

            return Ok(Response::new(
                status,
                final_url,
                resp_headers,
                body,
                elapsed_ms,
                history,
                resp_cookies,
                reason,
                is_redir,
                current_method,
                request_url,
                final_request_headers,
            ));
        }

        // Should not be reached, but just in case
        Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "Unexpected end of redirect chain",
        ))
    }
}

#[pymethods]
impl Session {
    #[new]
    fn new() -> Self {
        Session {
            clients: Mutex::new(HashMap::new()),
            cookie_jar: Mutex::new(HashMap::new()),
            max_redirects: MAX_REDIRECTS,
            default_headers: None,
            default_auth: None,
            default_params: None,
        }
    }

    #[pyo3(signature = (
        method,
        url,
        *,
        params = None,
        data = None,
        json = None,
        headers = None,
        cookies = None,
        files = None,
        auth = None,
        timeout = None,
        allow_redirects = None,
        proxies = None,
        stream = None,
        verify = None,
        cert = None
    ))]
    fn make_request(
        &self,
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
        verify: Option<bool>,
        cert: Option<CertParameter>,
    ) -> PyResult<Response> {
        // Validate URL first
        validate_url(&url)?;

        let params = RequestParams::from_args(
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
            allow_redirects,
            proxies,
            stream,
            verify,
            cert,
        );

        self.do_request(params)
    }

    fn close(&self) {
        let mut clients = self.clients.lock().unwrap();
        clients.clear();
        let mut cookies = self.cookie_jar.lock().unwrap();
        cookies.clear();
    }

    fn get_cookies(&self) -> HashMap<String, String> {
        let jar = self.cookie_jar.lock().unwrap();
        jar.clone()
    }

    fn set_cookies(&self, cookies: HashMap<String, String>) {
        let mut jar = self.cookie_jar.lock().unwrap();
        jar.extend(cookies);
    }

    fn set_cookie(&self, key: String, value: String) {
        let mut jar = self.cookie_jar.lock().unwrap();
        jar.insert(key, value);
    }

    fn remove_cookie(&self, key: &str) {
        let mut jar = self.cookie_jar.lock().unwrap();
        jar.remove(key);
    }
}

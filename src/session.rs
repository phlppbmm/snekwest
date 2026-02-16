use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict};
use pythonize::depythonize;
use reqwest::blocking::{Client, ClientBuilder};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use crate::exceptions::{raise_exception, raise_nested_exception};
use crate::request_params::CertParameter;
use crate::request_params::{DataParameter, RequestParams, TimeoutParameter, VerifyParameter};
use crate::response::{RawResponseData, Response, StreamingInner};

const MAX_REDIRECTS: usize = 30;

fn reason_phrase(status: u16) -> Option<String> {
    let phrase = match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a Teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => return None,
    };
    Some(phrase.to_string())
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Decide whether the Authorization header should be stripped when redirecting
/// from `old_url` to `new_url`. Mirrors requests' `should_strip_auth`.
fn should_strip_auth(old_url: &str, new_url: &str) -> bool {
    let old = match url::Url::parse(old_url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let new = match url::Url::parse(new_url) {
        Ok(u) => u,
        Err(_) => return false,
    };

    // Different host → always strip
    if old.host_str() != new.host_str() {
        return true;
    }

    // HTTP → HTTPS on default ports → safe upgrade, don't strip
    let old_port = old.port_or_known_default();
    let new_port = new.port_or_known_default();
    if old.scheme() == "http"
        && new.scheme() == "https"
        && old_port == Some(80)
        && new_port == Some(443)
    {
        return false;
    }

    let changed_scheme = old.scheme() != new.scheme();
    let changed_port = old_port != new_port;

    // Same scheme, both on default ports → don't strip
    if !changed_scheme {
        let default_port = match old.scheme() {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        };
        let old_is_default = old.port().is_none() || old.port() == default_port;
        let new_is_default = new.port().is_none() || new.port() == default_port;
        if old_is_default && new_is_default {
            return false;
        }
    }

    changed_port || changed_scheme
}

/// Validate the URL and raise the appropriate Python exception for invalid URLs.
fn validate_url(py: Python<'_>, url: &str) -> PyResult<()> {
    // Empty or whitespace-only
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(raise_exception(
            py,
            "InvalidURL",
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
                return Err(raise_exception(
                    py,
                    "InvalidSchema",
                    format!("No connection adapters were found for {:?}", url),
                ));
            }

            // Has http/https scheme - check for valid host
            let after_scheme = &trimmed[colon_pos + 1..];
            let after_slashes = after_scheme.trim_start_matches('/');

            if after_slashes.is_empty() {
                return Err(raise_exception(
                    py,
                    "InvalidURL",
                    format!("Invalid URL {:?}: No host supplied", url),
                ));
            }

            // Extract authority (before first /) and strip userinfo (user:pass@)
            let authority = after_slashes.split('/').next().unwrap_or("");
            let host = if let Some(at_pos) = authority.rfind('@') {
                &authority[at_pos + 1..]
            } else {
                authority
            };

            // Detect bare IPv6 addresses (without brackets)
            // e.g. http://fe80::5054:ff:fe5a:fc0 is invalid, should be http://[fe80::...]/
            if !host.starts_with('[') && host.chars().filter(|c| *c == ':').count() > 1 {
                return Err(raise_exception(
                    py,
                    "InvalidURL",
                    format!("Invalid URL {:?}: Invalid IPv6 URL", url),
                ));
            }

            let host_no_port = host.split(':').next().unwrap_or("");
            if host_no_port.is_empty() {
                return Err(raise_exception(
                    py,
                    "InvalidURL",
                    format!("Invalid URL {:?}: No host supplied", url),
                ));
            }
            if host_no_port.starts_with('*') || host_no_port.starts_with('.') {
                return Err(raise_exception(
                    py,
                    "InvalidURL",
                    format!("Invalid URL {:?}: Invalid host", url),
                ));
            }

            return Ok(());
        }
    }

    // No valid scheme found - check if it looks like host:port (InvalidSchema)
    // or just a bare word (MissingSchema)
    if trimmed.contains(':') || trimmed.contains('/') {
        // Looks like host:port or host/path without a scheme
        return Err(raise_exception(
            py,
            "InvalidSchema",
            format!("No connection adapters were found for {:?}", url),
        ));
    }

    Err(raise_exception(
        py,
        "MissingSchema",
        format!(
            "Invalid URL {:?}: No scheme supplied. Perhaps you meant \"https://{}\"?",
            url, url
        ),
    ))
}

fn repr_str(s: &str) -> String {
    format!("'{}'", s)
}

/// Check if the error originates from an SSL/TLS issue by walking the source chain.
/// This avoids false positives from URLs containing "ssl" in the path.
fn is_ssl_error(e: &reqwest::Error) -> bool {
    use std::error::Error;
    // Skip the top-level reqwest error (which contains the URL) and check sources
    let mut source: Option<&dyn Error> = e.source();
    while let Some(s) = source {
        let msg = s.to_string().to_lowercase();
        if msg.contains("certificate")
            || msg.contains("handshake")
            || msg.contains("unknown issuer")
            || msg.contains("self signed")
            || msg.contains("alertreceived")
        {
            return true;
        }
        source = s.source();
    }
    false
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
///
/// - `had_explicit_connect_timeout`: true when the user passed a (connect, read) timeout tuple
///   with a non-None connect value, signaling that ConnectTimeout should be raised.
/// - `connect_timeout_secs`: the connect timeout value in seconds (if any), used to disambiguate
///   timeout errors that fire during the connect phase when request.timeout races with connect_timeout.
/// - `elapsed`: how long the request took before the error occurred.
fn map_reqwest_error(
    py: Python<'_>,
    e: reqwest::Error,
    had_explicit_connect_timeout: bool,
    has_proxies: bool,
) -> PyErr {
    let msg = full_error_chain(&e);

    // 1. SSL/TLS errors — check source chain (not URL text)
    if is_ssl_error(&e) {
        return raise_exception(py, "SSLError", msg);
    }

    // 2. Connection errors that are NOT timeouts (connection refused, reset, etc.)
    if e.is_connect() && !e.is_timeout() {
        let lower = msg.to_lowercase();
        if has_proxies || lower.contains("proxy") || lower.contains("tunnel") {
            return raise_exception(py, "ProxyError", msg);
        }
        return raise_exception(py, "ConnectionError", msg);
    }

    // 3. Timeout errors
    if e.is_timeout() {
        if e.is_connect() {
            if had_explicit_connect_timeout {
                return raise_nested_exception(
                    py,
                    "ConnectTimeout",
                    format!("ConnectTimeout: connection timed out. {}", msg),
                );
            }
            // Connection attempt timed out under a general/single timeout
            return raise_exception(py, "ConnectionError", msg);
        }
        // Read / general timeout
        let read_msg = if msg.to_lowercase().contains("timed out") {
            format!("Read timed out. (read timeout={})", msg)
        } else {
            format!("Read timed out. {}", msg)
        };
        return raise_nested_exception(py, "ReadTimeout", read_msg);
    }

    // 4. Body/decode errors
    if e.is_decode() {
        return raise_exception(py, "ContentDecodingError", msg);
    }

    // 5. Redirect errors
    if e.is_redirect() {
        return raise_exception(py, "TooManyRedirects", msg);
    }

    // 6. Builder errors
    if e.is_builder() {
        return raise_exception(py, "InvalidURL", msg);
    }

    // 7. Connection closed / chunked encoding
    let lower = msg.to_lowercase();
    if lower.contains("connection closed") || lower.contains("incompletemessage") {
        return raise_exception(py, "ChunkedEncodingError", msg);
    }

    // Default
    raise_exception(py, "ConnectionError", msg)
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
enum VerifyConfig {
    /// Standard TLS verification (system CA store)
    Enabled,
    /// TLS verification disabled
    Disabled,
    /// Custom CA bundle path
    CaBundle(String),
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
enum CertConfig {
    /// Single PEM file containing both cert and key
    Single(String),
    /// Separate cert and key files
    Pair(String, String),
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct ClientConfig {
    verify: VerifyConfig,
    cert: Option<CertConfig>,
    /// Sorted list of (scheme, proxy_url) pairs for deterministic hashing
    proxies: Option<Vec<(String, String)>>,
    connect_timeout_ms: Option<u64>,
}

impl ClientConfig {
    fn from_params(params: &RequestParams) -> Self {
        let connect_timeout_ms = match &params.timeout {
            Some(TimeoutParameter::Pair(Some(c), _)) => Some((*c * 1000.0) as u64),
            Some(TimeoutParameter::Single(s)) => Some((*s * 1000.0) as u64),
            _ => None,
        };
        let proxies = params.proxies.as_ref().map(|p| {
            let mut v: Vec<(String, String)> = p.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            v.sort();
            v
        });
        let verify = match &params.verify {
            Some(VerifyParameter::Bool(false)) => VerifyConfig::Disabled,
            Some(VerifyParameter::CaBundle(path)) => VerifyConfig::CaBundle(path.clone()),
            _ => VerifyConfig::Enabled,
        };
        let cert = params.cert.as_ref().map(|c| match c {
            CertParameter::Single(path) => CertConfig::Single(path.clone()),
            CertParameter::Pair(cert, key) => CertConfig::Pair(cert.clone(), key.clone()),
        });
        Self {
            verify,
            cert,
            proxies,
            connect_timeout_ms,
        }
    }
}

/// Validate a proxy URL and return an error for malformed ones.
/// Mirrors Python requests' check: urlparse the URL and reject if hostname is missing.
/// Non-URL strings (like bare hostnames) are allowed through — they will fail
/// at connection time and be reported as ProxyError.
fn validate_proxy_url(py: Python<'_>, proxy_url: &str) -> PyResult<()> {
    let lower = proxy_url.to_lowercase();

    // Only validate URLs with an http/https scheme
    let after_scheme = if lower.starts_with("https:") {
        &proxy_url[6..]
    } else if lower.starts_with("http:") {
        &proxy_url[5..]
    } else {
        // No recognized scheme — let reqwest handle it.
        // If DNS fails it becomes ProxyError at connection time.
        return Ok(());
    };

    // Must have :// (double slash) after scheme.
    // Single-slash URLs like "http:/foo" are malformed.
    if !after_scheme.starts_with("//") {
        return Err(raise_exception(
            py,
            "InvalidProxyURL",
            "Please check proxy URL. It is malformed and could be missing the host.".to_string(),
        ));
    }

    // After "://", extract the authority (before any path)
    let authority = after_scheme[2..].split('/').next().unwrap_or("");

    // Strip userinfo (user:pass@)
    let host_port = if let Some(at_pos) = authority.rfind('@') {
        &authority[at_pos + 1..]
    } else {
        authority
    };

    // Extract host (strip port)
    let host = if host_port.starts_with('[') {
        // IPv6 — host is everything up to and including ']'
        host_port.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };

    if host.is_empty() {
        return Err(raise_exception(
            py,
            "InvalidProxyURL",
            "Please check proxy URL. It is malformed and could be missing the host.".to_string(),
        ));
    }

    Ok(())
}

#[pyclass(subclass, dict)]
pub struct Session {
    // Internal transport state (used by make_request/do_request chain)
    clients: Mutex<HashMap<ClientConfig, Arc<Client>>>,
    cookie_jar: Mutex<HashMap<String, String>>,
    // Python-facing session attributes
    #[pyo3(get, set)]
    pub headers: Py<PyAny>,
    #[pyo3(get, set)]
    pub cookies: Py<PyAny>,
    #[pyo3(get, set)]
    pub auth: Py<PyAny>,
    #[pyo3(get, set)]
    pub proxies: Py<PyAny>,
    #[pyo3(get, set)]
    pub hooks: Py<PyAny>,
    #[pyo3(get, set)]
    pub params: Py<PyAny>,
    #[pyo3(get, set)]
    pub stream: bool,
    #[pyo3(get, set)]
    pub verify: Py<PyAny>,
    #[pyo3(get, set)]
    pub cert: Py<PyAny>,
    #[pyo3(get, set)]
    pub max_redirects: usize,
    #[pyo3(get, set)]
    pub trust_env: bool,
    #[pyo3(get, set)]
    pub adapters: Py<PyAny>,
}

impl Session {
    fn get_or_create_client(&self, params: &RequestParams) -> PyResult<Arc<Client>> {
        let config = ClientConfig::from_params(params);
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(existing_client) = clients.get(&config) {
            return Ok(existing_client.clone());
        }

        let new_client = self.create_client_for_config(&config)?;
        clients.insert(config, new_client.clone());
        Ok(new_client)
    }

    fn merge_cookies(&self, params: &RequestParams) -> HashMap<String, String> {
        let mut all_cookies = {
            let session_cookies = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
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

        // Merge request params
        let mut merged_params: HashMap<String, String> = HashMap::new();
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

        // Set per-request timeout for the overall request duration.
        // connect_timeout is set on the client builder in create_client_for_config.
        if let Some(timeout_params) = &params.timeout {
            match timeout_params {
                TimeoutParameter::Single(secs) => {
                    request = request.timeout(std::time::Duration::from_secs_f64(*secs));
                }
                TimeoutParameter::Pair(connect, Some(read)) => {
                    let connect_secs = connect.unwrap_or(0.0);
                    request = request.timeout(std::time::Duration::from_secs_f64(
                        connect_secs + *read,
                    ));
                }
                TimeoutParameter::Pair(_, None) => {} // No read timeout
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

    fn update_session_cookies(
        &self,
        response: &reqwest::blocking::Response,
        request_had_cookies: bool,
    ) {
        // Don't update session cookies if the request had per-request cookies
        if request_had_cookies {
            return;
        }

        let mut jar = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());

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

        match &config.verify {
            VerifyConfig::Disabled => {
                builder = builder.danger_accept_invalid_certs(true);
            }
            VerifyConfig::CaBundle(path) => {
                let cert_pem = std::fs::read(path).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                        "Could not read CA bundle: {}: {}",
                        path, e
                    ))
                })?;
                let cert = reqwest::Certificate::from_pem(&cert_pem).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                        "Invalid CA certificate in {}: {}",
                        path, e
                    ))
                })?;
                builder = builder.add_root_certificate(cert);
            }
            VerifyConfig::Enabled => {}
        }

        // Apply client certificate (mTLS) — non-fatal on load failure
        // (cert is only used for HTTPS; for HTTP requests cert is ignored)
        if let Some(ref cert_config) = config.cert {
            let pem_data = match cert_config {
                CertConfig::Single(path) => std::fs::read(path).ok(),
                CertConfig::Pair(cert_path, key_path) => {
                    if let (Ok(mut cert), Ok(key)) =
                        (std::fs::read(cert_path), std::fs::read(key_path))
                    {
                        cert.push(b'\n');
                        cert.extend(key);
                        Some(cert)
                    } else {
                        None
                    }
                }
            };
            if let Some(pem) = pem_data {
                if let Ok(identity) = reqwest::Identity::from_pem(&pem) {
                    builder = builder.identity(identity);
                }
            }
        }

        // Always disable automatic redirects - we handle them manually
        builder = builder.redirect(reqwest::redirect::Policy::none());

        // Note: reqwest auto-decompression is kept enabled (gzip, deflate, brotli).

        if let Some(ct_ms) = config.connect_timeout_ms {
            builder = builder.connect_timeout(std::time::Duration::from_millis(ct_ms));
        }

        // Apply proxy configuration
        if let Some(ref proxies) = config.proxies {
            // Note: no_proxy() only disables system proxy lookups, not custom proxies.
            // But it seems to override custom proxies too in some reqwest versions.
            // So we don't call no_proxy() here.
            for (scheme, proxy_url) in proxies {
                // Validate the proxy URL first
                Python::attach(|py| validate_proxy_url(py, proxy_url))?;

                let proxy = match scheme.to_lowercase().as_str() {
                    "http" => reqwest::Proxy::http(proxy_url),
                    "https" => reqwest::Proxy::https(proxy_url),
                    "all" | "all_proxy" => reqwest::Proxy::all(proxy_url),
                    _ => continue,
                };
                match proxy {
                    Ok(p) => {
                        builder = builder.proxy(p);
                    }
                    Err(_) => {
                        // reqwest couldn't parse the proxy URL.
                        return Python::attach(|py| {
                            Err(raise_exception(
                                py,
                                "ProxyError",
                                format!(
                                    "Cannot connect to proxy. Could not resolve proxy: {}",
                                    proxy_url
                                ),
                            ))
                        });
                    }
                }
            }
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
        has_proxies: bool,
    ) -> PyResult<reqwest::blocking::Response> {
        let request =
            self.build_request(client, method, url, params, cookies, auth, extra_headers)?;
        let request = self.apply_body_and_timeout(request, params)?;

        // Release the GIL so Python-based servers (httpbin etc.) can process
        Python::attach(|py| {
            py.detach(|| {
                request.send()
            })
            .map_err(|e| map_reqwest_error(py, e, had_explicit_connect_timeout, has_proxies))
        })
    }

    fn do_request(&self, mut params: RequestParams) -> PyResult<RawResponseData> {
        let client = self.get_or_create_client(&params)?;
        let start = Instant::now();

        let had_explicit_connect_timeout = matches!(
            &params.timeout,
            Some(TimeoutParameter::Pair(Some(_), _))
        );

        let has_proxies = params.proxies.as_ref().map_or(false, |p| !p.is_empty());

        let original_method = params.method.clone();
        let request_url = params.url.clone();
        let has_request_cookies = params.cookies.is_some();

        // Determine auth from request params
        let auth = params.auth.clone();
        let extra_headers: Option<HashMap<String, String>> = None;

        // Build merged cookies for the first request
        let merged_cookies = self.merge_cookies(&params);

        // Collect request headers for the Request object on the final response
        // We'll capture them from the first redirect step
        let mut current_method = original_method.clone();
        let mut current_url = request_url.clone();
        let mut history: Vec<RawResponseData> = Vec::new();
        let mut current_cookies = merged_cookies;
        let mut current_auth = auth.clone();
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

            let response = self.execute_single_request(
                &client,
                &current_method,
                &current_url,
                &params,
                &current_cookies,
                &current_auth,
                &extra_headers,
                had_explicit_connect_timeout,
                has_proxies,
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
                    return Python::attach(|py| {
                        Err(raise_exception(
                            py,
                            "TooManyRedirects",
                            format!("Exceeded {} redirects.", max_redirects),
                        ))
                    });
                }

                // Get redirect location — if missing, treat as final response
                let location = match response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                {
                    Some(loc) => loc,
                    None => {
                        // No Location header — return this as the final response
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
                        final_request_headers = req_headers;
                        let mut final_url = resp_url;
                        if let Some(frag_pos) = request_url.find('#') {
                            let fragment = &request_url[frag_pos..];
                            if !final_url.contains('#') {
                                final_url.push_str(fragment);
                            }
                        }
                        return Ok(RawResponseData {
                            status,
                            url: final_url,
                            headers: resp_headers,
                            body,
                            elapsed_ms,
                            history,
                            cookies: resp_cookies,
                            reason,
                            is_redirect: is_redir,
                            method: current_method,
                            request_url,
                            request_headers: final_request_headers,
                            streaming_inner: None,
                            streaming_headers: None,
                        });
                    }
                };

                let resp_headers = Self::extract_response_headers(&response);
                let resp_cookies = Self::extract_response_cookies(&response);
                let reason = reason_phrase(status);
                let resp_url = response.url().to_string();

                // Read body for intermediate response
                let body = response.bytes().unwrap_or_default().to_vec();

                // Build intermediate response for history
                let intermediate = RawResponseData {
                    status,
                    url: resp_url,
                    headers: resp_headers,
                    body,
                    elapsed_ms: 0.0,
                    history: Vec::new(),
                    cookies: resp_cookies,
                    reason,
                    is_redirect: true,
                    method: current_method.clone(),
                    request_url: current_url.clone(),
                    request_headers: req_headers.clone(),
                    streaming_inner: None,
                    streaming_headers: None,
                };
                history.push(intermediate);

                let previous_url = current_url.clone();

                // Resolve redirect URL against current URL
                current_url = if let Ok(base) = url::Url::parse(&current_url) {
                    base.join(&location).map(|u| u.to_string()).unwrap_or(location)
                } else {
                    location
                };

                // Maintain fragment from original URL
                if let Some(frag_pos) = request_url.find('#') {
                    let fragment = &request_url[frag_pos..];
                    if !current_url.contains('#') {
                        current_url.push_str(fragment);
                    }
                }

                // Strip auth when redirecting to a different host/scheme
                if should_strip_auth(&previous_url, &current_url) {
                    current_auth = None;
                    params.headers.as_mut().map(|h| h.remove("Authorization"));
                }

                // 301: only POST -> GET (other methods preserved)
                // 302, 303: all non-HEAD -> GET
                let method_changed;
                if status == 301 && current_method.to_uppercase() == "POST" {
                    current_method = "GET".to_string();
                    method_changed = true;
                } else if matches!(status, 302 | 303)
                    && current_method.to_uppercase() != "HEAD"
                {
                    current_method = "GET".to_string();
                    method_changed = true;
                } else {
                    method_changed = false;
                }
                // 307, 308: method stays the same

                // Strip body and content headers when method changed to GET
                if method_changed {
                    params.data = None;
                    params.json = None;
                    params.files = None;
                    if let Some(ref mut h) = params.headers {
                        h.remove("Content-Length");
                        h.remove("content-length");
                        h.remove("Content-Type");
                        h.remove("content-type");
                        h.remove("Transfer-Encoding");
                        h.remove("transfer-encoding");
                    }
                }

                // Don't re-apply query params on redirect URLs
                params.params = None;
                continue;
            }

            // Final response
            let resp_headers = Self::extract_response_headers(&response);
            let resp_cookies = Self::extract_response_cookies(&response);
            let reason = reason_phrase(status);
            let resp_url = response.url().to_string();

            // For streaming requests with chunked transfer (no Content-Length),
            // create a StreamingBody for lazy chunk-at-a-time reading instead
            // of calling response.bytes() which hangs when the server doesn't
            // close the connection promptly.
            let is_stream = params.stream.unwrap_or(false);
            let has_content_length = response.headers().contains_key("content-length");
            let streaming = is_stream && !has_content_length;

            // Consume response in exactly one branch to satisfy the borrow checker.
            // For streaming, wrap in Arc<Mutex> for lazy reading; otherwise read eagerly.
            let (body, streaming_inner_opt) = if streaming {
                let inner = StreamingInner(Arc::new(Mutex::new(Some(response))));
                (Vec::new(), Some(inner))
            } else {
                (response.bytes().unwrap_or_default().to_vec(), None)
            };

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

            let streaming_hdrs = if streaming_inner_opt.is_some() {
                Some(resp_headers.clone())
            } else {
                None
            };

            return Ok(RawResponseData {
                status,
                url: final_url,
                headers: resp_headers,
                body,
                elapsed_ms,
                history,
                cookies: resp_cookies,
                reason,
                is_redirect: is_redir,
                method: current_method,
                request_url,
                request_headers: final_request_headers,
                streaming_inner: streaming_inner_opt,
                streaming_headers: streaming_hdrs,
            });
        }
    }
}

#[pymethods]
impl Session {
    #[new]
    fn new(py: Python<'_>) -> PyResult<Self> {
        let utils = py.import("snekwest.utils")?;
        let py_headers = utils.getattr("default_headers")?.call0()?.unbind();
        let cookies_mod = py.import("snekwest.cookies")?;
        let py_cookies = cookies_mod
            .getattr("cookiejar_from_dict")?
            .call1((PyDict::new(py),))?
            .unbind();
        let hooks_mod = py.import("snekwest.hooks")?;
        let py_hooks = hooks_mod.getattr("default_hooks")?.call0()?.unbind();
        let adapters_cls = py.import("collections")?.getattr("OrderedDict")?;
        let py_adapters = adapters_cls.call0()?.unbind();

        Ok(Session {
            clients: Mutex::new(HashMap::new()),
            cookie_jar: Mutex::new(HashMap::new()),
            headers: py_headers,
            cookies: py_cookies,
            auth: py.None().into(),
            proxies: PyDict::new(py).into_any().unbind(),
            hooks: py_hooks,
            params: PyDict::new(py).into_any().unbind(),
            stream: false,
            verify: PyBool::new(py, true).to_owned().into_any().unbind(),
            cert: py.None().into(),
            max_redirects: MAX_REDIRECTS,
            trust_env: true,
            adapters: py_adapters,
        })
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
        py: Python<'_>,
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
    ) -> PyResult<Response> {
        // Validate URL first
        validate_url(py, &url)?;

        let req_params = RequestParams::from_args(
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

        let raw = self.do_request(req_params)?;
        Response::from_raw(py, raw)
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        // Close all adapters
        let adapters = self.adapters.bind(py);
        let builtins = py.import("builtins").ok();
        if let Ok(values) = adapters.call_method0("values") {
            let values_as_list = builtins.and_then(|b| b.getattr("list").ok())
                .and_then(|list_fn| list_fn.call1((&values,)).ok());
            if let Ok(values_list) = values_as_list.unwrap_or(values).extract::<Vec<Py<PyAny>>>() {
                for adapter in values_list {
                    let _ = adapter.call_method0(py, "close");
                }
            }
        }
        // Clear internal state
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        clients.clear();
        let mut cookies = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
        cookies.clear();
        Ok(())
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __exit__(&self, py: Python<'_>, _exc_type: &Bound<'_, PyAny>, _exc_val: &Bound<'_, PyAny>, _exc_tb: &Bound<'_, PyAny>) -> PyResult<()> {
        self.close(py)
    }

    fn mount(&self, py: Python<'_>, prefix: String, adapter: Py<PyAny>) -> PyResult<()> {
        let adapters = self.adapters.bind(py);
        adapters.set_item(&prefix, &adapter)?;
        // Move shorter-prefix keys to end (maintains longest-prefix-first order)
        let prefix_len = prefix.len();
        let builtins = py.import("builtins")?;
        let keys_list: Vec<String> = builtins.getattr("list")?
            .call1((adapters.call_method0("keys")?,))?
            .extract::<Vec<String>>()?;
        for key in &keys_list {
            if key.len() < prefix_len {
                let val = adapters.get_item(key)?;
                adapters.call_method1("__delitem__", (key.as_str(),))?;
                adapters.set_item(key, val)?;
            }
        }
        Ok(())
    }

    fn get_adapter(&self, py: Python<'_>, url: String) -> PyResult<Py<PyAny>> {
        let adapters = self.adapters.bind(py);
        let url_lower = url.to_lowercase();
        let builtins = py.import("builtins")?;
        let items_list: Vec<(String, Py<PyAny>)> = builtins.getattr("list")?
            .call1((adapters.call_method0("items")?,))?
            .extract::<Vec<(String, Py<PyAny>)>>()?;
        for (prefix, adapter) in items_list {
            if url_lower.starts_with(&prefix.to_lowercase()) {
                return Ok(adapter);
            }
        }
        let exc_mod = py.import("snekwest.exceptions")?;
        let invalid_schema = exc_mod.getattr("InvalidSchema")?;
        Err(PyErr::from_value(
            invalid_schema.call1((format!("No connection adapters were found for {url:?}"),))?
        ))
    }

    fn get_cookies_internal(&self) -> HashMap<String, String> {
        let jar = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
        jar.clone()
    }

    fn set_cookies_internal(&self, cookies: HashMap<String, String>) {
        let mut jar = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
        jar.extend(cookies);
    }

    fn set_cookie_internal(&self, key: String, value: String) {
        let mut jar = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
        jar.insert(key, value);
    }

    fn remove_cookie_internal(&self, key: &str) {
        let mut jar = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
        jar.remove(key);
    }

    fn prepare_request(&self, py: Python<'_>, request: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let sessions_mod = py.import("snekwest.sessions")?;
        let merge_setting = sessions_mod.getattr("merge_setting")?;
        let merge_hooks_fn = sessions_mod.getattr("merge_hooks")?;
        let cookies_mod = py.import("snekwest.cookies")?;
        let merge_cookies_fn = cookies_mod.getattr("merge_cookies")?;
        let rcj_cls = cookies_mod.getattr("RequestsCookieJar")?;
        let cookiejar_from_dict = cookies_mod.getattr("cookiejar_from_dict")?;
        let cid_cls = py.import("snekwest.structures")?.getattr("CaseInsensitiveDict")?;

        // Merge cookies: session cookies + request cookies
        let req_cookies = request.getattr("cookies")?;
        let req_cookies = if req_cookies.is_none() || (req_cookies.is_instance_of::<PyDict>() && req_cookies.len()? == 0) {
            cookiejar_from_dict.call1((PyDict::new(py),))?
        } else {
            let cookielib = py.import("http.cookiejar")?;
            let cj_cls = cookielib.getattr("CookieJar")?;
            if req_cookies.is_instance(&cj_cls)? {
                req_cookies
            } else {
                cookiejar_from_dict.call1((&req_cookies,))?
            }
        };
        let merged_cookies = merge_cookies_fn.call1((
            merge_cookies_fn.call1((rcj_cls.call0()?, &self.cookies.bind(py)))?,
            &req_cookies,
        ))?;

        // Auth: trust_env netrc lookup (use is_truthy to match Python's `not auth`)
        let mut auth = request.getattr("auth")?;
        if self.trust_env && !auth.is_truthy()? && !self.auth.bind(py).is_truthy()? {
            // Use sessions module's get_netrc_auth so monkey-patching works
            let sessions_mod = py.import("snekwest.sessions")?;
            let netrc_auth = sessions_mod.getattr("get_netrc_auth")?.call1((request.getattr("url")?,))?;
            if !netrc_auth.is_none() {
                auth = netrc_auth;
            }
        }

        // Create and prepare PreparedRequest
        let prep_cls = py.import("snekwest.models")?.getattr("PreparedRequest")?;
        let p = prep_cls.call0()?;
        let kwargs_dict = PyDict::new(py);
        kwargs_dict.set_item("dict_class", &cid_cls)?;
        let merged_headers = merge_setting.call((
            request.getattr("headers")?,
            &self.headers.bind(py),
        ), Some(&kwargs_dict))?;
        let merged_params = merge_setting.call1((
            request.getattr("params")?,
            &self.params.bind(py),
        ))?;
        let merged_auth = merge_setting.call1((&auth, &self.auth.bind(py)))?;
        let merged_hooks = merge_hooks_fn.call1((
            request.getattr("hooks")?,
            &self.hooks.bind(py),
        ))?;

        let prepare_kwargs = PyDict::new(py);
        prepare_kwargs.set_item("method", request.getattr("method")?.call_method0("upper")?)?;
        prepare_kwargs.set_item("url", request.getattr("url")?)?;
        prepare_kwargs.set_item("files", request.getattr("files")?)?;
        prepare_kwargs.set_item("data", request.getattr("data")?)?;
        prepare_kwargs.set_item("json", request.getattr("json")?)?;
        prepare_kwargs.set_item("headers", &merged_headers)?;
        prepare_kwargs.set_item("params", &merged_params)?;
        prepare_kwargs.set_item("auth", &merged_auth)?;
        prepare_kwargs.set_item("cookies", &merged_cookies)?;
        prepare_kwargs.set_item("hooks", &merged_hooks)?;
        p.call_method("prepare", (), Some(&prepare_kwargs))?;

        Ok(p.unbind())
    }

    fn merge_environment_settings(
        &self,
        py: Python<'_>,
        url: Bound<'_, PyAny>,
        proxies: Bound<'_, PyAny>,
        stream: Bound<'_, PyAny>,
        verify: Bound<'_, PyAny>,
        cert: Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let sessions_mod = py.import("snekwest.sessions")?;
        let merge_setting = sessions_mod.getattr("merge_setting")?;
        let os = py.import("os")?;

        let proxies = proxies.unbind();
        let mut verify = verify.unbind();

        if self.trust_env {
            let utils = py.import("snekwest.utils")?;
            let no_proxy = proxies.bind(py).call_method1("get", ("no_proxy",))?;
            let no_proxy_kw = PyDict::new(py);
            no_proxy_kw.set_item("no_proxy", &no_proxy)?;
            let env_proxies = utils.getattr("get_environ_proxies")?.call((&url,), Some(&no_proxy_kw))?;
            // setdefault for each env proxy
            let env_items = env_proxies.call_method0("items")?;
            let builtins = py.import("builtins")?;
            let env_items_list: Vec<(String, Py<PyAny>)> = builtins.getattr("list")?
                .call1((&env_items,))?.extract()?;
            for (k, v) in env_items_list {
                proxies.bind(py).call_method1("setdefault", (k, v))?;
            }
            // Check REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE
            let verify_bound = verify.bind(py);
            let py_true = PyBool::new(py, true);
            if verify_bound.is(py_true) || verify_bound.is_none() {
                // Replicate: verify = os.environ.get("REQUESTS_CA_BUNDLE")
                //                  or os.environ.get("CURL_CA_BUNDLE")
                //                  or verify
                let environ = os.getattr("environ")?;
                let ca_bundle = environ.call_method1("get", ("REQUESTS_CA_BUNDLE",))?;
                if ca_bundle.is_truthy()? {
                    verify = ca_bundle.unbind();
                } else {
                    let curl_bundle = environ.call_method1("get", ("CURL_CA_BUNDLE",))?;
                    if curl_bundle.is_truthy()? {
                        verify = curl_bundle.unbind();
                    }
                    // else: keep original verify
                }
            }
        }

        let merged_proxies = merge_setting.call1((&proxies, &self.proxies.bind(py)))?;
        let merged_stream = merge_setting.call1((&stream, self.stream))?;
        let merged_verify = merge_setting.call1((&verify, &self.verify.bind(py)))?;
        let merged_cert = merge_setting.call1((&cert, &self.cert.bind(py)))?;

        let result = PyDict::new(py);
        result.set_item("proxies", merged_proxies)?;
        result.set_item("stream", merged_stream)?;
        result.set_item("verify", merged_verify)?;
        result.set_item("cert", merged_cert)?;
        Ok(result.into_any().unbind())
    }

    #[pyo3(signature = (
        method,
        url,
        *,
        params = None,
        data = None,
        headers = None,
        cookies = None,
        files = None,
        auth = None,
        timeout = None,
        allow_redirects = true,
        proxies = None,
        hooks = None,
        stream = None,
        verify = None,
        cert = None,
        json = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn request(
        slf: &Bound<'_, Self>,
        method: Py<PyAny>,
        url: String,
        params: Option<Py<PyAny>>,
        data: Option<Py<PyAny>>,
        headers: Option<Py<PyAny>>,
        cookies: Option<Py<PyAny>>,
        files: Option<Py<PyAny>>,
        auth: Option<Py<PyAny>>,
        timeout: Option<Py<PyAny>>,
        allow_redirects: bool,
        proxies: Option<Py<PyAny>>,
        hooks: Option<Py<PyAny>>,
        stream: Option<Py<PyAny>>,
        verify: Option<Py<PyAny>>,
        cert: Option<Py<PyAny>>,
        json: Option<Py<PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let models_mod = py.import("snekwest.models")?;
        let request_cls = models_mod.getattr("Request")?;

        let req_build_kwargs = PyDict::new(py);
        // Convert method to string (supports both str and bytes)
        let method_str: String = if let Ok(s) = method.extract::<String>(py) {
            s
        } else if let Ok(b) = method.extract::<Vec<u8>>(py) {
            String::from_utf8_lossy(&b).to_string()
        } else {
            method.bind(py).str()?.to_string()
        };
        req_build_kwargs.set_item("method", method_str.to_uppercase())?;
        req_build_kwargs.set_item("url", &url)?;
        req_build_kwargs.set_item("headers", headers.as_ref().map_or_else(|| py.None(), |h| h.clone_ref(py)))?;
        req_build_kwargs.set_item("files", files.as_ref().map_or_else(|| py.None(), |f| f.clone_ref(py)))?;
        req_build_kwargs.set_item("data", data.as_ref().map_or_else(|| PyDict::new(py).into_any().unbind(), |d| d.clone_ref(py)))?;
        req_build_kwargs.set_item("json", json.as_ref().map_or_else(|| py.None(), |j| j.clone_ref(py)))?;
        req_build_kwargs.set_item("params", params.as_ref().map_or_else(|| PyDict::new(py).into_any().unbind(), |p| p.clone_ref(py)))?;
        req_build_kwargs.set_item("auth", auth.as_ref().map_or_else(|| py.None(), |a| a.clone_ref(py)))?;
        req_build_kwargs.set_item("cookies", cookies.as_ref().map_or_else(|| py.None(), |c| c.clone_ref(py)))?;
        req_build_kwargs.set_item("hooks", hooks.as_ref().map_or_else(|| py.None(), |h| h.clone_ref(py)))?;

        let req = request_cls.call((), Some(&req_build_kwargs))?;
        let prep = slf.borrow().prepare_request(py, &req)?;
        let prep_bound = prep.bind(py);

        let py_proxies = proxies.unwrap_or_else(|| PyDict::new(py).into_any().unbind());
        let settings = slf.borrow().merge_environment_settings(
            py,
            prep_bound.getattr("url")?,
            py_proxies.into_bound(py),
            stream.map_or_else(|| py.None().into_bound(py), |s| s.into_bound(py)),
            verify.map_or_else(|| py.None().into_bound(py), |v| v.into_bound(py)),
            cert.map_or_else(|| py.None().into_bound(py), |c| c.into_bound(py)),
        )?;

        let send_kwargs = PyDict::new(py);
        send_kwargs.set_item("timeout", timeout.as_ref().map_or_else(|| py.None(), |t| t.clone_ref(py)))?;
        send_kwargs.set_item("allow_redirects", allow_redirects)?;
        let settings_bound = settings.bind(py);
        if let Ok(settings_dict) = settings_bound.cast::<PyDict>() {
            for (k, v) in settings_dict.iter() {
                send_kwargs.set_item(k, v)?;
            }
        }

        // Call send via Python dispatch so it goes through the correct MRO
        slf.call_method("send", (&prep,), Some(&send_kwargs))
            .map(|r| r.unbind())
    }

    #[pyo3(signature = (url, **kwargs))]
    fn get(slf: &Bound<'_, Self>, url: String, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        if !kw.contains("allow_redirects")? {
            kw.set_item("allow_redirects", true)?;
        }
        slf.call_method("request", ("GET", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, **kwargs))]
    fn options(slf: &Bound<'_, Self>, url: String, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        if !kw.contains("allow_redirects")? {
            kw.set_item("allow_redirects", true)?;
        }
        slf.call_method("request", ("OPTIONS", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, **kwargs))]
    fn head(slf: &Bound<'_, Self>, url: String, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        if !kw.contains("allow_redirects")? {
            kw.set_item("allow_redirects", false)?;
        }
        slf.call_method("request", ("HEAD", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, data = None, json = None, **kwargs))]
    fn post(slf: &Bound<'_, Self>, url: String, data: Option<Py<PyAny>>, json: Option<Py<PyAny>>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        kw.set_item("data", data.as_ref().map_or_else(|| py.None(), |d| d.clone_ref(py)))?;
        kw.set_item("json", json.as_ref().map_or_else(|| py.None(), |j| j.clone_ref(py)))?;
        slf.call_method("request", ("POST", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, data = None, **kwargs))]
    fn put(slf: &Bound<'_, Self>, url: String, data: Option<Py<PyAny>>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        kw.set_item("data", data.as_ref().map_or_else(|| py.None(), |d| d.clone_ref(py)))?;
        slf.call_method("request", ("PUT", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, data = None, **kwargs))]
    fn patch(slf: &Bound<'_, Self>, url: String, data: Option<Py<PyAny>>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        kw.set_item("data", data.as_ref().map_or_else(|| py.None(), |d| d.clone_ref(py)))?;
        slf.call_method("request", ("PATCH", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, **kwargs))]
    fn delete(slf: &Bound<'_, Self>, url: String, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        slf.call_method("request", ("DELETE", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (request, **kwargs))]
    fn send(slf: &Bound<'_, Self>, request: Py<PyAny>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();

        // Validate request type
        let models_mod = py.import("snekwest.models")?;
        let request_cls = models_mod.getattr("Request")?;
        if request.bind(py).is_instance(&request_cls)? {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "You can only send PreparedRequests.",
            ));
        }

        // Create kwargs dict if not provided
        let kwargs = match kwargs {
            Some(kw) => kw.copy()?,
            None => PyDict::new(py).clone(),
        };

        // Fill in defaults from session
        {
            let this = slf.borrow();
            if !kwargs.contains("stream")? {
                kwargs.set_item("stream", this.stream)?;
            }
            if !kwargs.contains("verify")? {
                kwargs.set_item("verify", &this.verify)?;
            }
            if !kwargs.contains("cert")? {
                kwargs.set_item("cert", &this.cert)?;
            }
            if !kwargs.contains("proxies")? {
                let utils = py.import("snekwest.utils")?;
                let resolved = utils.getattr("resolve_proxies")?.call1((
                    &request,
                    &this.proxies.bind(py),
                    this.trust_env,
                ))?;
                kwargs.set_item("proxies", resolved)?;
            }
        } // drop borrow

        let allow_redirects: bool = kwargs.get_item("allow_redirects")?
            .map(|v| v.extract::<bool>())
            .transpose()?
            .unwrap_or(true);
        let _ = kwargs.del_item("allow_redirects");

        let stream: bool = kwargs.get_item("stream")?
            .map(|v| v.extract::<bool>())
            .transpose()?
            .unwrap_or(false);

        // Get hooks from request
        let hooks = request.getattr(py, "hooks")?;

        // Get adapter and send
        let req_url: String = request.getattr(py, "url")?.extract(py)?;
        let adapter = slf.borrow().get_adapter(py, req_url)?;

        let start = std::time::Instant::now();
        let r = adapter.bind(py).call_method(
            "send",
            (&request,),
            Some(&kwargs),
        )?;
        let elapsed_secs = start.elapsed().as_secs_f64();
        let datetime = py.import("datetime")?;
        let timedelta = datetime.getattr("timedelta")?;
        let td_kwargs = PyDict::new(py);
        td_kwargs.set_item("seconds", elapsed_secs)?;
        let elapsed_td = timedelta.call((), Some(&td_kwargs))?;
        r.setattr("elapsed", elapsed_td)?;

        // Dispatch response hooks
        let hooks_mod = py.import("snekwest.hooks")?;
        let dispatch_hook = hooks_mod.getattr("dispatch_hook")?;
        let r = dispatch_hook.call(("response", &hooks, &r), Some(&kwargs))?;

        // Extract cookies from history
        let cookies_mod = py.import("snekwest.cookies")?;
        let extract_cookies = cookies_mod.getattr("extract_cookies_to_jar")?;
        let session_cookies = slf.borrow().cookies.clone_ref(py);
        let history = r.getattr("history")?;
        if history.is_truthy()? {
            let hist_list: Vec<Py<PyAny>> = history.extract()?;
            for resp in &hist_list {
                let resp_bound = resp.bind(py);
                extract_cookies.call1((
                    &session_cookies,
                    resp_bound.getattr("request")?,
                    resp_bound.getattr("raw")?,
                ))?;
            }
        }
        extract_cookies.call1((
            &session_cookies,
            &request,
            r.getattr("raw")?,
        ))?;

        // Handle redirects - call resolve_redirects via Python self (which inherits the mixin)
        if allow_redirects {
            let gen = slf.call_method("resolve_redirects", (&r, &request), Some(&kwargs))?;
            let builtins = py.import("builtins")?;
            let history_list = builtins.getattr("list")?.call1((&gen,))?;
            let history: Vec<Py<PyAny>> = history_list.extract()?;
            if !history.is_empty() {
                let mut full_history = vec![r.unbind()];
                full_history.extend(history);
                let final_resp = full_history.pop().unwrap();
                let hist_list = pyo3::types::PyList::new(py, &full_history)?;
                final_resp.setattr(py, "history", hist_list)?;

                if !stream {
                    let _ = final_resp.getattr(py, "content")?;
                }
                return Ok(final_resp);
            }
        } else {
            // Set _next for non-redirect responses
            let yield_kwargs = kwargs.copy()?;
            yield_kwargs.set_item("yield_requests", true)?;
            let gen = slf.call_method("resolve_redirects", (&r, &request), Some(&yield_kwargs))?;
            let builtins = py.import("builtins")?;
            let next_fn = builtins.getattr("next")?;
            let result = next_fn.call1((&gen, py.None()))?;
            if !result.is_none() {
                r.setattr("_next", result)?;
            }
        }

        if !stream {
            let _ = r.getattr("content")?;
        }
        Ok(r.unbind())
    }
}

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict};
use pythonize::depythonize;
use reqwest::blocking::{Client, ClientBuilder};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use crate::exceptions::{raise_exception, raise_nested_exception};
use crate::request_params::CertParameter;
use crate::request_params::{DataParameter, RequestParams, TimeoutParameter, VerifyParameter};
use crate::response::{RawResponseData, Response, StreamingInner};

const MAX_REDIRECTS: usize = 30;

fn reason_phrase(status: u16) -> Option<String> {
    let phrase = match status {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a Teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => return None,
    };
    Some(phrase.to_string())
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Decide whether the Authorization header should be stripped when redirecting
/// from `old_url` to `new_url`. Mirrors requests' `should_strip_auth`.
fn should_strip_auth(old_url: &str, new_url: &str) -> bool {
    let old = match url::Url::parse(old_url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let new = match url::Url::parse(new_url) {
        Ok(u) => u,
        Err(_) => return false,
    };

    // Different host → always strip
    if old.host_str() != new.host_str() {
        return true;
    }

    // HTTP → HTTPS on default ports → safe upgrade, don't strip
    let old_port = old.port_or_known_default();
    let new_port = new.port_or_known_default();
    if old.scheme() == "http"
        && new.scheme() == "https"
        && old_port == Some(80)
        && new_port == Some(443)
    {
        return false;
    }

    let changed_scheme = old.scheme() != new.scheme();
    let changed_port = old_port != new_port;

    // Same scheme, both on default ports → don't strip
    if !changed_scheme {
        let default_port = match old.scheme() {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        };
        let old_is_default = old.port().is_none() || old.port() == default_port;
        let new_is_default = new.port().is_none() || new.port() == default_port;
        if old_is_default && new_is_default {
            return false;
        }
    }

    changed_port || changed_scheme
}

/// Validate the URL and raise the appropriate Python exception for invalid URLs.
fn validate_url(py: Python<'_>, url: &str) -> PyResult<()> {
    // Empty or whitespace-only
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(raise_exception(
            py,
            "InvalidURL",
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
                return Err(raise_exception(
                    py,
                    "InvalidSchema",
                    format!("No connection adapters were found for {:?}", url),
                ));
            }

            // Has http/https scheme - check for valid host
            let after_scheme = &trimmed[colon_pos + 1..];
            let after_slashes = after_scheme.trim_start_matches('/');

            if after_slashes.is_empty() {
                return Err(raise_exception(
                    py,
                    "InvalidURL",
                    format!("Invalid URL {:?}: No host supplied", url),
                ));
            }

            // Extract authority (before first /) and strip userinfo (user:pass@)
            let authority = after_slashes.split('/').next().unwrap_or("");
            let host = if let Some(at_pos) = authority.rfind('@') {
                &authority[at_pos + 1..]
            } else {
                authority
            };

            // Detect bare IPv6 addresses (without brackets)
            // e.g. http://fe80::5054:ff:fe5a:fc0 is invalid, should be http://[fe80::...]/
            if !host.starts_with('[') && host.chars().filter(|c| *c == ':').count() > 1 {
                return Err(raise_exception(
                    py,
                    "InvalidURL",
                    format!("Invalid URL {:?}: Invalid IPv6 URL", url),
                ));
            }

            let host_no_port = host.split(':').next().unwrap_or("");
            if host_no_port.is_empty() {
                return Err(raise_exception(
                    py,
                    "InvalidURL",
                    format!("Invalid URL {:?}: No host supplied", url),
                ));
            }
            if host_no_port.starts_with('*') || host_no_port.starts_with('.') {
                return Err(raise_exception(
                    py,
                    "InvalidURL",
                    format!("Invalid URL {:?}: Invalid host", url),
                ));
            }

            return Ok(());
        }
    }

    // No valid scheme found - check if it looks like host:port (InvalidSchema)
    // or just a bare word (MissingSchema)
    if trimmed.contains(':') || trimmed.contains('/') {
        // Looks like host:port or host/path without a scheme
        return Err(raise_exception(
            py,
            "InvalidSchema",
            format!("No connection adapters were found for {:?}", url),
        ));
    }

    Err(raise_exception(
        py,
        "MissingSchema",
        format!(
            "Invalid URL {:?}: No scheme supplied. Perhaps you meant \"https://{}\"?",
            url, url
        ),
    ))
}

fn repr_str(s: &str) -> String {
    format!("'{}'", s)
}

/// Check if the error originates from an SSL/TLS issue by walking the source chain.
/// This avoids false positives from URLs containing "ssl" in the path.
fn is_ssl_error(e: &reqwest::Error) -> bool {
    use std::error::Error;
    // Skip the top-level reqwest error (which contains the URL) and check sources
    let mut source: Option<&dyn Error> = e.source();
    while let Some(s) = source {
        let msg = s.to_string().to_lowercase();
        if msg.contains("certificate")
            || msg.contains("handshake")
            || msg.contains("unknown issuer")
            || msg.contains("self signed")
            || msg.contains("alertreceived")
        {
            return true;
        }
        source = s.source();
    }
    false
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
///
/// - `had_explicit_connect_timeout`: true when the user passed a (connect, read) timeout tuple
///   with a non-None connect value, signaling that ConnectTimeout should be raised.
/// - `connect_timeout_secs`: the connect timeout value in seconds (if any), used to disambiguate
///   timeout errors that fire during the connect phase when request.timeout races with connect_timeout.
/// - `elapsed`: how long the request took before the error occurred.
fn map_reqwest_error(
    py: Python<'_>,
    e: reqwest::Error,
    had_explicit_connect_timeout: bool,
    has_proxies: bool,
) -> PyErr {
    let msg = full_error_chain(&e);

    // 1. SSL/TLS errors — check source chain (not URL text)
    if is_ssl_error(&e) {
        return raise_exception(py, "SSLError", msg);
    }

    // 2. Connection errors that are NOT timeouts (connection refused, reset, etc.)
    if e.is_connect() && !e.is_timeout() {
        let lower = msg.to_lowercase();
        if has_proxies || lower.contains("proxy") || lower.contains("tunnel") {
            return raise_exception(py, "ProxyError", msg);
        }
        return raise_exception(py, "ConnectionError", msg);
    }

    // 3. Timeout errors
    if e.is_timeout() {
        if e.is_connect() {
            if had_explicit_connect_timeout {
                return raise_nested_exception(
                    py,
                    "ConnectTimeout",
                    format!("ConnectTimeout: connection timed out. {}", msg),
                );
            }
            // Connection attempt timed out under a general/single timeout
            return raise_exception(py, "ConnectionError", msg);
        }
        // Read / general timeout
        let read_msg = if msg.to_lowercase().contains("timed out") {
            format!("Read timed out. (read timeout={})", msg)
        } else {
            format!("Read timed out. {}", msg)
        };
        return raise_nested_exception(py, "ReadTimeout", read_msg);
    }

    // 4. Body/decode errors
    if e.is_decode() {
        return raise_exception(py, "ContentDecodingError", msg);
    }

    // 5. Redirect errors
    if e.is_redirect() {
        return raise_exception(py, "TooManyRedirects", msg);
    }

    // 6. Builder errors
    if e.is_builder() {
        return raise_exception(py, "InvalidURL", msg);
    }

    // 7. Connection closed / chunked encoding
    let lower = msg.to_lowercase();
    if lower.contains("connection closed") || lower.contains("incompletemessage") {
        return raise_exception(py, "ChunkedEncodingError", msg);
    }

    // Default
    raise_exception(py, "ConnectionError", msg)
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
enum VerifyConfig {
    /// Standard TLS verification (system CA store)
    Enabled,
    /// TLS verification disabled
    Disabled,
    /// Custom CA bundle path
    CaBundle(String),
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
enum CertConfig {
    /// Single PEM file containing both cert and key
    Single(String),
    /// Separate cert and key files
    Pair(String, String),
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct ClientConfig {
    verify: VerifyConfig,
    cert: Option<CertConfig>,
    /// Sorted list of (scheme, proxy_url) pairs for deterministic hashing
    proxies: Option<Vec<(String, String)>>,
    connect_timeout_ms: Option<u64>,
}

impl ClientConfig {
    fn from_params(params: &RequestParams) -> Self {
        let connect_timeout_ms = match &params.timeout {
            Some(TimeoutParameter::Pair(Some(c), _)) => Some((*c * 1000.0) as u64),
            Some(TimeoutParameter::Single(s)) => Some((*s * 1000.0) as u64),
            _ => None,
        };
        let proxies = params.proxies.as_ref().map(|p| {
            let mut v: Vec<(String, String)> = p.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            v.sort();
            v
        });
        let verify = match &params.verify {
            Some(VerifyParameter::Bool(false)) => VerifyConfig::Disabled,
            Some(VerifyParameter::CaBundle(path)) => VerifyConfig::CaBundle(path.clone()),
            _ => VerifyConfig::Enabled,
        };
        let cert = params.cert.as_ref().map(|c| match c {
            CertParameter::Single(path) => CertConfig::Single(path.clone()),
            CertParameter::Pair(cert, key) => CertConfig::Pair(cert.clone(), key.clone()),
        });
        Self {
            verify,
            cert,
            proxies,
            connect_timeout_ms,
        }
    }
}

/// Validate a proxy URL and return an error for malformed ones.
/// Mirrors Python requests' check: urlparse the URL and reject if hostname is missing.
/// Non-URL strings (like bare hostnames) are allowed through — they will fail
/// at connection time and be reported as ProxyError.
fn validate_proxy_url(py: Python<'_>, proxy_url: &str) -> PyResult<()> {
    let lower = proxy_url.to_lowercase();

    // Only validate URLs with an http/https scheme
    let after_scheme = if lower.starts_with("https:") {
        &proxy_url[6..]
    } else if lower.starts_with("http:") {
        &proxy_url[5..]
    } else {
        // No recognized scheme — let reqwest handle it.
        // If DNS fails it becomes ProxyError at connection time.
        return Ok(());
    };

    // Must have :// (double slash) after scheme.
    // Single-slash URLs like "http:/foo" are malformed.
    if !after_scheme.starts_with("//") {
        return Err(raise_exception(
            py,
            "InvalidProxyURL",
            "Please check proxy URL. It is malformed and could be missing the host.".to_string(),
        ));
    }

    // After "://", extract the authority (before any path)
    let authority = after_scheme[2..].split('/').next().unwrap_or("");

    // Strip userinfo (user:pass@)
    let host_port = if let Some(at_pos) = authority.rfind('@') {
        &authority[at_pos + 1..]
    } else {
        authority
    };

    // Extract host (strip port)
    let host = if host_port.starts_with('[') {
        // IPv6 — host is everything up to and including ']'
        host_port.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };

    if host.is_empty() {
        return Err(raise_exception(
            py,
            "InvalidProxyURL",
            "Please check proxy URL. It is malformed and could be missing the host.".to_string(),
        ));
    }

    Ok(())
}

#[pyclass(subclass, dict)]
pub struct Session {
    // Internal transport state (used by make_request/do_request chain)
    clients: Mutex<HashMap<ClientConfig, Arc<Client>>>,
    cookie_jar: Mutex<HashMap<String, String>>,
    // Python-facing session attributes
    #[pyo3(get, set)]
    pub headers: Py<PyAny>,
    #[pyo3(get, set)]
    pub cookies: Py<PyAny>,
    #[pyo3(get, set)]
    pub auth: Py<PyAny>,
    #[pyo3(get, set)]
    pub proxies: Py<PyAny>,
    #[pyo3(get, set)]
    pub hooks: Py<PyAny>,
    #[pyo3(get, set)]
    pub params: Py<PyAny>,
    #[pyo3(get, set)]
    pub stream: bool,
    #[pyo3(get, set)]
    pub verify: Py<PyAny>,
    #[pyo3(get, set)]
    pub cert: Py<PyAny>,
    #[pyo3(get, set)]
    pub max_redirects: usize,
    #[pyo3(get, set)]
    pub trust_env: bool,
    #[pyo3(get, set)]
    pub adapters: Py<PyAny>,
}

impl Session {
    fn get_or_create_client(&self, params: &RequestParams) -> PyResult<Arc<Client>> {
        let config = ClientConfig::from_params(params);
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(existing_client) = clients.get(&config) {
            return Ok(existing_client.clone());
        }

        let new_client = self.create_client_for_config(&config)?;
        clients.insert(config, new_client.clone());
        Ok(new_client)
    }

    fn merge_cookies(&self, params: &RequestParams) -> HashMap<String, String> {
        let mut all_cookies = {
            let session_cookies = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
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

        // Merge request params
        let mut merged_params: HashMap<String, String> = HashMap::new();
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

        // Set per-request timeout for the overall request duration.
        // Note: connect_timeout is set on the client builder in create_client_for_config.
        // For Single timeouts, we add a small margin (50ms) so that connect_timeout
        // fires first for connect-phase failures (avoiding a race condition in reqwest
        // where request.timeout fires before connect_timeout).
        if let Some(timeout_params) = &params.timeout {
            match timeout_params {
                TimeoutParameter::Single(secs) => {
                    // Add 50ms margin so connect_timeout fires first
                    request = request.timeout(std::time::Duration::from_secs_f64(*secs + 0.05));
                }
                TimeoutParameter::Pair(connect, Some(read)) => {
                    // Overall timeout = connect + read so connect_timeout fires first
                    let connect_secs = connect.unwrap_or(0.0);
                    request = request.timeout(std::time::Duration::from_secs_f64(
                        connect_secs + *read,
                    ));
                }
                TimeoutParameter::Pair(_, None) => {} // No read timeout
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

    fn update_session_cookies(
        &self,
        response: &reqwest::blocking::Response,
        request_had_cookies: bool,
    ) {
        // Don't update session cookies if the request had per-request cookies
        if request_had_cookies {
            return;
        }

        let mut jar = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());

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
    ) -> Vec<(String, String)> {
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

        match &config.verify {
            VerifyConfig::Disabled => {
                builder = builder.danger_accept_invalid_certs(true);
            }
            VerifyConfig::CaBundle(path) => {
                let cert_pem = std::fs::read(path).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                        "Could not read CA bundle: {}: {}",
                        path, e
                    ))
                })?;
                let cert = reqwest::Certificate::from_pem(&cert_pem).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                        "Invalid CA certificate in {}: {}",
                        path, e
                    ))
                })?;
                builder = builder.add_root_certificate(cert);
            }
            VerifyConfig::Enabled => {}
        }

        // Apply client certificate (mTLS) — non-fatal on load failure
        // (cert is only used for HTTPS; for HTTP requests cert is ignored)
        if let Some(ref cert_config) = config.cert {
            let pem_data = match cert_config {
                CertConfig::Single(path) => std::fs::read(path).ok(),
                CertConfig::Pair(cert_path, key_path) => {
                    if let (Ok(mut cert), Ok(key)) =
                        (std::fs::read(cert_path), std::fs::read(key_path))
                    {
                        cert.push(b'\n');
                        cert.extend(key);
                        Some(cert)
                    } else {
                        None
                    }
                }
            };
            if let Some(pem) = pem_data {
                if let Ok(identity) = reqwest::Identity::from_pem(&pem) {
                    builder = builder.identity(identity);
                }
            }
        }

        // Always disable automatic redirects - we handle them manually
        builder = builder.redirect(reqwest::redirect::Policy::none());

        // Note: reqwest auto-decompression is kept enabled (gzip, deflate, brotli).

        if let Some(ct_ms) = config.connect_timeout_ms {
            builder = builder.connect_timeout(std::time::Duration::from_millis(ct_ms));
        }

        // Apply proxy configuration
        if let Some(ref proxies) = config.proxies {
            // Note: no_proxy() only disables system proxy lookups, not custom proxies.
            // But it seems to override custom proxies too in some reqwest versions.
            // So we don't call no_proxy() here.
            for (scheme, proxy_url) in proxies {
                // Validate the proxy URL first
                Python::attach(|py| validate_proxy_url(py, proxy_url))?;

                let proxy = match scheme.to_lowercase().as_str() {
                    "http" => reqwest::Proxy::http(proxy_url),
                    "https" => reqwest::Proxy::https(proxy_url),
                    "all" | "all_proxy" => reqwest::Proxy::all(proxy_url),
                    _ => continue,
                };
                match proxy {
                    Ok(p) => {
                        builder = builder.proxy(p);
                    }
                    Err(_) => {
                        // reqwest couldn't parse the proxy URL.
                        return Python::attach(|py| {
                            Err(raise_exception(
                                py,
                                "ProxyError",
                                format!(
                                    "Cannot connect to proxy. Could not resolve proxy: {}",
                                    proxy_url
                                ),
                            ))
                        });
                    }
                }
            }
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
        has_proxies: bool,
    ) -> PyResult<reqwest::blocking::Response> {
        let request =
            self.build_request(client, method, url, params, cookies, auth, extra_headers)?;
        let request = self.apply_body_and_timeout(request, params)?;

        // Release the GIL so Python-based servers (httpbin etc.) can process
        Python::attach(|py| {
            py.detach(|| {
                request.send()
            })
            .map_err(|e| map_reqwest_error(py, e, had_explicit_connect_timeout, has_proxies))
        })
    }

    fn do_request(&self, mut params: RequestParams) -> PyResult<RawResponseData> {
        let client = self.get_or_create_client(&params)?;
        let start = Instant::now();

        let had_explicit_connect_timeout = matches!(
            &params.timeout,
            Some(TimeoutParameter::Pair(Some(_), _))
        );

        let has_proxies = params.proxies.as_ref().map_or(false, |p| !p.is_empty());

        let original_method = params.method.clone();
        let request_url = params.url.clone();
        let has_request_cookies = params.cookies.is_some();

        // Determine auth from request params
        let auth = params.auth.clone();
        let extra_headers: Option<HashMap<String, String>> = None;

        // Build merged cookies for the first request
        let merged_cookies = self.merge_cookies(&params);

        // Collect request headers for the Request object on the final response
        // We'll capture them from the first redirect step
        let mut current_method = original_method.clone();
        let mut current_url = request_url.clone();
        let mut history: Vec<RawResponseData> = Vec::new();
        let mut current_cookies = merged_cookies;
        let mut current_auth = auth.clone();
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

            let response = self.execute_single_request(
                &client,
                &current_method,
                &current_url,
                &params,
                &current_cookies,
                &current_auth,
                &extra_headers,
                had_explicit_connect_timeout,
                has_proxies,
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
                    return Python::attach(|py| {
                        Err(raise_exception(
                            py,
                            "TooManyRedirects",
                            format!("Exceeded {} redirects.", max_redirects),
                        ))
                    });
                }

                // Get redirect location — if missing, treat as final response
                let location = match response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                {
                    Some(loc) => loc,
                    None => {
                        // No Location header — return this as the final response
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
                        final_request_headers = req_headers;
                        let mut final_url = resp_url;
                        if let Some(frag_pos) = request_url.find('#') {
                            let fragment = &request_url[frag_pos..];
                            if !final_url.contains('#') {
                                final_url.push_str(fragment);
                            }
                        }
                        return Ok(RawResponseData {
                            status,
                            url: final_url,
                            headers: resp_headers,
                            body,
                            elapsed_ms,
                            history,
                            cookies: resp_cookies,
                            reason,
                            is_redirect: is_redir,
                            method: current_method,
                            request_url,
                            request_headers: final_request_headers,
                            streaming_inner: None,
                            streaming_headers: None,
                        });
                    }
                };

                let resp_headers = Self::extract_response_headers(&response);
                let resp_cookies = Self::extract_response_cookies(&response);
                let reason = reason_phrase(status);
                let resp_url = response.url().to_string();

                // Read body for intermediate response
                let body = response.bytes().unwrap_or_default().to_vec();

                // Build intermediate response for history
                let intermediate = RawResponseData {
                    status,
                    url: resp_url,
                    headers: resp_headers,
                    body,
                    elapsed_ms: 0.0,
                    history: Vec::new(),
                    cookies: resp_cookies,
                    reason,
                    is_redirect: true,
                    method: current_method.clone(),
                    request_url: current_url.clone(),
                    request_headers: req_headers.clone(),
                    streaming_inner: None,
                    streaming_headers: None,
                };
                history.push(intermediate);

                let previous_url = current_url.clone();

                // Resolve redirect URL against current URL
                current_url = if let Ok(base) = url::Url::parse(&current_url) {
                    base.join(&location).map(|u| u.to_string()).unwrap_or(location)
                } else {
                    location
                };

                // Maintain fragment from original URL
                if let Some(frag_pos) = request_url.find('#') {
                    let fragment = &request_url[frag_pos..];
                    if !current_url.contains('#') {
                        current_url.push_str(fragment);
                    }
                }

                // Strip auth when redirecting to a different host/scheme
                if should_strip_auth(&previous_url, &current_url) {
                    current_auth = None;
                    params.headers.as_mut().map(|h| h.remove("Authorization"));
                }

                // 301: only POST -> GET (other methods preserved)
                // 302, 303: all non-HEAD -> GET
                let method_changed;
                if status == 301 && current_method.to_uppercase() == "POST" {
                    current_method = "GET".to_string();
                    method_changed = true;
                } else if matches!(status, 302 | 303)
                    && current_method.to_uppercase() != "HEAD"
                {
                    current_method = "GET".to_string();
                    method_changed = true;
                } else {
                    method_changed = false;
                }
                // 307, 308: method stays the same

                // Strip body and content headers when method changed to GET
                if method_changed {
                    params.data = None;
                    params.json = None;
                    params.files = None;
                    if let Some(ref mut h) = params.headers {
                        h.remove("Content-Length");
                        h.remove("content-length");
                        h.remove("Content-Type");
                        h.remove("content-type");
                        h.remove("Transfer-Encoding");
                        h.remove("transfer-encoding");
                    }
                }

                // Don't re-apply query params on redirect URLs
                params.params = None;
                continue;
            }

            // Final response
            let resp_headers = Self::extract_response_headers(&response);
            let resp_cookies = Self::extract_response_cookies(&response);
            let reason = reason_phrase(status);
            let resp_url = response.url().to_string();

            // For streaming requests with chunked transfer (no Content-Length),
            // create a StreamingBody for lazy chunk-at-a-time reading instead
            // of calling response.bytes() which hangs when the server doesn't
            // close the connection promptly.
            let is_stream = params.stream.unwrap_or(false);
            let has_content_length = response.headers().contains_key("content-length");
            let streaming = is_stream && !has_content_length;

            // Consume response in exactly one branch to satisfy the borrow checker.
            // For streaming, wrap in Arc<Mutex> for lazy reading; otherwise read eagerly.
            let (body, streaming_inner_opt) = if streaming {
                let inner = StreamingInner(Arc::new(Mutex::new(Some(response))));
                (Vec::new(), Some(inner))
            } else {
                (response.bytes().unwrap_or_default().to_vec(), None)
            };

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

            let streaming_hdrs = if streaming_inner_opt.is_some() {
                Some(resp_headers.clone())
            } else {
                None
            };

            return Ok(RawResponseData {
                status,
                url: final_url,
                headers: resp_headers,
                body,
                elapsed_ms,
                history,
                cookies: resp_cookies,
                reason,
                is_redirect: is_redir,
                method: current_method,
                request_url,
                request_headers: final_request_headers,
                streaming_inner: streaming_inner_opt,
                streaming_headers: streaming_hdrs,
            });
        }
    }
}

#[pymethods]
impl Session {
    #[new]
    fn new(py: Python<'_>) -> PyResult<Self> {
        let utils = py.import("snekwest.utils")?;
        let py_headers = utils.getattr("default_headers")?.call0()?.unbind();
        let cookies_mod = py.import("snekwest.cookies")?;
        let py_cookies = cookies_mod
            .getattr("cookiejar_from_dict")?
            .call1((PyDict::new(py),))?
            .unbind();
        let hooks_mod = py.import("snekwest.hooks")?;
        let py_hooks = hooks_mod.getattr("default_hooks")?.call0()?.unbind();
        let adapters_cls = py.import("collections")?.getattr("OrderedDict")?;
        let py_adapters = adapters_cls.call0()?.unbind();

        Ok(Session {
            clients: Mutex::new(HashMap::new()),
            cookie_jar: Mutex::new(HashMap::new()),
            headers: py_headers,
            cookies: py_cookies,
            auth: py.None().into(),
            proxies: PyDict::new(py).into_any().unbind(),
            hooks: py_hooks,
            params: PyDict::new(py).into_any().unbind(),
            stream: false,
            verify: PyBool::new(py, true).to_owned().into_any().unbind(),
            cert: py.None().into(),
            max_redirects: MAX_REDIRECTS,
            trust_env: true,
            adapters: py_adapters,
        })
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
        py: Python<'_>,
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
    ) -> PyResult<Response> {
        // Validate URL first
        validate_url(py, &url)?;

        let req_params = RequestParams::from_args(
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

        let raw = self.do_request(req_params)?;
        Response::from_raw(py, raw)
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        // Close all adapters
        let adapters = self.adapters.bind(py);
        let builtins = py.import("builtins").ok();
        if let Ok(values) = adapters.call_method0("values") {
            let values_as_list = builtins.and_then(|b| b.getattr("list").ok())
                .and_then(|list_fn| list_fn.call1((&values,)).ok());
            if let Ok(values_list) = values_as_list.unwrap_or(values).extract::<Vec<Py<PyAny>>>() {
                for adapter in values_list {
                    let _ = adapter.call_method0(py, "close");
                }
            }
        }
        // Clear internal state
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        clients.clear();
        let mut cookies = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
        cookies.clear();
        Ok(())
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    fn __exit__(&self, py: Python<'_>, _exc_type: &Bound<'_, PyAny>, _exc_val: &Bound<'_, PyAny>, _exc_tb: &Bound<'_, PyAny>) -> PyResult<()> {
        self.close(py)
    }

    fn mount(&self, py: Python<'_>, prefix: String, adapter: Py<PyAny>) -> PyResult<()> {
        let adapters = self.adapters.bind(py);
        adapters.set_item(&prefix, &adapter)?;
        // Move shorter-prefix keys to end (maintains longest-prefix-first order)
        let prefix_len = prefix.len();
        let builtins = py.import("builtins")?;
        let keys_list: Vec<String> = builtins.getattr("list")?
            .call1((adapters.call_method0("keys")?,))?
            .extract::<Vec<String>>()?;
        for key in &keys_list {
            if key.len() < prefix_len {
                let val = adapters.get_item(key)?;
                adapters.call_method1("__delitem__", (key.as_str(),))?;
                adapters.set_item(key, val)?;
            }
        }
        Ok(())
    }

    fn get_adapter(&self, py: Python<'_>, url: String) -> PyResult<Py<PyAny>> {
        let adapters = self.adapters.bind(py);
        let url_lower = url.to_lowercase();
        let builtins = py.import("builtins")?;
        let items_list: Vec<(String, Py<PyAny>)> = builtins.getattr("list")?
            .call1((adapters.call_method0("items")?,))?
            .extract::<Vec<(String, Py<PyAny>)>>()?;
        for (prefix, adapter) in items_list {
            if url_lower.starts_with(&prefix.to_lowercase()) {
                return Ok(adapter);
            }
        }
        let exc_mod = py.import("snekwest.exceptions")?;
        let invalid_schema = exc_mod.getattr("InvalidSchema")?;
        Err(PyErr::from_value(
            invalid_schema.call1((format!("No connection adapters were found for {url:?}"),))?
        ))
    }

    fn get_cookies_internal(&self) -> HashMap<String, String> {
        let jar = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
        jar.clone()
    }

    fn set_cookies_internal(&self, cookies: HashMap<String, String>) {
        let mut jar = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
        jar.extend(cookies);
    }

    fn set_cookie_internal(&self, key: String, value: String) {
        let mut jar = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
        jar.insert(key, value);
    }

    fn remove_cookie_internal(&self, key: &str) {
        let mut jar = self.cookie_jar.lock().unwrap_or_else(|e| e.into_inner());
        jar.remove(key);
    }

    fn prepare_request(&self, py: Python<'_>, request: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let sessions_mod = py.import("snekwest.sessions")?;
        let merge_setting = sessions_mod.getattr("merge_setting")?;
        let merge_hooks_fn = sessions_mod.getattr("merge_hooks")?;
        let cookies_mod = py.import("snekwest.cookies")?;
        let merge_cookies_fn = cookies_mod.getattr("merge_cookies")?;
        let rcj_cls = cookies_mod.getattr("RequestsCookieJar")?;
        let cookiejar_from_dict = cookies_mod.getattr("cookiejar_from_dict")?;
        let cid_cls = py.import("snekwest.structures")?.getattr("CaseInsensitiveDict")?;

        // Merge cookies: session cookies + request cookies
        let req_cookies = request.getattr("cookies")?;
        let req_cookies = if req_cookies.is_none() || (req_cookies.is_instance_of::<PyDict>() && req_cookies.len()? == 0) {
            cookiejar_from_dict.call1((PyDict::new(py),))?
        } else {
            let cookielib = py.import("http.cookiejar")?;
            let cj_cls = cookielib.getattr("CookieJar")?;
            if req_cookies.is_instance(&cj_cls)? {
                req_cookies
            } else {
                cookiejar_from_dict.call1((&req_cookies,))?
            }
        };
        let merged_cookies = merge_cookies_fn.call1((
            merge_cookies_fn.call1((rcj_cls.call0()?, &self.cookies.bind(py)))?,
            &req_cookies,
        ))?;

        // Auth: trust_env netrc lookup (use is_truthy to match Python's `not auth`)
        let mut auth = request.getattr("auth")?;
        if self.trust_env && !auth.is_truthy()? && !self.auth.bind(py).is_truthy()? {
            // Use sessions module's get_netrc_auth so monkey-patching works
            let sessions_mod = py.import("snekwest.sessions")?;
            let netrc_auth = sessions_mod.getattr("get_netrc_auth")?.call1((request.getattr("url")?,))?;
            if !netrc_auth.is_none() {
                auth = netrc_auth;
            }
        }

        // Create and prepare PreparedRequest
        let prep_cls = py.import("snekwest.models")?.getattr("PreparedRequest")?;
        let p = prep_cls.call0()?;
        let kwargs_dict = PyDict::new(py);
        kwargs_dict.set_item("dict_class", &cid_cls)?;
        let merged_headers = merge_setting.call((
            request.getattr("headers")?,
            &self.headers.bind(py),
        ), Some(&kwargs_dict))?;
        let merged_params = merge_setting.call1((
            request.getattr("params")?,
            &self.params.bind(py),
        ))?;
        let merged_auth = merge_setting.call1((&auth, &self.auth.bind(py)))?;
        let merged_hooks = merge_hooks_fn.call1((
            request.getattr("hooks")?,
            &self.hooks.bind(py),
        ))?;

        let prepare_kwargs = PyDict::new(py);
        prepare_kwargs.set_item("method", request.getattr("method")?.call_method0("upper")?)?;
        prepare_kwargs.set_item("url", request.getattr("url")?)?;
        prepare_kwargs.set_item("files", request.getattr("files")?)?;
        prepare_kwargs.set_item("data", request.getattr("data")?)?;
        prepare_kwargs.set_item("json", request.getattr("json")?)?;
        prepare_kwargs.set_item("headers", &merged_headers)?;
        prepare_kwargs.set_item("params", &merged_params)?;
        prepare_kwargs.set_item("auth", &merged_auth)?;
        prepare_kwargs.set_item("cookies", &merged_cookies)?;
        prepare_kwargs.set_item("hooks", &merged_hooks)?;
        p.call_method("prepare", (), Some(&prepare_kwargs))?;

        Ok(p.unbind())
    }

    fn merge_environment_settings(
        &self,
        py: Python<'_>,
        url: Bound<'_, PyAny>,
        proxies: Bound<'_, PyAny>,
        stream: Bound<'_, PyAny>,
        verify: Bound<'_, PyAny>,
        cert: Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let sessions_mod = py.import("snekwest.sessions")?;
        let merge_setting = sessions_mod.getattr("merge_setting")?;
        let os = py.import("os")?;

        let proxies = proxies.unbind();
        let mut verify = verify.unbind();

        if self.trust_env {
            let utils = py.import("snekwest.utils")?;
            let no_proxy = proxies.bind(py).call_method1("get", ("no_proxy",))?;
            let no_proxy_kw = PyDict::new(py);
            no_proxy_kw.set_item("no_proxy", &no_proxy)?;
            let env_proxies = utils.getattr("get_environ_proxies")?.call((&url,), Some(&no_proxy_kw))?;
            // setdefault for each env proxy
            let env_items = env_proxies.call_method0("items")?;
            let builtins = py.import("builtins")?;
            let env_items_list: Vec<(String, Py<PyAny>)> = builtins.getattr("list")?
                .call1((&env_items,))?.extract()?;
            for (k, v) in env_items_list {
                proxies.bind(py).call_method1("setdefault", (k, v))?;
            }
            // Check REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE
            let verify_bound = verify.bind(py);
            let py_true = PyBool::new(py, true);
            if verify_bound.is(py_true) || verify_bound.is_none() {
                // Replicate: verify = os.environ.get("REQUESTS_CA_BUNDLE")
                //                  or os.environ.get("CURL_CA_BUNDLE")
                //                  or verify
                let environ = os.getattr("environ")?;
                let ca_bundle = environ.call_method1("get", ("REQUESTS_CA_BUNDLE",))?;
                if ca_bundle.is_truthy()? {
                    verify = ca_bundle.unbind();
                } else {
                    let curl_bundle = environ.call_method1("get", ("CURL_CA_BUNDLE",))?;
                    if curl_bundle.is_truthy()? {
                        verify = curl_bundle.unbind();
                    }
                    // else: keep original verify
                }
            }
        }

        let merged_proxies = merge_setting.call1((&proxies, &self.proxies.bind(py)))?;
        let merged_stream = merge_setting.call1((&stream, self.stream))?;
        let merged_verify = merge_setting.call1((&verify, &self.verify.bind(py)))?;
        let merged_cert = merge_setting.call1((&cert, &self.cert.bind(py)))?;

        let result = PyDict::new(py);
        result.set_item("proxies", merged_proxies)?;
        result.set_item("stream", merged_stream)?;
        result.set_item("verify", merged_verify)?;
        result.set_item("cert", merged_cert)?;
        Ok(result.into_any().unbind())
    }

    #[pyo3(signature = (
        method,
        url,
        *,
        params = None,
        data = None,
        headers = None,
        cookies = None,
        files = None,
        auth = None,
        timeout = None,
        allow_redirects = true,
        proxies = None,
        hooks = None,
        stream = None,
        verify = None,
        cert = None,
        json = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn request(
        slf: &Bound<'_, Self>,
        method: Py<PyAny>,
        url: String,
        params: Option<Py<PyAny>>,
        data: Option<Py<PyAny>>,
        headers: Option<Py<PyAny>>,
        cookies: Option<Py<PyAny>>,
        files: Option<Py<PyAny>>,
        auth: Option<Py<PyAny>>,
        timeout: Option<Py<PyAny>>,
        allow_redirects: bool,
        proxies: Option<Py<PyAny>>,
        hooks: Option<Py<PyAny>>,
        stream: Option<Py<PyAny>>,
        verify: Option<Py<PyAny>>,
        cert: Option<Py<PyAny>>,
        json: Option<Py<PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let models_mod = py.import("snekwest.models")?;
        let request_cls = models_mod.getattr("Request")?;

        let req_build_kwargs = PyDict::new(py);
        // Convert method to string (supports both str and bytes)
        let method_str: String = if let Ok(s) = method.extract::<String>(py) {
            s
        } else if let Ok(b) = method.extract::<Vec<u8>>(py) {
            String::from_utf8_lossy(&b).to_string()
        } else {
            method.bind(py).str()?.to_string()
        };
        req_build_kwargs.set_item("method", method_str.to_uppercase())?;
        req_build_kwargs.set_item("url", &url)?;
        req_build_kwargs.set_item("headers", headers.as_ref().map_or_else(|| py.None(), |h| h.clone_ref(py)))?;
        req_build_kwargs.set_item("files", files.as_ref().map_or_else(|| py.None(), |f| f.clone_ref(py)))?;
        req_build_kwargs.set_item("data", data.as_ref().map_or_else(|| PyDict::new(py).into_any().unbind(), |d| d.clone_ref(py)))?;
        req_build_kwargs.set_item("json", json.as_ref().map_or_else(|| py.None(), |j| j.clone_ref(py)))?;
        req_build_kwargs.set_item("params", params.as_ref().map_or_else(|| PyDict::new(py).into_any().unbind(), |p| p.clone_ref(py)))?;
        req_build_kwargs.set_item("auth", auth.as_ref().map_or_else(|| py.None(), |a| a.clone_ref(py)))?;
        req_build_kwargs.set_item("cookies", cookies.as_ref().map_or_else(|| py.None(), |c| c.clone_ref(py)))?;
        req_build_kwargs.set_item("hooks", hooks.as_ref().map_or_else(|| py.None(), |h| h.clone_ref(py)))?;

        let req = request_cls.call((), Some(&req_build_kwargs))?;
        let prep = slf.borrow().prepare_request(py, &req)?;
        let prep_bound = prep.bind(py);

        let py_proxies = proxies.unwrap_or_else(|| PyDict::new(py).into_any().unbind());
        let settings = slf.borrow().merge_environment_settings(
            py,
            prep_bound.getattr("url")?,
            py_proxies.into_bound(py),
            stream.map_or_else(|| py.None().into_bound(py), |s| s.into_bound(py)),
            verify.map_or_else(|| py.None().into_bound(py), |v| v.into_bound(py)),
            cert.map_or_else(|| py.None().into_bound(py), |c| c.into_bound(py)),
        )?;

        let send_kwargs = PyDict::new(py);
        send_kwargs.set_item("timeout", timeout.as_ref().map_or_else(|| py.None(), |t| t.clone_ref(py)))?;
        send_kwargs.set_item("allow_redirects", allow_redirects)?;
        let settings_bound = settings.bind(py);
        if let Ok(settings_dict) = settings_bound.cast::<PyDict>() {
            for (k, v) in settings_dict.iter() {
                send_kwargs.set_item(k, v)?;
            }
        }

        // Call send via Python dispatch so it goes through the correct MRO
        slf.call_method("send", (&prep,), Some(&send_kwargs))
            .map(|r| r.unbind())
    }

    #[pyo3(signature = (url, **kwargs))]
    fn get(slf: &Bound<'_, Self>, url: String, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        if !kw.contains("allow_redirects")? {
            kw.set_item("allow_redirects", true)?;
        }
        slf.call_method("request", ("GET", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, **kwargs))]
    fn options(slf: &Bound<'_, Self>, url: String, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        if !kw.contains("allow_redirects")? {
            kw.set_item("allow_redirects", true)?;
        }
        slf.call_method("request", ("OPTIONS", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, **kwargs))]
    fn head(slf: &Bound<'_, Self>, url: String, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        if !kw.contains("allow_redirects")? {
            kw.set_item("allow_redirects", false)?;
        }
        slf.call_method("request", ("HEAD", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, data = None, json = None, **kwargs))]
    fn post(slf: &Bound<'_, Self>, url: String, data: Option<Py<PyAny>>, json: Option<Py<PyAny>>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        kw.set_item("data", data.as_ref().map_or_else(|| py.None(), |d| d.clone_ref(py)))?;
        kw.set_item("json", json.as_ref().map_or_else(|| py.None(), |j| j.clone_ref(py)))?;
        slf.call_method("request", ("POST", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, data = None, **kwargs))]
    fn put(slf: &Bound<'_, Self>, url: String, data: Option<Py<PyAny>>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        kw.set_item("data", data.as_ref().map_or_else(|| py.None(), |d| d.clone_ref(py)))?;
        slf.call_method("request", ("PUT", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, data = None, **kwargs))]
    fn patch(slf: &Bound<'_, Self>, url: String, data: Option<Py<PyAny>>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        kw.set_item("data", data.as_ref().map_or_else(|| py.None(), |d| d.clone_ref(py)))?;
        slf.call_method("request", ("PATCH", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (url, **kwargs))]
    fn delete(slf: &Bound<'_, Self>, url: String, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let kw = kwargs.map(|d| d.copy()).transpose()?.unwrap_or_else(|| PyDict::new(py).clone());
        slf.call_method("request", ("DELETE", url), Some(&kw)).map(|r| r.unbind())
    }

    #[pyo3(signature = (request, **kwargs))]
    fn send(slf: &Bound<'_, Self>, request: Py<PyAny>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Py<PyAny>> {
        let py = slf.py();

        // Validate request type
        let models_mod = py.import("snekwest.models")?;
        let request_cls = models_mod.getattr("Request")?;
        if request.bind(py).is_instance(&request_cls)? {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "You can only send PreparedRequests.",
            ));
        }

        // Create kwargs dict if not provided
        let kwargs = match kwargs {
            Some(kw) => kw.copy()?,
            None => PyDict::new(py).clone(),
        };

        // Fill in defaults from session
        {
            let this = slf.borrow();
            if !kwargs.contains("stream")? {
                kwargs.set_item("stream", this.stream)?;
            }
            if !kwargs.contains("verify")? {
                kwargs.set_item("verify", &this.verify)?;
            }
            if !kwargs.contains("cert")? {
                kwargs.set_item("cert", &this.cert)?;
            }
            if !kwargs.contains("proxies")? {
                let utils = py.import("snekwest.utils")?;
                let resolved = utils.getattr("resolve_proxies")?.call1((
                    &request,
                    &this.proxies.bind(py),
                    this.trust_env,
                ))?;
                kwargs.set_item("proxies", resolved)?;
            }
        } // drop borrow

        let allow_redirects: bool = kwargs.get_item("allow_redirects")?
            .map(|v| v.extract::<bool>())
            .transpose()?
            .unwrap_or(true);
        let _ = kwargs.del_item("allow_redirects");

        let stream: bool = kwargs.get_item("stream")?
            .map(|v| v.extract::<bool>())
            .transpose()?
            .unwrap_or(false);

        // Get hooks from request
        let hooks = request.getattr(py, "hooks")?;

        // Get adapter and send
        let req_url: String = request.getattr(py, "url")?.extract(py)?;
        let adapter = slf.borrow().get_adapter(py, req_url)?;

        let start = std::time::Instant::now();
        let r = adapter.bind(py).call_method(
            "send",
            (&request,),
            Some(&kwargs),
        )?;
        let elapsed_secs = start.elapsed().as_secs_f64();
        let datetime = py.import("datetime")?;
        let timedelta = datetime.getattr("timedelta")?;
        let td_kwargs = PyDict::new(py);
        td_kwargs.set_item("seconds", elapsed_secs)?;
        let elapsed_td = timedelta.call((), Some(&td_kwargs))?;
        r.setattr("elapsed", elapsed_td)?;

        // Dispatch response hooks
        let hooks_mod = py.import("snekwest.hooks")?;
        let dispatch_hook = hooks_mod.getattr("dispatch_hook")?;
        let r = dispatch_hook.call(("response", &hooks, &r), Some(&kwargs))?;

        // Extract cookies from history
        let cookies_mod = py.import("snekwest.cookies")?;
        let extract_cookies = cookies_mod.getattr("extract_cookies_to_jar")?;
        let session_cookies = slf.borrow().cookies.clone_ref(py);
        let history = r.getattr("history")?;
        if history.is_truthy()? {
            let hist_list: Vec<Py<PyAny>> = history.extract()?;
            for resp in &hist_list {
                let resp_bound = resp.bind(py);
                extract_cookies.call1((
                    &session_cookies,
                    resp_bound.getattr("request")?,
                    resp_bound.getattr("raw")?,
                ))?;
            }
        }
        extract_cookies.call1((
            &session_cookies,
            &request,
            r.getattr("raw")?,
        ))?;

        // Handle redirects - call resolve_redirects via Python self (which inherits the mixin)
        if allow_redirects {
            let gen = slf.call_method("resolve_redirects", (&r, &request), Some(&kwargs))?;
            let builtins = py.import("builtins")?;
            let history_list = builtins.getattr("list")?.call1((&gen,))?;
            let history: Vec<Py<PyAny>> = history_list.extract()?;
            if !history.is_empty() {
                let mut full_history = vec![r.unbind()];
                full_history.extend(history);
                let final_resp = full_history.pop().unwrap();
                let hist_list = pyo3::types::PyList::new(py, &full_history)?;
                final_resp.setattr(py, "history", hist_list)?;

                if !stream {
                    let _ = final_resp.getattr(py, "content")?;
                }
                return Ok(final_resp);
            }
        } else {
            // Set _next for non-redirect responses
            let yield_kwargs = kwargs.copy()?;
            yield_kwargs.set_item("yield_requests", true)?;
            let gen = slf.call_method("resolve_redirects", (&r, &request), Some(&yield_kwargs))?;
            let builtins = py.import("builtins")?;
            let next_fn = builtins.getattr("next")?;
            let result = next_fn.call1((&gen, py.None()))?;
            if !result.is_none() {
                r.setattr("_next", result)?;
            }
        }

        if !stream {
            let _ = r.getattr("content")?;
        }
        Ok(r.unbind())
    }
}


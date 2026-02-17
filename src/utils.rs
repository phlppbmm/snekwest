use pyo3::prelude::*;
use pyo3::types::PyString;
use std::collections::HashMap;
use std::net::Ipv4Addr;

// ============================================================================
// LookupDict — Dictionary lookup object for status codes
// ============================================================================

/// Dictionary lookup object. Used for status codes.
/// Mirrors requests' `LookupDict` but backed by a Rust HashMap.
#[pyclass]
pub struct LookupDict {
    pub(crate) name: Option<String>,
    pub(crate) data: HashMap<String, Py<PyAny>>,
}

#[pymethods]
impl LookupDict {
    #[new]
    #[pyo3(signature = (name=None))]
    fn new(name: Option<String>) -> Self {
        LookupDict {
            name,
            data: HashMap::new(),
        }
    }

    fn __repr__(&self) -> String {
        format!("<lookup '{}'>", self.name.as_deref().unwrap_or(""))
    }

    fn __getattr__(&self, py: Python<'_>, key: &str) -> Py<PyAny> {
        if key == "name" {
            return self
                .name
                .clone()
                .into_pyobject(py)
                .expect("name into_pyobject failed")
                .into_any()
                .unbind();
        }
        self.data
            .get(key)
            .map(|v| v.clone_ref(py))
            .unwrap_or_else(|| py.None())
    }

    fn __setattr__(&mut self, key: String, value: Bound<'_, PyAny>) {
        if key == "name" {
            self.name = value.extract::<Option<String>>().ok().flatten();
        } else {
            self.data.insert(key, value.unbind());
        }
    }

    fn __getitem__(&self, py: Python<'_>, key: &str) -> Py<PyAny> {
        self.data
            .get(key)
            .map(|v| v.clone_ref(py))
            .unwrap_or_else(|| py.None())
    }

    #[pyo3(signature = (key, default=None))]
    fn get(&self, py: Python<'_>, key: &str, default: Option<Py<PyAny>>) -> Py<PyAny> {
        self.data
            .get(key)
            .map(|v| v.clone_ref(py))
            .unwrap_or_else(|| default.unwrap_or_else(|| py.None()))
    }
}

/// Raw status code data: (code, &[title_aliases]).
/// Extracted so pure Rust tests can validate the mapping without the GIL.
const STATUS_DATA: &[(i32, &[&str])] = &[
    (100, &["continue"]),
    (101, &["switching_protocols"]),
    (102, &["processing", "early-hints"]),
    (103, &["checkpoint"]),
    (122, &["uri_too_long", "request_uri_too_long"]),
    (
        200,
        &[
            "ok", "okay", "all_ok", "all_okay", "all_good", "\\o/", "\u{2713}",
        ],
    ),
    (201, &["created"]),
    (202, &["accepted"]),
    (
        203,
        &["non_authoritative_info", "non_authoritative_information"],
    ),
    (204, &["no_content"]),
    (205, &["reset_content", "reset"]),
    (206, &["partial_content", "partial"]),
    (
        207,
        &[
            "multi_status",
            "multiple_status",
            "multi_stati",
            "multiple_stati",
        ],
    ),
    (208, &["already_reported"]),
    (226, &["im_used"]),
    (300, &["multiple_choices"]),
    (301, &["moved_permanently", "moved", "\\o-"]),
    (302, &["found"]),
    (303, &["see_other", "other"]),
    (304, &["not_modified"]),
    (305, &["use_proxy"]),
    (306, &["switch_proxy"]),
    (307, &["temporary_redirect", "temporary_moved", "temporary"]),
    (308, &["permanent_redirect", "resume_incomplete", "resume"]),
    (400, &["bad_request", "bad"]),
    (401, &["unauthorized"]),
    (402, &["payment_required", "payment"]),
    (403, &["forbidden"]),
    (404, &["not_found", "-o-"]),
    (405, &["method_not_allowed", "not_allowed"]),
    (406, &["not_acceptable"]),
    (
        407,
        &[
            "proxy_authentication_required",
            "proxy_auth",
            "proxy_authentication",
        ],
    ),
    (408, &["request_timeout", "timeout"]),
    (409, &["conflict"]),
    (410, &["gone"]),
    (411, &["length_required"]),
    (412, &["precondition_failed", "precondition"]),
    (413, &["request_entity_too_large", "content_too_large"]),
    (414, &["request_uri_too_large", "uri_too_long"]),
    (
        415,
        &["unsupported_media_type", "unsupported_media", "media_type"],
    ),
    (
        416,
        &[
            "requested_range_not_satisfiable",
            "requested_range",
            "range_not_satisfiable",
        ],
    ),
    (417, &["expectation_failed"]),
    (418, &["im_a_teapot", "teapot", "i_am_a_teapot"]),
    (421, &["misdirected_request"]),
    (
        422,
        &[
            "unprocessable_entity",
            "unprocessable",
            "unprocessable_content",
        ],
    ),
    (423, &["locked"]),
    (424, &["failed_dependency", "dependency"]),
    (425, &["unordered_collection", "unordered", "too_early"]),
    (426, &["upgrade_required", "upgrade"]),
    (428, &["precondition_required", "precondition"]),
    (429, &["too_many_requests", "too_many"]),
    (431, &["header_fields_too_large", "fields_too_large"]),
    (444, &["no_response", "none"]),
    (449, &["retry_with", "retry"]),
    (
        450,
        &["blocked_by_windows_parental_controls", "parental_controls"],
    ),
    (451, &["unavailable_for_legal_reasons", "legal_reasons"]),
    (499, &["client_closed_request"]),
    (
        500,
        &["internal_server_error", "server_error", "/o\\", "\u{2717}"],
    ),
    (501, &["not_implemented"]),
    (502, &["bad_gateway"]),
    (503, &["service_unavailable", "unavailable"]),
    (504, &["gateway_timeout"]),
    (505, &["http_version_not_supported", "http_version"]),
    (506, &["variant_also_negotiates"]),
    (507, &["insufficient_storage"]),
    (509, &["bandwidth_limit_exceeded", "bandwidth"]),
    (510, &["not_extended"]),
    (
        511,
        &[
            "network_authentication_required",
            "network_auth",
            "network_authentication",
        ],
    ),
];

/// Build a flat `HashMap<String, i32>` from `STATUS_DATA`, including uppercase
/// variants for titles that don't start with `\` or `/`.
/// This is the pure-Rust core that can be tested without the GIL.
fn build_status_map() -> HashMap<String, i32> {
    let mut map = HashMap::new();
    for &(code, titles) in STATUS_DATA {
        for title in titles {
            map.insert(title.to_string(), code);
            if !title.starts_with('\\') && !title.starts_with('/') {
                map.insert(title.to_uppercase(), code);
            }
        }
    }
    map
}

/// Construct a pre-populated `LookupDict` with all HTTP status code mappings.
#[pyfunction]
pub fn _init_status_codes() -> LookupDict {
    let mut codes = LookupDict::new(Some("status_codes".to_string()));
    let status_map = build_status_map();

    Python::attach(|py| {
        for (key, code) in &status_map {
            let code_obj: Py<PyAny> = code
                .into_pyobject(py)
                .expect("i32 into_pyobject failed")
                .into_any()
                .unbind();
            codes.data.insert(key.clone(), code_obj);
        }
    });

    codes
}

// ============================================================================
// 2a: IP/CIDR functions
// ============================================================================

#[pyfunction]
pub fn is_ipv4_address(string_ip: &str) -> bool {
    string_ip.parse::<Ipv4Addr>().is_ok()
}

#[pyfunction]
pub fn is_valid_cidr(string_network: &str) -> bool {
    if let Some((ip_str, mask_str)) = string_network.split_once('/') {
        let mask: u32 = match mask_str.parse() {
            Ok(m) => m,
            Err(_) => return false,
        };
        if !(1..=32).contains(&mask) {
            return false;
        }
        ip_str.parse::<Ipv4Addr>().is_ok()
    } else {
        false
    }
}

#[pyfunction]
pub fn dotted_netmask(mask: u32) -> String {
    let bits: u32 = if mask == 0 {
        0
    } else {
        !((1u32 << (32 - mask)) - 1)
    };
    Ipv4Addr::from(bits).to_string()
}

#[pyfunction]
pub fn address_in_network(ip: &str, net: &str) -> bool {
    let ip_addr: Ipv4Addr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let (net_ip_str, mask_str) = match net.split_once('/') {
        Some(p) => p,
        None => return false,
    };
    let net_addr: Ipv4Addr = match net_ip_str.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let mask_bits: u32 = match mask_str.parse() {
        Ok(m) => m,
        Err(_) => return false,
    };
    if mask_bits > 32 {
        return false;
    }
    let netmask: u32 = if mask_bits == 0 {
        0
    } else {
        !((1u32 << (32 - mask_bits)) - 1)
    };
    let ip_u32 = u32::from(ip_addr);
    let net_u32 = u32::from(net_addr);
    (ip_u32 & netmask) == (net_u32 & netmask)
}

// ============================================================================
// 2b: URL functions
// ============================================================================

#[pyfunction]
pub fn get_auth_from_url(url_str: &str) -> (String, String) {
    match url::Url::parse(url_str) {
        Ok(parsed) => {
            let username = percent_decode(parsed.username());
            let password = parsed.password().map(percent_decode).unwrap_or_default();
            (username, password)
        }
        Err(_) => (String::new(), String::new()),
    }
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// The unreserved URI characters (RFC 3986)
const UNRESERVED_SET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

#[pyfunction]
pub fn unquote_unreserved(py: Python<'_>, uri: &str) -> PyResult<String> {
    let parts: Vec<&str> = uri.split('%').collect();
    let mut result = String::with_capacity(uri.len());
    result.push_str(parts[0]);

    for part in &parts[1..] {
        if part.len() >= 2 {
            let h = &part[0..2];
            if h.chars().all(|c| c.is_ascii_alphanumeric()) {
                match u8::from_str_radix(h, 16) {
                    Ok(byte) => {
                        let c = byte as char;
                        if UNRESERVED_SET.contains(c) {
                            result.push(c);
                            result.push_str(&part[2..]);
                        } else {
                            result.push('%');
                            result.push_str(part);
                        }
                    }
                    Err(_) => {
                        // Import and raise InvalidURL from Python
                        let exc_module = py.import("snekwest.exceptions")?;
                        let invalid_url = exc_module.getattr("InvalidURL")?;
                        return Err(PyErr::from_value(
                            invalid_url
                                .call1((format!("Invalid percent-escape sequence: '{h}'"),))?,
                        ));
                    }
                }
            } else {
                result.push('%');
                result.push_str(part);
            }
        } else {
            result.push('%');
            result.push_str(part);
        }
    }
    Ok(result)
}

#[pyfunction]
pub fn requote_uri(py: Python<'_>, uri: &str) -> PyResult<String> {
    let safe_with_percent = "!#$%&'()*+,/:;=?@[]~";
    let safe_without_percent = "!#$&'()*+,/:;=?@[]~";

    match unquote_unreserved(py, uri) {
        Ok(unquoted) => Ok(quote_str(&unquoted, safe_with_percent)),
        Err(_) => Ok(quote_str(uri, safe_without_percent)),
    }
}

/// Percent-encode a string, leaving characters in `safe` unencoded.
fn quote_str(s: &str, safe: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        let c = byte as char;
        if c.is_ascii_alphanumeric() || safe.contains(c) || UNRESERVED_SET.contains(c) {
            result.push(c);
        } else {
            result.push_str(&format!("%{:02X}", byte));
        }
    }
    result
}

#[pyfunction]
pub fn urldefragauth(url_str: &str) -> String {
    // Parse the URL and remove fragment and auth
    match url::Url::parse(url_str) {
        Ok(mut parsed) => {
            parsed.set_fragment(None);
            parsed.set_username("").ok();
            parsed.set_password(None).ok();
            parsed.to_string()
        }
        Err(_) => url_str.to_string(),
    }
}

#[pyfunction]
pub fn prepend_scheme_if_needed(url_str: &str, new_scheme: &str) -> String {
    // If URL already has a scheme, return as-is
    if url::Url::parse(url_str).is_ok() {
        return url_str.to_string();
    }
    // Try prepending the scheme
    let with_scheme = format!("{}://{}", new_scheme, url_str);
    with_scheme
}

#[pyfunction]
pub fn unicode_is_ascii(s: &str) -> bool {
    s.is_ascii()
}

// ============================================================================
// 2c: Header functions
// ============================================================================

#[pyfunction]
pub fn parse_header_links(value: &str) -> Vec<HashMap<String, String>> {
    let replace_chars: &[char] = &[' ', '\'', '"'];
    let value = value.trim_matches(replace_chars);
    if value.is_empty() {
        return Vec::new();
    }

    let mut links = Vec::new();
    // Split on ", *<" pattern (comma, optional spaces, <) — matching Python's re.split(r", *<", value)
    for val in split_comma_angle(value)
        .iter()
        .map(|s| s.trim_start_matches('<'))
    {
        let (url_part, params_part) = match val.split_once(';') {
            Some((u, p)) => (u, p),
            None => (val, ""),
        };

        let mut link = HashMap::new();
        link.insert(
            "url".to_string(),
            url_part
                .trim_matches(&['<', '>', ' ', '\'', '"'][..])
                .to_string(),
        );

        for param in params_part.split(';') {
            let param = param.trim();
            if param.is_empty() {
                continue;
            }
            if let Some((key, value)) = param.split_once('=') {
                link.insert(
                    key.trim_matches(replace_chars).to_string(),
                    value.trim_matches(replace_chars).to_string(),
                );
            }
        }

        links.push(link);
    }
    links
}

/// Split a string on the pattern `, *<` (comma, optional spaces, then `<`).
fn split_comma_angle(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b',' {
            // skip optional spaces after comma
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b' ' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'<' {
                parts.push(&s[start..i]);
                start = j; // start after the spaces, at '<'
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    parts.push(&s[start..]);
    parts
}

#[pyfunction]
pub fn get_encoding_from_headers(
    headers: &crate::case_insensitive_dict::CaseInsensitiveDict,
) -> Option<String> {
    Python::attach(|py| {
        let content_type: Option<String> = headers.get_value(py, "content-type").and_then(|val| {
            if val.is_none(py) {
                None
            } else {
                val.extract::<String>(py).ok()
            }
        });

        let content_type = content_type?;
        let (ct, params) = parse_content_type_header_inner(&content_type);

        if let Some(charset) = params.get("charset") {
            return Some(charset.trim_matches(&['\'', '"'][..]).to_string());
        }

        if ct.contains("text") {
            return Some("ISO-8859-1".to_string());
        }

        if ct.contains("application/json") {
            return Some("utf-8".to_string());
        }

        None
    })
}

fn parse_content_type_header_inner(header: &str) -> (String, HashMap<String, String>) {
    let tokens: Vec<&str> = header.splitn(2, ';').collect();
    let content_type = tokens[0].trim().to_string();
    let mut params = HashMap::new();
    let items_to_strip: &[char] = &['"', '\'', ' '];

    if tokens.len() > 1 {
        for param in tokens[1].split(';') {
            let param = param.trim();
            if param.is_empty() {
                continue;
            }
            if let Some(eq_pos) = param.find('=') {
                let key = param[..eq_pos].trim_matches(items_to_strip).to_lowercase();
                let value = param[eq_pos + 1..].trim_matches(items_to_strip).to_string();
                params.insert(key, value);
            } else {
                // Sentinel value that _parse_content_type_header converts to Python True
                params.insert(
                    param.trim_matches(items_to_strip).to_lowercase(),
                    "\x00__true__".to_string(),
                );
            }
        }
    }

    (content_type, params)
}

#[pyfunction]
pub fn _parse_content_type_header(
    py: Python<'_>,
    header: &str,
) -> PyResult<(String, Py<pyo3::types::PyDict>)> {
    let (content_type, params_map) = parse_content_type_header_inner(header);
    let dict = pyo3::types::PyDict::new(py);
    for (key, value) in &params_map {
        if value == "\x00__true__" {
            dict.set_item(key, true)?;
        } else {
            dict.set_item(key, value)?;
        }
    }
    Ok((content_type, dict.unbind()))
}

// ============================================================================
// 2d: Encoding functions
// ============================================================================

#[pyfunction]
pub fn guess_json_utf(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return Some("utf-8".to_string());
    }

    let sample: Vec<u8> = data.iter().take(4).cloned().collect();
    let sample_len = sample.len();

    // BOM detection
    if sample_len >= 4 {
        // UTF-32 LE BOM: FF FE 00 00
        if sample[0] == 0xFF && sample[1] == 0xFE && sample[2] == 0x00 && sample[3] == 0x00 {
            return Some("utf-32".to_string());
        }
        // UTF-32 BE BOM: 00 00 FE FF
        if sample[0] == 0x00 && sample[1] == 0x00 && sample[2] == 0xFE && sample[3] == 0xFF {
            return Some("utf-32".to_string());
        }
    }
    if sample_len >= 3 && sample[0] == 0xEF && sample[1] == 0xBB && sample[2] == 0xBF {
        return Some("utf-8-sig".to_string());
    }
    if sample_len >= 2 {
        // UTF-16 LE BOM: FF FE
        if sample[0] == 0xFF && sample[1] == 0xFE {
            return Some("utf-16".to_string());
        }
        // UTF-16 BE BOM: FE FF
        if sample[0] == 0xFE && sample[1] == 0xFF {
            return Some("utf-16".to_string());
        }
    }

    // Count nulls in the actual sample bytes (not padded)
    let nullcount = sample.iter().filter(|&&b| b == 0).count();

    if nullcount == 0 {
        return Some("utf-8".to_string());
    }
    if nullcount == 2 && sample_len >= 4 {
        // 1st and 3rd are null -> UTF-16 BE
        if sample[0] == 0 && sample[2] == 0 {
            return Some("utf-16-be".to_string());
        }
        // 2nd and 4th are null -> UTF-16 LE
        if sample[1] == 0 && sample[3] == 0 {
            return Some("utf-16-le".to_string());
        }
    }
    if nullcount == 3 && sample_len >= 4 {
        // First 3 are null -> UTF-32 BE
        if sample[0] == 0 && sample[1] == 0 && sample[2] == 0 {
            return Some("utf-32-be".to_string());
        }
        // Last 3 are null -> UTF-32 LE
        if sample[1] == 0 && sample[2] == 0 && sample[3] == 0 {
            return Some("utf-32-le".to_string());
        }
    }
    None
}

// ============================================================================
// 2e: Proxy functions
// ============================================================================

#[pyfunction]
pub fn select_proxy(url_str: &str, proxies: Option<HashMap<String, String>>) -> Option<String> {
    let proxies = proxies.unwrap_or_default();
    if proxies.is_empty() {
        return None;
    }

    let parsed = match url::Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return None,
    };

    let scheme = parsed.scheme();
    let hostname = match parsed.host_str() {
        Some(h) => h.to_string(),
        None => return proxies.get(scheme).or_else(|| proxies.get("all")).cloned(),
    };

    let proxy_keys = [
        format!("{}://{}", scheme, hostname),
        scheme.to_string(),
        format!("all://{}", hostname),
        "all".to_string(),
    ];

    for key in &proxy_keys {
        if let Some(proxy) = proxies.get(key) {
            return Some(proxy.clone());
        }
    }
    None
}

/// Core no_proxy matching logic. Checks if a hostname (possibly with port)
/// matches any entry in a comma-separated no_proxy string.
/// This is the inner loop from Python's should_bypass_proxies, extracted
/// for performance (called on every request with trust_env=True).
#[pyfunction]
pub fn should_bypass_proxies_core(
    hostname: &str,
    port: Option<u16>,
    is_ipv4: bool,
    no_proxy: &str,
) -> bool {
    for entry in no_proxy.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        if is_ipv4 {
            if is_valid_cidr(entry) {
                if address_in_network(hostname, entry) {
                    return true;
                }
            } else if hostname == entry {
                return true;
            }
        } else {
            let host_with_port = match port {
                Some(p) => format!("{}:{}", hostname, p),
                None => hostname.to_string(),
            };
            if hostname.ends_with(entry) || host_with_port.ends_with(entry) {
                return true;
            }
        }
    }
    false
}

/// Compute the final URL to use when making a request.
/// Handles proxy vs. direct and SOCKS proxy logic.
/// Mirrors requests' `HTTPAdapter.request_url`.
#[pyfunction]
pub fn request_url(url: &str, path_url: &str, proxies: Option<HashMap<String, String>>) -> String {
    let proxy = select_proxy(url, proxies);

    let scheme = url::Url::parse(url)
        .map(|u| u.scheme().to_string())
        .unwrap_or_default();

    let is_proxied_http = proxy.is_some() && scheme != "https";
    let using_socks = proxy.as_ref().is_some_and(|p| {
        url::Url::parse(p)
            .map(|u| u.scheme().starts_with("socks"))
            .unwrap_or(false)
    });

    let mut result = path_url.to_string();
    if result.starts_with("//") {
        result = format!("/{}", result.trim_start_matches('/'));
    }

    if is_proxied_http && !using_socks {
        result = urldefragauth(url);
    }

    result
}

// ============================================================================
// 2f: HTTP list/dict header parsing
// ============================================================================

/// Parse RFC 2068 comma-separated lists with quoted-string support.
/// Equivalent to urllib.request.parse_http_list.
fn parse_http_list(s: &str) -> Vec<String> {
    let mut res = Vec::new();
    let mut part = String::new();
    let mut escape = false;
    let mut quote = false;

    for cur in s.chars() {
        if escape {
            part.push(cur);
            escape = false;
            continue;
        }
        if quote {
            if cur == '\\' {
                escape = true;
                continue;
            } else if cur == '"' {
                quote = false;
            }
            part.push(cur);
            continue;
        }
        if cur == ',' {
            res.push(part.clone());
            part.clear();
            continue;
        }
        if cur == '"' {
            quote = true;
        }
        part.push(cur);
    }
    if !part.is_empty() {
        res.push(part);
    }
    res.into_iter().map(|p| p.trim().to_string()).collect()
}

/// Unquote a header value — reversal of quote_header_value.
/// This is what browsers actually use for quoting, not full RFC unquoting.
fn unquote_header_value_inner(value: &str, is_filename: bool) -> String {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let inner = &value[1..value.len() - 1];
        if !is_filename || !inner.starts_with("\\\\") {
            return inner.replace("\\\\", "\\").replace("\\\"", "\"");
        }
        return inner.to_string();
    }
    value.to_string()
}

/// Parse a list header value (RFC 2068 Section 2).
#[pyfunction]
pub fn parse_list_header(value: &str) -> Vec<String> {
    let mut result = Vec::new();
    for item in parse_http_list(value) {
        if item.len() >= 2 && item.starts_with('"') && item.ends_with('"') {
            result.push(unquote_header_value_inner(&item[1..item.len() - 1], false));
        } else {
            result.push(item);
        }
    }
    result
}

/// Parse a dict header value (RFC 2068 Section 2).
#[pyfunction]
pub fn parse_dict_header(py: Python<'_>, value: &str) -> PyResult<Py<pyo3::types::PyDict>> {
    let dict = pyo3::types::PyDict::new(py);
    for item in parse_http_list(value) {
        if let Some(eq_pos) = item.find('=') {
            let name = &item[..eq_pos];
            let val = &item[eq_pos + 1..];
            if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
                dict.set_item(
                    name,
                    unquote_header_value_inner(&val[1..val.len() - 1], false),
                )?;
            } else {
                dict.set_item(name, val)?;
            }
        } else {
            dict.set_item(&item, py.None())?;
        }
    }
    Ok(dict.unbind())
}

/// Unquote a header value.
#[pyfunction]
#[pyo3(signature = (value, is_filename=false))]
pub fn unquote_header_value(value: &str, is_filename: bool) -> String {
    unquote_header_value_inner(value, is_filename)
}

// ============================================================================
// 2g: Header validation (check_header_validity)
// ============================================================================

/// Validate a header name (str).
/// Pattern: `^[^:\s][^:\r\n]*$`
fn is_valid_header_name_str(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let bytes = name.as_bytes();
    let first = bytes[0];
    // First char must not be ':' or whitespace
    if first == b':' || first.is_ascii_whitespace() {
        return false;
    }
    // Rest must not contain ':', '\r', '\n'
    for &b in &bytes[1..] {
        if b == b':' || b == b'\r' || b == b'\n' {
            return false;
        }
    }
    true
}

/// Validate a header name (bytes).
/// Pattern: `^[^:\s][^:\r\n]*$`
fn is_valid_header_name_bytes(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    let first = name[0];
    if first == b':' || first.is_ascii_whitespace() {
        return false;
    }
    for &b in &name[1..] {
        if b == b':' || b == b'\r' || b == b'\n' {
            return false;
        }
    }
    true
}

/// Validate a header value (str).
/// Pattern: `^\S[^\r\n]*$|^$`
fn is_valid_header_value_str(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let bytes = value.as_bytes();
    // First char must not be whitespace
    if bytes[0].is_ascii_whitespace() {
        return false;
    }
    // Rest must not contain '\r' or '\n'
    for &b in &bytes[1..] {
        if b == b'\r' || b == b'\n' {
            return false;
        }
    }
    true
}

/// Validate a header value (bytes).
/// Pattern: `^\S[^\r\n]*$|^$`
fn is_valid_header_value_bytes(value: &[u8]) -> bool {
    if value.is_empty() {
        return true;
    }
    if value[0].is_ascii_whitespace() {
        return false;
    }
    for &b in &value[1..] {
        if b == b'\r' || b == b'\n' {
            return false;
        }
    }
    true
}

/// Validate a header (name, value) tuple from Rust code.
/// Returns Ok(()) or Err(PyErr) with InvalidHeader.
pub fn check_header_validity_rust(
    py: Python<'_>,
    name: &Bound<'_, PyAny>,
    value: &Bound<'_, PyAny>,
) -> PyResult<()> {
    // Validate name
    if let Ok(s) = name.extract::<String>() {
        if !is_valid_header_name_str(&s) {
            return Err(crate::exceptions::make_exception(
                py,
                "InvalidHeader",
                format!(
                    "Invalid leading whitespace, reserved character(s), or return character(s) in header name: {:?}",
                    s
                ),
            ));
        }
    } else if let Ok(b) = name.extract::<Vec<u8>>() {
        if !is_valid_header_name_bytes(&b) {
            return Err(crate::exceptions::make_exception(
                py,
                "InvalidHeader",
                format!(
                    "Invalid leading whitespace, reserved character(s), or return character(s) in header name: {:?}",
                    b
                ),
            ));
        }
    } else {
        return Err(crate::exceptions::make_exception(
            py,
            "InvalidHeader",
            format!(
                "Header part ({}) from ({}, {}) must be of type str or bytes, not {}",
                name,
                name,
                value,
                name.get_type().name()?
            ),
        ));
    }

    // Validate value
    if let Ok(s) = value.extract::<String>() {
        if !is_valid_header_value_str(&s) {
            return Err(crate::exceptions::make_exception(
                py,
                "InvalidHeader",
                format!(
                    "Invalid leading whitespace, reserved character(s), or return character(s) in header value: {:?}",
                    s
                ),
            ));
        }
    } else if let Ok(b) = value.extract::<Vec<u8>>() {
        if !is_valid_header_value_bytes(&b) {
            return Err(crate::exceptions::make_exception(
                py,
                "InvalidHeader",
                format!(
                    "Invalid leading whitespace, reserved character(s), or return character(s) in header value: {:?}",
                    b
                ),
            ));
        }
    } else {
        return Err(crate::exceptions::make_exception(
            py,
            "InvalidHeader",
            format!(
                "Header part ({}) from ({}, {}) must be of type str or bytes, not {}",
                value,
                name,
                value,
                value.get_type().name()?
            ),
        ));
    }

    Ok(())
}

/// Python-callable check_header_validity(header) where header is a (name, value) tuple.
#[pyfunction]
pub fn check_header_validity(py: Python<'_>, header: &Bound<'_, PyAny>) -> PyResult<()> {
    let name = header.get_item(0)?;
    let value = header.get_item(1)?;
    check_header_validity_rust(py, &name, &value)
}

// ============================================================================
// 2g: to_native_string
// ============================================================================

/// Given a string object (str or bytes), return a native str.
/// Equivalent to Python's to_native_string(string, encoding='ascii').
#[pyfunction]
#[pyo3(signature = (string, encoding="ascii"))]
pub fn to_native_string(
    _py: Python<'_>,
    string: &Bound<'_, PyAny>,
    encoding: &str,
) -> PyResult<String> {
    if let Ok(s) = string.extract::<String>() {
        Ok(s)
    } else {
        // Call bytes.decode(encoding) — same as Python implementation
        let decoded = string.call_method1("decode", (encoding,))?;
        decoded.extract::<String>()
    }
}

// ============================================================================
// 2h: Session merge helpers
// ============================================================================

/// Merge a request-level setting with a session-level setting.
///
/// Python reference (sessions.py:62-80):
///   - If session_setting is None → return request_setting
///   - If request_setting is None → return session_setting
///   - If either is not a Mapping → return request_setting
///   - Both are Mappings → merge session into request, prune None-valued keys
///   - Fast path when both inputs are CaseInsensitiveDict
#[pyfunction]
#[pyo3(signature = (request_setting, session_setting, dict_class=None))]
pub fn merge_setting(
    py: Python<'_>,
    request_setting: &Bound<'_, PyAny>,
    session_setting: &Bound<'_, PyAny>,
    dict_class: Option<&Bound<'_, PyAny>>,
) -> PyResult<Py<PyAny>> {
    // Case 1: session_setting is None → return request_setting
    if session_setting.is_none() {
        return Ok(request_setting.clone().unbind());
    }
    // Case 2: request_setting is None → return session_setting
    if request_setting.is_none() {
        return Ok(session_setting.clone().unbind());
    }
    // Case 3: Either is not a Mapping → return request_setting
    let mapping_abc = py.import("collections.abc")?.getattr("Mapping")?;
    if !(session_setting.is_instance(&mapping_abc)? && request_setting.is_instance(&mapping_abc)?) {
        return Ok(request_setting.clone().unbind());
    }
    // Case 4: Both are Mappings → merge
    // CaseInsensitiveDict fast path: when BOTH are CID, merge using the Rust store directly
    if let (Ok(session_cid), Ok(request_cid)) = (
        session_setting.cast::<crate::case_insensitive_dict::CaseInsensitiveDict>(),
        request_setting.cast::<crate::case_insensitive_dict::CaseInsensitiveDict>(),
    ) {
        let mut merged = crate::case_insensitive_dict::CaseInsensitiveDict::new_empty();
        // First: iterate session's items
        {
            let session_ref = session_cid.borrow();
            for (orig_key, val) in session_ref.iter_items() {
                merged.set_item(py, orig_key, val.bind(py).clone())?;
            }
        }
        // Then: overlay request's items
        {
            let request_ref = request_cid.borrow();
            for (orig_key, val) in request_ref.iter_items() {
                merged.set_item(py, orig_key, val.bind(py).clone())?;
            }
        }
        // Prune entries where value is None
        let none_keys: Vec<String> = merged
            .iter_items()
            .filter(|(_, val)| val.bind(py).is_none())
            .map(|(key, _)| key.to_lowercase())
            .collect();
        // Create the Python object, then delete None-valued keys via its __delitem__
        let merged_obj = pyo3::Py::new(py, merged)?;
        for key in &none_keys {
            merged_obj.bind(py).call_method1("__delitem__", (key,))?;
        }
        return Ok(merged_obj.into_any());
    }
    // Generic path: for other Mappings
    let dict_cls = match dict_class {
        Some(dc) => dc.clone(),
        None => py.import("collections")?.getattr("OrderedDict")?,
    };
    let to_key_val_list = py.import("snekwest.utils")?.getattr("to_key_val_list")?;
    let session_kvl = to_key_val_list.call1((session_setting,))?;
    let request_kvl = to_key_val_list.call1((request_setting,))?;
    let merged = dict_cls.call1((&session_kvl,))?;
    merged.call_method1("update", (&request_kvl,))?;
    // Prune None-valued keys
    let none_keys: Vec<Py<PyAny>> = merged
        .call_method0("items")?
        .try_iter()?
        .filter_map(|item| item.ok())
        .filter_map(|item| {
            let val = item.get_item(1).ok()?;
            if val.is_none() {
                Some(item.get_item(0).ok()?.unbind())
            } else {
                None
            }
        })
        .collect();
    for key in &none_keys {
        merged.del_item(key)?;
    }
    Ok(merged.unbind())
}

// ============================================================================
// 2i: Default headers / user-agent
// ============================================================================

/// Inline what urllib3.util.make_headers(accept_encoding=True) returns.
pub const DEFAULT_ACCEPT_ENCODING: &str = "gzip, deflate, br";

/// Return a string representing the default user agent.
#[pyfunction]
#[pyo3(signature = (name="python-requests"))]
pub fn default_user_agent(py: Python<'_>, name: &str) -> PyResult<String> {
    let version: String = py
        .import("snekwest.__version__")?
        .getattr("__version__")?
        .extract()?;
    Ok(format!("{name}/{version}"))
}

/// Return default HTTP headers as a CaseInsensitiveDict.
#[pyfunction]
pub fn default_headers(
    py: Python<'_>,
) -> PyResult<crate::case_insensitive_dict::CaseInsensitiveDict> {
    let mut dict = crate::case_insensitive_dict::CaseInsensitiveDict::new_empty();
    let ua = default_user_agent(py, "python-requests")?;
    dict.set_item(py, "User-Agent", PyString::new(py, &ua).into_any())?;
    dict.set_item(
        py,
        "Accept-Encoding",
        PyString::new(py, DEFAULT_ACCEPT_ENCODING).into_any(),
    )?;
    dict.set_item(py, "Accept", PyString::new(py, "*/*").into_any())?;
    dict.set_item(py, "Connection", PyString::new(py, "keep-alive").into_any())?;
    Ok(dict)
}

// ============================================================================
// Rust-only unit tests (Group C)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- IP/CIDR tests --

    #[test]
    fn test_is_ipv4_address_valid() {
        assert!(is_ipv4_address("192.168.1.1"));
        assert!(is_ipv4_address("10.0.0.1"));
        assert!(is_ipv4_address("0.0.0.0"));
        assert!(is_ipv4_address("255.255.255.255"));
    }

    #[test]
    fn test_is_ipv4_address_invalid() {
        assert!(!is_ipv4_address("not_an_ip"));
        assert!(!is_ipv4_address("999.999.999.999"));
        assert!(!is_ipv4_address("::1"));
        assert!(!is_ipv4_address(""));
    }

    #[test]
    fn test_is_valid_cidr() {
        assert!(is_valid_cidr("192.168.1.0/24"));
        assert!(is_valid_cidr("10.0.0.0/8"));
        assert!(is_valid_cidr("172.16.0.0/12"));
    }

    #[test]
    fn test_is_valid_cidr_invalid() {
        assert!(!is_valid_cidr("192.168.1.0"));
        assert!(!is_valid_cidr("192.168.1.0/33"));
        assert!(!is_valid_cidr("192.168.1.0/0"));
        assert!(!is_valid_cidr("not_a_cidr/24"));
        assert!(!is_valid_cidr("192.168.1.0/abc"));
    }

    #[test]
    fn test_dotted_netmask() {
        assert_eq!(dotted_netmask(24), "255.255.255.0");
        assert_eq!(dotted_netmask(8), "255.0.0.0");
        assert_eq!(dotted_netmask(16), "255.255.0.0");
        assert_eq!(dotted_netmask(32), "255.255.255.255");
    }

    #[test]
    fn test_address_in_network() {
        assert!(address_in_network("192.168.1.1", "192.168.1.0/24"));
        assert!(!address_in_network("192.168.1.1", "192.168.100.0/24"));
        assert!(address_in_network("10.0.0.1", "10.0.0.0/8"));
        assert!(!address_in_network("172.16.0.1", "10.0.0.0/8"));
    }

    // -- URL function tests --

    #[test]
    fn test_get_auth_from_url() {
        assert_eq!(
            get_auth_from_url("http://user:pass@host.com/path"),
            ("user".to_string(), "pass".to_string())
        );
        assert_eq!(
            get_auth_from_url("http://host.com/path"),
            ("".to_string(), "".to_string())
        );
        assert_eq!(
            get_auth_from_url("http://user%40name:p%40ss@host.com"),
            ("user@name".to_string(), "p@ss".to_string())
        );
    }

    #[test]
    fn test_unicode_is_ascii() {
        assert!(unicode_is_ascii("hello"));
        assert!(unicode_is_ascii(""));
        assert!(!unicode_is_ascii("héllo"));
        assert!(!unicode_is_ascii("日本語"));
    }

    #[test]
    fn test_urldefragauth() {
        assert_eq!(
            urldefragauth("http://user:pass@host.com/path#frag"),
            "http://host.com/path"
        );
        assert_eq!(
            urldefragauth("http://host.com/path?q=1#frag"),
            "http://host.com/path?q=1"
        );
    }

    #[test]
    fn test_prepend_scheme_if_needed() {
        assert_eq!(
            prepend_scheme_if_needed("http://example.com", "https"),
            "http://example.com"
        );
        assert_eq!(
            prepend_scheme_if_needed("example.com", "https"),
            "https://example.com"
        );
    }

    // -- Header function tests --

    #[test]
    fn test_parse_header_links() {
        let links = parse_header_links(
            r#"<http://example.com>; rel="next", <http://example.com/prev>; rel="prev""#,
        );
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].get("url").unwrap(), "http://example.com");
        assert_eq!(links[0].get("rel").unwrap(), "next");
        assert_eq!(links[1].get("url").unwrap(), "http://example.com/prev");
        assert_eq!(links[1].get("rel").unwrap(), "prev");
    }

    #[test]
    fn test_parse_content_type_header() {
        let (ct, params) = parse_content_type_header_inner("text/html; charset=utf-8");
        assert_eq!(ct, "text/html");
        assert_eq!(params.get("charset").unwrap(), "utf-8");
    }

    #[test]
    fn test_parse_content_type_header_no_params() {
        let (ct, params) = parse_content_type_header_inner("application/json");
        assert_eq!(ct, "application/json");
        assert!(params.is_empty());
    }

    // -- Encoding tests --

    #[test]
    fn test_guess_json_utf_basic() {
        assert_eq!(guess_json_utf(b"{}"), Some("utf-8".to_string()));
        assert_eq!(guess_json_utf(b"[1,2,3]"), Some("utf-8".to_string()));
    }

    #[test]
    fn test_guess_json_utf_bom() {
        // UTF-8 BOM
        assert_eq!(
            guess_json_utf(&[0xEF, 0xBB, 0xBF, b'{', b'}']),
            Some("utf-8-sig".to_string())
        );
        // UTF-16 LE BOM
        assert_eq!(
            guess_json_utf(&[0xFF, 0xFE, b'{', 0x00]),
            Some("utf-16".to_string())
        );
        // UTF-16 BE BOM
        assert_eq!(
            guess_json_utf(&[0xFE, 0xFF, 0x00, b'{']),
            Some("utf-16".to_string())
        );
    }

    #[test]
    fn test_guess_json_utf_nulls() {
        // UTF-16 BE: null, char, null, char
        assert_eq!(
            guess_json_utf(&[0x00, b'{', 0x00, b'}']),
            Some("utf-16-be".to_string())
        );
        // UTF-16 LE: char, null, char, null
        assert_eq!(
            guess_json_utf(&[b'{', 0x00, b'}', 0x00]),
            Some("utf-16-le".to_string())
        );
        // UTF-32 BE: null, null, null, char
        assert_eq!(
            guess_json_utf(&[0x00, 0x00, 0x00, b'{']),
            Some("utf-32-be".to_string())
        );
        // UTF-32 LE: char, null, null, null
        assert_eq!(
            guess_json_utf(&[b'{', 0x00, 0x00, 0x00]),
            Some("utf-32-le".to_string())
        );
    }

    // -- Proxy tests --

    #[test]
    fn test_select_proxy_basic() {
        let mut proxies = HashMap::new();
        proxies.insert("http".to_string(), "http://proxy:8080".to_string());
        proxies.insert("https".to_string(), "https://proxy:8443".to_string());

        assert_eq!(
            select_proxy("http://example.com", Some(proxies.clone())),
            Some("http://proxy:8080".to_string())
        );
        assert_eq!(
            select_proxy("https://example.com", Some(proxies)),
            Some("https://proxy:8443".to_string())
        );
    }

    #[test]
    fn test_select_proxy_hostname_specific() {
        let mut proxies = HashMap::new();
        proxies.insert(
            "http://example.com".to_string(),
            "http://special:8080".to_string(),
        );
        proxies.insert("http".to_string(), "http://default:8080".to_string());

        assert_eq!(
            select_proxy("http://example.com/path", Some(proxies.clone())),
            Some("http://special:8080".to_string())
        );
        assert_eq!(
            select_proxy("http://other.com/path", Some(proxies)),
            Some("http://default:8080".to_string())
        );
    }

    #[test]
    fn test_select_proxy_none() {
        assert_eq!(select_proxy("http://example.com", None), None);
        assert_eq!(
            select_proxy("http://example.com", Some(HashMap::new())),
            None
        );
    }

    // -- Header validation tests --

    #[test]
    fn test_valid_header_name_str() {
        assert!(is_valid_header_name_str("Content-Type"));
        assert!(is_valid_header_name_str("X-Custom-Header"));
        assert!(is_valid_header_name_str("Accept"));
        assert!(is_valid_header_name_str("a"));
    }

    #[test]
    fn test_invalid_header_name_str() {
        // Empty
        assert!(!is_valid_header_name_str(""));
        // Starts with colon
        assert!(!is_valid_header_name_str(":bad"));
        // Starts with space
        assert!(!is_valid_header_name_str(" bad"));
        // Starts with tab
        assert!(!is_valid_header_name_str("\tbad"));
        // Contains colon
        assert!(!is_valid_header_name_str("bad:header"));
        // Contains \r
        assert!(!is_valid_header_name_str("bad\rheader"));
        // Contains \n
        assert!(!is_valid_header_name_str("bad\nheader"));
    }

    #[test]
    fn test_valid_header_name_bytes() {
        assert!(is_valid_header_name_bytes(b"Content-Type"));
        assert!(is_valid_header_name_bytes(b"X-Custom"));
        assert!(is_valid_header_name_bytes(b"a"));
    }

    #[test]
    fn test_invalid_header_name_bytes() {
        assert!(!is_valid_header_name_bytes(b""));
        assert!(!is_valid_header_name_bytes(b":bad"));
        assert!(!is_valid_header_name_bytes(b" bad"));
        assert!(!is_valid_header_name_bytes(b"bad:header"));
        assert!(!is_valid_header_name_bytes(b"bad\rheader"));
        assert!(!is_valid_header_name_bytes(b"bad\nheader"));
    }

    #[test]
    fn test_valid_header_value_str() {
        assert!(is_valid_header_value_str("application/json"));
        assert!(is_valid_header_value_str("text/html; charset=utf-8"));
        // Empty is valid
        assert!(is_valid_header_value_str(""));
        // Value with internal spaces is fine
        assert!(is_valid_header_value_str("hello world"));
    }

    #[test]
    fn test_invalid_header_value_str() {
        // Starts with space
        assert!(!is_valid_header_value_str(" bad"));
        // Starts with tab
        assert!(!is_valid_header_value_str("\tbad"));
        // Contains \r
        assert!(!is_valid_header_value_str("bad\rvalue"));
        // Contains \n
        assert!(!is_valid_header_value_str("bad\nvalue"));
    }

    #[test]
    fn test_valid_header_value_bytes() {
        assert!(is_valid_header_value_bytes(b"application/json"));
        assert!(is_valid_header_value_bytes(b""));
        assert!(is_valid_header_value_bytes(b"hello world"));
    }

    #[test]
    fn test_invalid_header_value_bytes() {
        assert!(!is_valid_header_value_bytes(b" bad"));
        assert!(!is_valid_header_value_bytes(b"\tbad"));
        assert!(!is_valid_header_value_bytes(b"bad\rvalue"));
        assert!(!is_valid_header_value_bytes(b"bad\nvalue"));
    }

    // -- HTTP list/dict header parsing tests --

    #[test]
    fn test_parse_http_list_simple() {
        let result = parse_http_list("foo, bar, baz");
        assert_eq!(result, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn test_parse_http_list_quoted() {
        let result = parse_http_list(r#"foo, "bar, baz", qux"#);
        assert_eq!(result, vec!["foo", "\"bar, baz\"", "qux"]);
    }

    #[test]
    fn test_parse_http_list_escaped() {
        let result = parse_http_list(r#""val with \"escaped\" quotes""#);
        assert_eq!(result, vec![r#""val with "escaped" quotes""#]);
    }

    #[test]
    fn test_parse_http_list_empty() {
        let result = parse_http_list("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_unquote_header_value_quoted() {
        assert_eq!(unquote_header_value_inner(r#""hello""#, false), "hello");
    }

    #[test]
    fn test_unquote_header_value_escaped_backslash() {
        assert_eq!(
            unquote_header_value_inner(r#""hello\\world""#, false),
            "hello\\world"
        );
    }

    #[test]
    fn test_unquote_header_value_escaped_quote() {
        assert_eq!(
            unquote_header_value_inner(r#""hello\"world""#, false),
            r#"hello"world"#
        );
    }

    #[test]
    fn test_unquote_header_value_unquoted() {
        assert_eq!(unquote_header_value_inner("hello", false), "hello");
    }

    #[test]
    fn test_unquote_header_value_filename_unc() {
        // UNC path should not have backslashes unescaped
        assert_eq!(
            unquote_header_value_inner(r#""\\\\server\\share""#, true),
            r#"\\\\server\\share"#
        );
    }

    #[test]
    fn test_parse_list_header() {
        let result = parse_list_header("token, \"quoted value\"");
        assert_eq!(result, vec!["token", "quoted value"]);
    }

    #[test]
    fn test_parse_list_header_empty() {
        let result = parse_list_header("");
        assert!(result.is_empty());
    }

    // -- request_url tests --

    #[test]
    fn test_request_url_no_proxy() {
        assert_eq!(
            request_url("http://example.com/path?q=1", "/path?q=1", None),
            "/path?q=1"
        );
    }

    #[test]
    fn test_request_url_http_proxy() {
        let mut proxies = HashMap::new();
        proxies.insert(
            "http".to_string(),
            "http://proxy.example.com:8080".to_string(),
        );
        assert_eq!(
            request_url(
                "http://example.com/path?q=1#frag",
                "/path?q=1",
                Some(proxies)
            ),
            "http://example.com/path?q=1" // urldefragauth strips fragment and auth
        );
    }

    #[test]
    fn test_request_url_https_no_proxy_override() {
        // HTTPS requests don't use proxy URL even if proxy is set
        let mut proxies = HashMap::new();
        proxies.insert(
            "http".to_string(),
            "http://proxy.example.com:8080".to_string(),
        );
        assert_eq!(
            request_url("https://example.com/path", "/path", Some(proxies)),
            "/path"
        );
    }

    #[test]
    fn test_request_url_socks_proxy() {
        // SOCKS proxy: use path_url, not full URL
        let mut proxies = HashMap::new();
        proxies.insert(
            "http".to_string(),
            "socks5://proxy.example.com:1080".to_string(),
        );
        assert_eq!(
            request_url("http://example.com/path", "/path", Some(proxies)),
            "/path"
        );
    }

    #[test]
    fn test_request_url_leading_double_slash() {
        assert_eq!(
            request_url("http://example.com//path", "//path", None),
            "/path"
        );
    }

    // -- should_bypass_proxies_core tests --

    #[test]
    fn test_bypass_proxies_cidr_match() {
        assert!(should_bypass_proxies_core(
            "192.168.1.100",
            None,
            true,
            "192.168.1.0/24"
        ));
    }

    #[test]
    fn test_bypass_proxies_exact_ip_match() {
        assert!(should_bypass_proxies_core(
            "10.0.0.1",
            None,
            true,
            "10.0.0.1,172.16.0.1"
        ));
    }

    #[test]
    fn test_bypass_proxies_ip_no_match() {
        assert!(!should_bypass_proxies_core(
            "10.0.0.2", None, true, "10.0.0.1"
        ));
    }

    #[test]
    fn test_bypass_proxies_hostname_suffix() {
        assert!(should_bypass_proxies_core(
            "api.example.com",
            None,
            false,
            "example.com"
        ));
    }

    #[test]
    fn test_bypass_proxies_hostname_with_port() {
        assert!(should_bypass_proxies_core(
            "google.com",
            Some(6000),
            false,
            "google.com:6000"
        ));
    }

    #[test]
    fn test_bypass_proxies_hostname_no_match() {
        assert!(!should_bypass_proxies_core(
            "other.com",
            None,
            false,
            "example.com"
        ));
    }

    #[test]
    fn test_bypass_proxies_empty_no_proxy() {
        assert!(!should_bypass_proxies_core("example.com", None, false, ""));
    }

    #[test]
    fn test_bypass_proxies_spaces_in_entries() {
        assert!(should_bypass_proxies_core(
            "example.com",
            None,
            false,
            " example.com , other.com "
        ));
    }

    // -- LookupDict / status codes tests --

    #[test]
    fn test_build_status_map_keys() {
        let map = build_status_map();
        // Check that data was populated
        assert!(map.contains_key("ok"));
        assert!(map.contains_key("OK"));
        assert!(map.contains_key("not_found"));
        assert!(map.contains_key("NOT_FOUND"));
        assert!(map.contains_key("teapot"));
        // Special chars should not have uppercase
        assert!(map.contains_key("\\o/"));
        assert!(!map.contains_key("\\O/"));
        assert!(map.contains_key("/o\\"));
        assert!(!map.contains_key("/O\\"));
    }

    #[test]
    fn test_build_status_map_values() {
        let map = build_status_map();
        assert_eq!(map.get("ok"), Some(&200));
        assert_eq!(map.get("OK"), Some(&200));
        assert_eq!(map.get("not_found"), Some(&404));
        assert_eq!(map.get("NOT_FOUND"), Some(&404));
        assert_eq!(map.get("teapot"), Some(&418));
        assert_eq!(map.get("TEAPOT"), Some(&418));
        assert_eq!(map.get("too_early"), Some(&425));
        assert_eq!(map.get("TOO_EARLY"), Some(&425));
        assert_eq!(map.get("temporary_redirect"), Some(&307));
        assert_eq!(map.get("permanent_redirect"), Some(&308));
        assert_eq!(map.get("moved"), Some(&301));
        assert_eq!(map.get("found"), Some(&302));
        assert_eq!(map.get("see_other"), Some(&303));
        assert_eq!(map.get("bad_gateway"), Some(&502));
    }
}

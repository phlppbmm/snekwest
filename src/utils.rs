use pyo3::prelude::*;
use std::collections::HashMap;
use std::net::Ipv4Addr;

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
        if mask < 1 || mask > 32 {
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
            let password = parsed
                .password()
                .map(|p| percent_decode(p))
                .unwrap_or_default();
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
    for val in split_comma_angle(value).iter().map(|s| s.trim_start_matches('<')) {
        let (url_part, params_part) = match val.split_once(';') {
            Some((u, p)) => (u, p),
            None => (val, ""),
        };

        let mut link = HashMap::new();
        link.insert(
            "url".to_string(),
            url_part.trim_matches(&['<', '>', ' ', '\'', '"'][..]).to_string(),
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
pub fn get_encoding_from_headers(headers: &crate::case_insensitive_dict::CaseInsensitiveDict) -> Option<String> {
    Python::attach(|py| {
        let content_type: Option<String> = headers
            .get_value(py, "content-type")
            .and_then(|val| {
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
                params.insert(param.trim_matches(items_to_strip).to_lowercase(), "\x00__true__".to_string());
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
pub fn select_proxy(
    url_str: &str,
    proxies: Option<HashMap<String, String>>,
) -> Option<String> {
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
        proxies.insert("http://example.com".to_string(), "http://special:8080".to_string());
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
}

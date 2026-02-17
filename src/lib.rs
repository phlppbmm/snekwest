pub mod case_insensitive_dict;
pub mod exceptions;
pub mod prepared_request;
pub mod request_params;
pub mod response;
pub mod session;
pub mod utils;

use case_insensitive_dict::{CaseInsensitiveDict, CaseInsensitiveDictIter};
use prepared_request::PreparedRequest;
use pyo3::prelude::*;
use response::{ContentIterator, LinesIterator, Response, StreamingBody};
use session::Session;

#[pymodule]
fn _bindings(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Session>()?;
    m.add_class::<Response>()?;
    m.add_class::<StreamingBody>()?;
    m.add_class::<CaseInsensitiveDict>()?;
    m.add_class::<CaseInsensitiveDictIter>()?;
    m.add_class::<PreparedRequest>()?;
    m.add_class::<ContentIterator>()?;
    m.add_class::<LinesIterator>()?;
    m.add_class::<utils::LookupDict>()?;

    // Utility functions
    m.add_function(wrap_pyfunction!(utils::is_ipv4_address, m)?)?;
    m.add_function(wrap_pyfunction!(utils::is_valid_cidr, m)?)?;
    m.add_function(wrap_pyfunction!(utils::dotted_netmask, m)?)?;
    m.add_function(wrap_pyfunction!(utils::address_in_network, m)?)?;
    m.add_function(wrap_pyfunction!(utils::get_auth_from_url, m)?)?;
    m.add_function(wrap_pyfunction!(utils::unquote_unreserved, m)?)?;
    m.add_function(wrap_pyfunction!(utils::requote_uri, m)?)?;
    m.add_function(wrap_pyfunction!(utils::urldefragauth, m)?)?;
    m.add_function(wrap_pyfunction!(utils::prepend_scheme_if_needed, m)?)?;
    m.add_function(wrap_pyfunction!(utils::unicode_is_ascii, m)?)?;
    m.add_function(wrap_pyfunction!(utils::parse_header_links, m)?)?;
    m.add_function(wrap_pyfunction!(utils::get_encoding_from_headers, m)?)?;
    m.add_function(wrap_pyfunction!(utils::_parse_content_type_header, m)?)?;
    m.add_function(wrap_pyfunction!(utils::guess_json_utf, m)?)?;
    m.add_function(wrap_pyfunction!(utils::select_proxy, m)?)?;
    m.add_function(wrap_pyfunction!(utils::should_bypass_proxies_core, m)?)?;
    m.add_function(wrap_pyfunction!(utils::request_url, m)?)?;
    m.add_function(wrap_pyfunction!(utils::check_header_validity, m)?)?;
    m.add_function(wrap_pyfunction!(utils::to_native_string, m)?)?;
    m.add_function(wrap_pyfunction!(utils::parse_list_header, m)?)?;
    m.add_function(wrap_pyfunction!(utils::parse_dict_header, m)?)?;
    m.add_function(wrap_pyfunction!(utils::unquote_header_value, m)?)?;
    m.add_function(wrap_pyfunction!(utils::merge_setting, m)?)?;
    m.add_function(wrap_pyfunction!(utils::default_user_agent, m)?)?;
    m.add_function(wrap_pyfunction!(utils::default_headers, m)?)?;
    m.add_function(wrap_pyfunction!(utils::_init_status_codes, m)?)?;
    m.add("DEFAULT_ACCEPT_ENCODING", utils::DEFAULT_ACCEPT_ENCODING)?;

    // Session utility functions
    m.add_function(wrap_pyfunction!(session::should_strip_auth, m)?)?;
    m.add_function(wrap_pyfunction!(session::rebuild_method, m)?)?;
    Ok(())
}

/// All symbols expected to be available from the `_bindings` Python module.
/// Used by tests to verify no registration is missing.
#[cfg(test)]
pub const EXPECTED_EXPORTS: &[&str] = &[
    // Classes
    "Session",
    "Response",
    "StreamingBody",
    "CaseInsensitiveDict",
    "CaseInsensitiveDictIter",
    "PreparedRequest",
    "ContentIterator",
    "LinesIterator",
    "LookupDict",
    // Constants
    "DEFAULT_ACCEPT_ENCODING",
    // Utility functions — IP/CIDR
    "is_ipv4_address",
    "is_valid_cidr",
    "dotted_netmask",
    "address_in_network",
    // Utility functions — URL
    "get_auth_from_url",
    "unquote_unreserved",
    "requote_uri",
    "urldefragauth",
    "prepend_scheme_if_needed",
    "unicode_is_ascii",
    // Utility functions — Headers
    "parse_header_links",
    "get_encoding_from_headers",
    "_parse_content_type_header",
    "check_header_validity",
    "to_native_string",
    "parse_list_header",
    "parse_dict_header",
    "unquote_header_value",
    // Utility functions — Encoding
    "guess_json_utf",
    // Utility functions — Proxy
    "select_proxy",
    "should_bypass_proxies_core",
    // Utility functions — Misc
    "request_url",
    "merge_setting",
    "default_user_agent",
    "default_headers",
    "_init_status_codes",
    // Session utility functions
    "should_strip_auth",
    "rebuild_method",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn init_python() {
        Python::initialize();
        Python::attach(|py| {
            let sys = py.import("sys").unwrap();
            let path = sys.getattr("path").unwrap();
            let python_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/python");
            let _ = path.call_method1("insert", (0, python_dir));
        });
    }

    #[test]
    fn test_all_exports_accessible_from_bindings() {
        init_python();
        Python::attach(|py| {
            let module = py.import("snekwest._bindings").unwrap();
            for name in EXPECTED_EXPORTS {
                assert!(
                    module.getattr(*name).is_ok(),
                    "Missing export in _bindings: {}",
                    name
                );
            }
        });
    }
}

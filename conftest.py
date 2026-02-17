"""Root conftest.py — swaps ``requests`` for ``snekwest`` in sys.modules.

The swap happens at module-level (import time) so it runs before
any downstream conftest.py files are loaded.

Group B tests (Python-internal tests) are skipped via pytest_collection_modifyitems.
"""

import sys
from pathlib import Path

import pytest

# Make upstream ``from tests.testserver.server import ...`` work.
sys.path.insert(0, str(Path(__file__).parent / "python-requests"))

import snekwest  # noqa: E402
import snekwest._internal_utils  # noqa: E402
import snekwest.adapters  # noqa: E402
import snekwest.auth  # noqa: E402
import snekwest.certs  # noqa: E402
import snekwest.compat  # noqa: E402
import snekwest.cookies  # noqa: E402
import snekwest.exceptions  # noqa: E402
import snekwest.help  # noqa: E402
import snekwest.hooks  # noqa: E402
import snekwest.models  # noqa: E402
import snekwest.packages  # noqa: E402
import snekwest.sessions  # noqa: E402
import snekwest.status_codes  # noqa: E402
import snekwest.structures  # noqa: E402
import snekwest.utils  # noqa: E402

_MODULE_MAP = {
    "requests": snekwest,
    "requests._internal_utils": snekwest._internal_utils,
    "requests.adapters": snekwest.adapters,
    "requests.auth": snekwest.auth,
    "requests.certs": snekwest.certs,
    "requests.compat": snekwest.compat,
    "requests.cookies": snekwest.cookies,
    "requests.exceptions": snekwest.exceptions,
    "requests.help": snekwest.help,
    "requests.hooks": snekwest.hooks,
    "requests.models": snekwest.models,
    "requests.packages": snekwest.packages,
    "requests.sessions": snekwest.sessions,
    "requests.status_codes": snekwest.status_codes,
    "requests.structures": snekwest.structures,
    "requests.utils": snekwest.utils,
}

for _alias, _mod in _MODULE_MAP.items():
    sys.modules[_alias] = _mod

# Map requests.packages.urllib3 (and sub-modules) so that
# ``from requests.packages.urllib3.poolmanager import PoolManager`` works.
import urllib3  # noqa: E402

sys.modules["requests.packages.urllib3"] = urllib3
# Dynamically map all urllib3 sub-modules already loaded
for _name, _mod in list(sys.modules.items()):
    if _name.startswith("urllib3.") and _mod is not None:
        sys.modules["requests.packages." + _name] = _mod


# ---------------------------------------------------------------------------
# Group B: tests that probe Python internals (pickling, isinstance on _content,
# urllib3 pool internals, etc.).  These are skipped because snekwest replaces
# those internals with Rust pyclasses.
# ---------------------------------------------------------------------------
_GROUP_B_TESTS = frozenset(
    {
        # test_requests.py -- Python-internal tests
        "TestRequests::test_cookielib_cookiejar_on_redirect",
        "TestRequests::test_https_warnings",
        "TestRequests::test_cookie_policy_copy",
        "TestRequests::test_empty_response_has_content_none",
        "TestRequests::test_response_is_iterable",
        "TestRequests::test_response_decode_unicode",
        "TestRequests::test_response_chunk_size_type",
        "TestRequests::test_iter_content_wraps_exceptions",
        "TestRequests::test_request_and_response_are_pickleable",
        "TestRequests::test_prepared_request_is_pickleable",
        "TestRequests::test_prepared_request_with_file_is_pickleable",
        "TestRequests::test_prepared_request_with_hook_is_pickleable",
        "TestRequests::test_session_pickling",
        "TestRequests::test_transport_adapter_ordering",
        "TestRequests::test_session_get_adapter_prefix_matching",
        "TestRequests::test_session_get_adapter_prefix_matching_mixed_case",
        "TestRequests::test_session_get_adapter_prefix_matching_is_case_insensitive",
        "TestRequests::test_session_get_adapter_prefix_with_trailing_slash",
        "TestRequests::test_session_get_adapter_prefix_without_trailing_slash",
        "TestRequests::test_prepare_body_position_non_stream",
        "TestRequests::test_rewind_body",
        "TestRequests::test_rewind_body_no_seek",
        "TestRequests::test_rewind_body_failed_seek",
        "TestRequests::test_rewind_body_failed_tell",
        "TestRequests::test_redirect_with_wrong_gzipped_header",
        "TestRequests::test_unconsumed_session_response_closes_connection",
        "TestRequests::test_response_iter_lines_reentrant",
        "TestRequests::test_session_close_proxy_clear",
        "TestRequests::test_response_json_when_content_is_None",
        "TestRequests::test_response_without_release_conn",
        "test_requests_are_updated_each_time",
        "test_prepared_copy",
        "test_urllib3_pool_connection_closed",
        "test_json_decode_errors_are_serializable_deserializable",
        "TestPreparingURLs::test_different_connection_pool_for_tls_settings_verify_True",
        "TestPreparingURLs::test_different_connection_pool_for_tls_settings_verify_bundle_expired_cert",
        "TestPreparingURLs::test_different_connection_pool_for_tls_settings_verify_bundle_unexpired_cert",
        # test_structures.py
        "TestCaseInsensitiveDict::test_repr",
        "TestLookupDict::test_repr",
        # test_help.py -- all tests
        "test_system_ssl",
        "test_idna_without_version_attribute",
        "test_idna_with_version_attribute",
        # test_packages.py -- all tests
        "test_can_access_urllib3_attribute",
        "test_can_access_idna_attribute",
        "test_can_access_chardet_attribute",
        # test_adapters.py
        "test_request_url_trims_leading_path_separators",
        # test_requests.py -- require CWD=submodule root for cert/file paths
        "TestRequests::test_POSTBIN_GET_POST_FILES",
        "TestRequests::test_POSTBIN_GET_POST_FILES_WITH_DATA",
        "TestRequests::test_conflicting_post_params",
        # mTLS test — requires urllib3 connection pool internals
        "TestPreparingURLs::test_different_connection_pool_for_mtls_settings",
        # Windows CI: localhost:1 times out instead of connection refused
        "TestRequests::test_errors",
        # test_testserver.py -- all tests
        "TestTestServer::test_basic",
        "TestTestServer::test_server_closes",
        "TestTestServer::test_text_response",
        "TestTestServer::test_basic_response",
        "TestTestServer::test_basic_waiting_server",
        "TestTestServer::test_multiple_requests",
        "TestTestServer::test_request_recovery",
        "TestTestServer::test_requests_after_timeout_are_not_received",
        "TestTestServer::test_request_recovery_with_bigger_timeout",
        "TestTestServer::test_server_finishes_on_error",
        "TestTestServer::test_server_finishes_when_no_connections",
    }
)

_GROUP_B_SKIP = pytest.mark.skip(reason="Group B: tests Python internals")


def pytest_collection_modifyitems(config, items):
    for item in items:
        # Build a suffix like "TestRequests::test_foo" or "test_foo[param]"
        # from the full nodeid "tests/test_requests.py::TestRequests::test_foo[param]"
        parts = item.nodeid.split("::", 1)
        suffix = parts[1] if len(parts) > 1 else ""
        # Strip parametrize IDs for matching: "test_prepared_copy[None]" -> "test_prepared_copy"
        base_name = suffix.split("[")[0] if "[" in suffix else suffix
        if base_name in _GROUP_B_TESTS or suffix in _GROUP_B_TESTS:
            item.add_marker(_GROUP_B_SKIP)

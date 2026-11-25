"""Unit tests for CWEMapper and OWASPMapper in SecureCode AI."""

from analyzer.cwe_mapper import CWEMapper
from analyzer.owasp_mapper import OWASPMapper


def test_cwe_normalization():
    assert CWEMapper.normalize_cwe("89") == "CWE-89"
    assert CWEMapper.normalize_cwe("cwe-89") == "CWE-89"
    assert CWEMapper.normalize_cwe("CWE-089") == "CWE-89"
    assert CWEMapper.normalize_cwe("cwe_78") == "CWE-78"
    assert CWEMapper.normalize_cwe("") == "CWE-OTHER"


def test_cwe_definitions():
    defn = CWEMapper.get_definition("CWE-89")
    assert defn is not None
    assert defn.cwe == "CWE-89"
    assert defn.category == "SQL_INJECTION"
    assert defn.default_severity == "CRITICAL"
    assert defn.base_risk_score >= 90.0

    defn_cmd = CWEMapper.get_definition("CWE-78")
    assert defn_cmd is not None
    assert defn_cmd.default_severity == "CRITICAL"


def test_category_to_cwe_mapping():
    assert CWEMapper.map_category_to_cwe("SQL_INJECTION") == "CWE-89"
    assert CWEMapper.map_category_to_cwe("COMMAND_INJECTION") == "CWE-78"
    assert CWEMapper.map_category_to_cwe("PATH_TRAVERSAL") == "CWE-22"
    assert CWEMapper.map_category_to_cwe("HARDCODED_CREDENTIALS") == "CWE-798"
    assert CWEMapper.map_category_to_cwe("UNKNOWN_CATEGORY") == "CWE-OTHER"


def test_owasp_mapping():
    assert OWASPMapper.map_cwe_to_owasp("CWE-89") == "A03:2021-Injection"
    assert OWASPMapper.map_cwe_to_owasp("CWE-78") == "A03:2021-Injection"
    assert OWASPMapper.map_cwe_to_owasp("CWE-79") == "A03:2021-Injection"
    assert OWASPMapper.map_cwe_to_owasp("CWE-22") == "A01:2021-Broken Access Control"
    assert OWASPMapper.map_cwe_to_owasp("CWE-798") == "A07:2021-Identification and Authentication Failures"
    assert OWASPMapper.map_cwe_to_owasp("CWE-502") == "A08:2021-Software and Data Integrity Failures"
    assert OWASPMapper.map_cwe_to_owasp("CWE-918") == "A10:2021-Server-Side Request Forgery"

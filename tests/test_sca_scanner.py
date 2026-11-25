import pytest
from analyzer.dependency_parser import DependencyParser
from analyzer.version_matcher import VersionMatcher, VulnerabilityStatus
from analyzer.sca_scanner import ScaScanner


def test_requirements_parser(sample_requirements_content):
    """Test parsing requirements.txt with pinned and range specs."""
    deps = DependencyParser.parse_requirements_txt(sample_requirements_content)
    dep_dict = {d.name: d for d in deps}

    assert "requests" in dep_dict
    assert dep_dict["requests"].version == "2.19.0"
    assert dep_dict["requests"].is_pinned is True

    assert "urllib3" in dep_dict
    assert dep_dict["urllib3"].version == "1.24.1"

    assert "fastapi" in dep_dict
    assert dep_dict["fastapi"].is_pinned is False


def test_package_json_parser(sample_package_json_content):
    """Test parsing package.json dependencies and devDependencies."""
    deps = DependencyParser.parse_package_json(sample_package_json_content)
    dep_dict = {d.name: d for d in deps}

    assert "lodash" in dep_dict
    assert dep_dict["lodash"].ecosystem == "npm"
    assert "mocha" in dep_dict
    assert dep_dict["mocha"].is_dev is True


def test_package_lock_parser():
    """Test parsing package-lock.json with resolved versions."""
    lock_content = """{
      "name": "sample",
      "version": "1.0.0",
      "lockfileVersion": 2,
      "packages": {
        "node_modules/axios": {
          "version": "0.21.1",
          "resolved": "https://registry.npmjs.org/axios/-/axios-0.21.1.tgz"
        }
      }
    }"""
    deps = DependencyParser.parse_package_lock_json(lock_content)
    assert len(deps) >= 1
    assert deps[0].name == "axios"
    assert deps[0].version == "0.21.1"
    assert deps[0].is_pinned is True


def test_pyproject_toml_parser():
    """Test parsing pyproject.toml PEP 621 dependencies."""
    toml_content = """
    [project]
    name = "my-project"
    version = "0.1.0"
    dependencies = [
        "flask==2.0.1",
        "requests>=2.25.0"
    ]
    """
    deps = DependencyParser.parse_pyproject_toml(toml_content)
    dep_dict = {d.name: d for d in deps}
    assert "flask" in dep_dict
    assert dep_dict["flask"].version == "2.0.1"


def test_version_matcher_affected():
    """Test version range checking: version falls within affected range."""
    # Advisory affects >= 2.0.0, < 2.20.0
    advisory_ranges = [
        {
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "2.0.0"},
                {"fixed": "2.20.0"}
            ]
        }
    ]
    status, details = VersionMatcher.is_version_affected("2.19.0", advisory_ranges, "PyPI")
    assert status == VulnerabilityStatus.AFFECTED
    assert "2.20.0" in details


def test_version_matcher_unaffected():
    """Test version range checking: version is patched (fixed)."""
    advisory_ranges = [
        {
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "2.0.0"},
                {"fixed": "2.20.0"}
            ]
        }
    ]
    status, _ = VersionMatcher.is_version_affected("2.25.0", advisory_ranges, "PyPI")
    assert status == VulnerabilityStatus.UNAFFECTED


def test_sca_scanner_advisory_cwe_mapping():
    """Test that SCA findings receive accurate advisory CWE or CWE-1395, never arbitrary generic CWEs."""
    advisory = {
        "id": "GHSA-j8r2-6x86-q33q",
        "summary": "Requests vulnerable to session leak",
        "details": "Details here",
        "database_specific": {
            "cwe_ids": ["CWE-200"],
            "severity": "HIGH"
        }
    }
    cwe = ScaScanner.extract_cwe_from_advisory(advisory)
    assert cwe == "CWE-200"

    # Default fallback when no specific CWE is provided in advisory
    advisory_no_cwe = {"id": "OSV-123"}
    default_cwe = ScaScanner.extract_cwe_from_advisory(advisory_no_cwe)
    assert default_cwe == "CWE-1395"


def test_no_vulnerability_inferred_without_version():
    """Ensure that an unversioned dependency import is NOT marked vulnerable without version evidence."""
    scanner = ScaScanner()
    # Pinned=False, version=None
    from analyzer.dependency_parser import ParsedDependency
    unversioned_dep = ParsedDependency(
        name="requests",
        version=None,
        version_constraint="*",
        ecosystem="PyPI",
        source_manifest="requirements.txt",
        is_pinned=False
    )
    # Scanning without known version must evaluate safely without false positives
    findings = scanner.scan_dependencies([unversioned_dep], scan_id="test-scan")
    assert len(findings) == 0, "Unversioned dependencies must not be flagged without version evidence!"

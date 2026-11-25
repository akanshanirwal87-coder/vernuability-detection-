"""Unit tests for FixValidator in SecureCode AI."""

from analyzer.fix_validator import FixValidator


def test_fix_validation_successful():
    original = """
import sqlite3
def fetch(uid):
    cursor.execute("SELECT * FROM users WHERE id = '" + uid + "'")
"""
    proposed = '    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))'
    finding = {
        "id": "fnd-1",
        "cwe": "CWE-89",
        "startLine": 4,
        "endLine": 4,
        "file": "app.py",
    }

    report = FixValidator.verify_remediation(
        original_source=original,
        proposed_code=proposed,
        target_finding=finding,
        language="python",
    )

    assert report.passed is True
    assert report.status == "REGRESSION_TESTS_PASSED"
    assert report.syntax_valid is True
    assert report.vulnerability_fixed is True
    assert report.regression_free is True
    assert report.unified_diff != ""


def test_fix_validation_syntax_error():
    original = "x = 1"
    proposed = "def broken(:"
    finding = {"id": "fnd-1", "cwe": "CWE-89", "startLine": 1, "endLine": 1}

    report = FixValidator.verify_remediation(
        original_source=original,
        proposed_code=proposed,
        target_finding=finding,
        language="python",
    )

    assert report.passed is False
    assert report.status == "VERIFICATION_FAILED"
    assert report.syntax_valid is False
    assert "Syntax Error" in report.message


def test_fix_validation_target_vulnerability_still_present():
    original = """
import sqlite3
def fetch(uid):
    cursor.execute("SELECT * FROM users WHERE id = '" + uid + "'")
"""
    # Fix still uses dynamic concatenation!
    proposed = '    cursor.execute("SELECT * FROM users WHERE id = " + str(uid))'
    finding = {"id": "fnd-1", "cwe": "CWE-89", "startLine": 4, "endLine": 4}

    report = FixValidator.verify_remediation(
        original_source=original,
        proposed_code=proposed,
        target_finding=finding,
        language="python",
    )

    # Must fail because target vulnerability is still detected!
    assert report.passed is False
    assert report.status == "VERIFICATION_FAILED"
    assert report.vulnerability_fixed is False


def test_fix_validation_security_regression():
    original = """
def fetch(uid):
    query = "SELECT * FROM t WHERE id=" + uid
    cursor.execute(query)
"""
    # Eliminates SQLi but introduces Command Injection (Security Regression!)
    proposed = """    import os
    os.system("echo " + uid)
    cursor.execute("SELECT * FROM t WHERE id = %s", (uid,))"""
    finding = {"id": "fnd-1", "cwe": "CWE-89", "startLine": 3, "endLine": 4}

    report = FixValidator.verify_remediation(
        original_source=original,
        proposed_code=proposed,
        target_finding=finding,
        language="python",
    )

    # Must fail because a new critical security defect was introduced!
    assert report.passed is False
    assert report.status == "VERIFICATION_FAILED"
    assert report.regression_free is False
    assert len(report.new_findings) >= 1

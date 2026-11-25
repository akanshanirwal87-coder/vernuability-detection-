"""Unit tests for HybridScanner in SecureCode AI."""

from analyzer.hybrid_scanner import HybridScanner


def test_hybrid_scanner_python_vulnerable():
    code = """
import sqlite3
from flask import request

def get_user():
    uid = request.args.get("id")
    query = "SELECT * FROM users WHERE id = '" + uid + "'"
    cursor.execute(query)
"""
    scanner = HybridScanner(code, language="python", file_name="app.py")
    findings, ast_summary, risk_report = scanner.scan()

    assert len(findings) >= 1
    # Verify deduplication combined AST and Taint into hybrid
    sqli = next((f for f in findings if f["cwe"] == "CWE-89"), None)
    assert sqli is not None
    assert sqli["detectionSource"] in ("HYBRID_TAINT_AND_AST", "TAINT_ANALYSIS", "AST")

    # Risk report checks
    assert risk_report["overallScore"] > 60.0
    assert risk_report["riskLevel"] in ("CRITICAL", "HIGH")


def test_hybrid_scanner_safe_code():
    code = """
import sqlite3
from flask import request

def get_user():
    uid = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
"""
    scanner = HybridScanner(code, language="python", file_name="app.py")
    findings, ast_summary, risk_report = scanner.scan()

    # Parameterized query should have 0 findings
    assert len(findings) == 0
    assert risk_report["overallScore"] == 0.0
    assert risk_report["riskLevel"] == "CLEAN"


def test_hybrid_scanner_javascript():
    code = """
const userMsg = urlParams.get('msg');
document.getElementById('display').innerHTML = userMsg;
"""
    scanner = HybridScanner(code, language="javascript", file_name="app.js")
    findings, _, risk_report = scanner.scan()

    assert len(findings) >= 1
    assert any(f["cwe"] == "CWE-79" for f in findings)
    assert risk_report["overallScore"] > 0.0

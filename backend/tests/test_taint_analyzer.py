"""Unit tests for TaintAnalyzer and Dataflow Analysis in SecureCode AI."""

from analyzer.taint_analyzer import TaintAnalyzer


def test_python_sqli_taint_flow():
    code = """
import sqlite3
from flask import request

def get_user():
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
"""
    analyzer = TaintAnalyzer(code, file_name="app.py", language="python")
    findings = analyzer.analyze()

    assert len(findings) >= 1
    f = findings[0]
    assert f["cwe"] == "CWE-89"
    assert f["category"] == "SQL_INJECTION"
    assert f["detectionSource"] == "TAINT_ANALYSIS"
    assert f["dataFlow"] is not None
    assert len(f["dataFlow"]) >= 2

    # Verify source and sink in steps
    types = [step["type"] for step in f["dataFlow"]]
    assert "SOURCE" in types
    assert "SINK" in types


def test_python_safe_parameterized_query_suppression():
    code = """
import sqlite3
from flask import request

def get_user():
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
    analyzer = TaintAnalyzer(code, file_name="app.py", language="python")
    findings = analyzer.analyze()

    # Parameterized queries must not trigger SQL injection!
    assert len(findings) == 0


def test_python_command_injection_taint():
    code = """
import subprocess
from flask import request

def run_ping():
    host = request.args.get("host")
    cmd = "ping -c 1 " + host
    subprocess.run(cmd, shell=True)
"""
    analyzer = TaintAnalyzer(code, file_name="app.py", language="python")
    findings = analyzer.analyze()

    assert len(findings) >= 1
    assert findings[0]["cwe"] == "CWE-78"
    assert findings[0]["severity"] == "CRITICAL"


def test_python_safe_subprocess_shell_false():
    code = """
import subprocess
from flask import request

def run_ping():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], shell=False)
"""
    analyzer = TaintAnalyzer(code, file_name="app.py", language="python")
    findings = analyzer.analyze()

    # shell=False with argument list is safe against command injection!
    assert len(findings) == 0


def test_javascript_xss_taint_flow():
    code = """
const query = urlParams.get('q');
document.getElementById('output').innerHTML = 'Search: ' + query;
"""
    analyzer = TaintAnalyzer(code, file_name="index.js", language="javascript")
    findings = analyzer.analyze()

    assert len(findings) >= 1
    assert findings[0]["cwe"] == "CWE-79"
    assert findings[0]["dataFlow"] is not None
    assert findings[0]["dataFlow"][0]["type"] == "SOURCE"
    assert findings[0]["dataFlow"][-1]["type"] == "SINK"


def test_javascript_safe_dompurify_sanitization():
    code = """
const query = urlParams.get('q');
document.getElementById('output').innerHTML = DOMPurify.sanitize(query);
"""
    analyzer = TaintAnalyzer(code, file_name="index.js", language="javascript")
    findings = analyzer.analyze()

    # DOMPurify sanitized content must not flag XSS
    assert len(findings) == 0

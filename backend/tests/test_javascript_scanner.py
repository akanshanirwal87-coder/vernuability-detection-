"""Unit tests for JavaScriptScanner in SecureCode AI."""

from analyzer.javascript_scanner import JavaScriptScanner


def test_js_xss_innerhtml():
    code = """
const userText = urlParams.get('msg');
document.getElementById('chat').innerHTML = '<div>' + userText + '</div>';
"""
    scanner = JavaScriptScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-79" for f in findings)


def test_js_safe_dompurify():
    code = """
const userText = urlParams.get('msg');
document.getElementById('chat').innerHTML = DOMPurify.sanitize(userText);
"""
    scanner = JavaScriptScanner(code)
    findings, _ = scanner.scan()
    # Sanitized DOM assignment must not flag XSS
    assert not any(f["cwe"] == "CWE-79" for f in findings)


def test_js_prototype_pollution():
    code = """
const payload = JSON.parse(req.body);
target[payload.key] = payload.value; // __proto__
target.__proto__.isAdmin = true;
"""
    scanner = JavaScriptScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-1321" for f in findings)


def test_js_dynamic_eval():
    code = """
const expr = req.query.expr;
eval(expr);
"""
    scanner = JavaScriptScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-95" for f in findings)


def test_js_command_injection_exec():
    code = """
const child_process = require('child_process');
child_process.exec('ping ' + req.query.host);
"""
    scanner = JavaScriptScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-78" for f in findings)


def test_js_hardcoded_secrets():
    code = """
const jwt_secret = "my_super_secret_jwt_key_12345";
"""
    scanner = JavaScriptScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-798" for f in findings)

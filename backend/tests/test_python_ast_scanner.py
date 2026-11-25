"""Unit tests for PythonAstScanner in SecureCode AI."""

from analyzer.python_ast_scanner import PythonAstScanner


def test_sqli_string_concatenation():
    code = """
query = "SELECT * FROM users WHERE username = '" + user + "'"
cursor.execute(query)
"""
    scanner = PythonAstScanner(code)
    findings, summary = scanner.scan()
    assert any(f["cwe"] == "CWE-89" for f in findings)
    assert summary["sinksIdentified"] >= 1


def test_sqli_fstring():
    code = """
cursor.execute(f"SELECT * FROM items WHERE category = {cat}")
"""
    scanner = PythonAstScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-89" for f in findings)


def test_safe_parameterized_query():
    code = """
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
    scanner = PythonAstScanner(code)
    findings, _ = scanner.scan()
    assert not any(f["cwe"] == "CWE-89" for f in findings)


def test_command_injection_os_system():
    code = """
import os
os.system("rm -rf " + folder)
"""
    scanner = PythonAstScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-78" for f in findings)


def test_safe_subprocess():
    code = """
import subprocess
subprocess.run(["ls", "-la", path], shell=False)
"""
    scanner = PythonAstScanner(code)
    findings, _ = scanner.scan()
    assert not any(f["cwe"] == "CWE-78" for f in findings)


def test_path_traversal_open():
    code = """
user_file = request.args.get('file')
with open('/var/data/' + user_file, 'r') as f:
    data = f.read()
"""
    scanner = PythonAstScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-22" for f in findings)


def test_safe_path_containment():
    code = """
filename = os.path.basename(user_input)
safe_path = os.path.abspath(os.path.join(BASE_DIR, filename))
if not safe_path.startswith(BASE_DIR):
    raise ValueError("Access Denied")
with open(safe_path, 'r') as f:
    data = f.read()
"""
    scanner = PythonAstScanner(code)
    findings, _ = scanner.scan()
    assert not any(f["cwe"] == "CWE-22" for f in findings)


def test_unsafe_dynamic_evaluation():
    code = """
user_code = request.args.get('expr')
result = eval(user_code)
"""
    scanner = PythonAstScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-95" for f in findings)


def test_hardcoded_secrets():
    code = """
API_KEY = "sk-live-98745982734982739487"
"""
    scanner = PythonAstScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-798" for f in findings)


def test_weak_cryptography():
    code = """
import hashlib
token = hashlib.md5(password.encode()).hexdigest()
"""
    scanner = PythonAstScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-327" for f in findings)


def test_insecure_temp_file():
    code = """
import tempfile
tmp_path = tempfile.mktemp()
"""
    scanner = PythonAstScanner(code)
    findings, _ = scanner.scan()
    assert any(f["cwe"] == "CWE-377" for f in findings)


def test_malformed_syntax_graceful_handling():
    malformed_code = "def foo(: return broken"
    scanner = PythonAstScanner(malformed_code)
    findings, summary = scanner.scan()
    assert len(findings) == 1
    assert findings[0]["category"] == "SYNTAX_ERROR"
    assert summary["nodesCount"] == 0

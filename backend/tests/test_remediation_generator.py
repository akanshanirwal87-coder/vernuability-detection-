"""Unit tests for RemediationGenerator in SecureCode AI."""

from analyzer.remediation_generator import RemediationGenerator


def test_remediation_generation_sqli():
    rem = RemediationGenerator.generate_remediation(
        cwe="CWE-89",
        vulnerable_code="cursor.execute('SELECT * FROM t WHERE id=' + uid)",
        language="python",
    )
    assert rem["cwe"] == "CWE-89"
    assert "%s" in rem["suggestedCode"] or "?" in rem["suggestedCode"]
    assert "Parameterized" in rem["title"]
    assert len(rem["bestPractices"]) >= 2


def test_remediation_generation_command_injection():
    rem = RemediationGenerator.generate_remediation(
        cwe="CWE-78",
        vulnerable_code="os.system('ping ' + host)",
        language="python",
    )
    assert rem["cwe"] == "CWE-78"
    assert "shell=False" in rem["suggestedCode"]


def test_remediation_generation_path_traversal():
    rem = RemediationGenerator.generate_remediation(
        cwe="CWE-22",
        vulnerable_code="open(user_path)",
        language="python",
    )
    assert rem["cwe"] == "CWE-22"
    assert "os.path.basename" in rem["suggestedCode"]
    assert "startswith" in rem["suggestedCode"]


def test_remediation_generation_xss():
    rem = RemediationGenerator.generate_remediation(
        cwe="CWE-79",
        vulnerable_code="element.innerHTML = userInput",
        language="javascript",
    )
    assert rem["cwe"] == "CWE-79"
    assert "textContent" in rem["suggestedCode"] or "DOMPurify" in rem["suggestedCode"]


def test_remediation_generation_secrets():
    rem = RemediationGenerator.generate_remediation(
        cwe="CWE-798",
        vulnerable_code="API_KEY = 'secret12345'",
        language="python",
        variable_name="API_KEY",
    )
    assert rem["cwe"] == "CWE-798"
    assert "os.getenv('API_KEY')" in rem["suggestedCode"]

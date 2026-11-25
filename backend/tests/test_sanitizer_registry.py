"""Unit tests for SanitizerRegistry in SecureCode AI."""

from analyzer.sanitizer_registry import SanitizerRegistry


def test_verified_sanitizers_recognized():
    # SQL casting
    assert SanitizerRegistry.is_sanitizer("int", cwe="CWE-89", language="python")
    assert SanitizerRegistry.is_sanitizer("float", cwe="CWE-89", language="python")

    # Command quoting
    assert SanitizerRegistry.is_sanitizer("shlex.quote", cwe="CWE-78", language="python")

    # Path basename
    assert SanitizerRegistry.is_sanitizer("os.path.basename", cwe="CWE-22", language="python")
    assert SanitizerRegistry.is_sanitizer("pathlib.Path.name", cwe="CWE-22", language="python")

    # XSS escaping
    assert SanitizerRegistry.is_sanitizer("html.escape", cwe="CWE-79", language="python")
    assert SanitizerRegistry.is_sanitizer("DOMPurify.sanitize", cwe="CWE-79", language="javascript")

    # Safe deserialization
    assert SanitizerRegistry.is_sanitizer("json.loads", cwe="CWE-502", language="python")
    assert SanitizerRegistry.is_sanitizer("yaml.safe_load", cwe="CWE-502", language="python")
    assert SanitizerRegistry.is_sanitizer("ast.literal_eval", cwe="CWE-502", language="python")


def test_fake_or_unverified_sanitizer_names_rejected():
    # Crucial rule: Do not treat a function as sanitizer simply because name contains "sanitize"
    assert not SanitizerRegistry.is_sanitizer("my_custom_sanitize_function", cwe="CWE-89", language="python")
    assert not SanitizerRegistry.is_sanitizer("sanitize_input", cwe="CWE-78", language="python")
    assert not SanitizerRegistry.is_sanitizer("clean_string", cwe="CWE-79", language="python")


def test_parameterized_query_detection():
    # Valid prepared statement with ?
    assert SanitizerRegistry.is_parameterized_query("SELECT * FROM users WHERE id = ?")
    # Valid prepared statement with %s
    assert SanitizerRegistry.is_parameterized_query("SELECT * FROM users WHERE id = %s AND active = %s")
    # Valid prepared statement with :name
    assert SanitizerRegistry.is_parameterized_query("SELECT * FROM users WHERE username = :uname")

    # Invalid: dynamic concatenation with +
    assert not SanitizerRegistry.is_parameterized_query("SELECT * FROM users WHERE id = " + "123")
    # Invalid: f-string
    assert not SanitizerRegistry.is_parameterized_query("f'SELECT * FROM users WHERE id = {uid}'")


def test_safe_path_containment():
    safe_code = """
    target = os.path.abspath(os.path.join(BASE_DIR, filename))
    if not target.startswith(BASE_DIR):
        raise ValueError('Invalid path')
    """
    assert SanitizerRegistry.is_safe_path_containment(safe_code)

    unsafe_code = "open('/tmp/' + user_filename)"
    assert not SanitizerRegistry.is_safe_path_containment(unsafe_code)

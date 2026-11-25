"""Unit tests for SinkRegistry in SecureCode AI."""

from analyzer.sink_registry import SinkRegistry


def test_python_sinks_retrieval():
    # SQL sink
    sink = SinkRegistry.get_python_sink("cursor.execute")
    assert sink is not None
    assert sink.cwe == "CWE-89"
    assert sink.category == "SQL_INJECTION"
    assert sink.default_severity == "CRITICAL"

    # Command sink
    cmd_sink = SinkRegistry.get_python_sink("os.system")
    assert cmd_sink is not None
    assert cmd_sink.cwe == "CWE-78"
    assert cmd_sink.default_severity == "CRITICAL"

    # Path traversal sink
    path_sink = SinkRegistry.get_python_sink("open")
    assert path_sink is not None
    assert path_sink.cwe == "CWE-22"
    assert path_sink.default_severity == "HIGH"

    # Deserialization sink
    deser_sink = SinkRegistry.get_python_sink("pickle.loads")
    assert deser_sink is not None
    assert deser_sink.cwe == "CWE-502"

    # Eval sink
    eval_sink = SinkRegistry.get_python_sink("eval")
    assert eval_sink is not None
    assert eval_sink.cwe == "CWE-95"


def test_javascript_sinks_retrieval():
    # DOM XSS
    xss_sink = SinkRegistry.get_js_sink("innerHTML")
    assert xss_sink is not None
    assert xss_sink.cwe == "CWE-79"

    # Command execution
    js_cmd = SinkRegistry.get_js_sink("child_process.exec")
    assert js_cmd is not None
    assert js_cmd.cwe == "CWE-78"

    # Prototype pollution
    proto_sink = SinkRegistry.get_js_sink("__proto__")
    assert proto_sink is not None
    assert proto_sink.cwe == "CWE-1321"


def test_unknown_sinks_return_none():
    assert SinkRegistry.get_python_sink("math.sin") is None
    assert SinkRegistry.get_js_sink("array.map") is None

"""Unit tests for SourceRegistry in SecureCode AI."""

from analyzer.source_registry import SourceRegistry, SourceDefinition


def test_match_python_call_sources():
    assert SourceRegistry.is_source("request.args.get('id')", language="python")
    assert SourceRegistry.is_source("request.form.get('user')", language="python")
    assert SourceRegistry.is_source("input('Enter command: ')", language="python")

    src = SourceRegistry.match_python_source("request.args.get('username')")
    assert src is not None
    assert src.category == "HTTP_QUERY"
    assert src.language == "python"


def test_match_python_attribute_sources():
    assert SourceRegistry.is_source("sys.argv[1]", language="python")
    assert SourceRegistry.is_source("request.data", language="python")
    assert SourceRegistry.is_source("request.json", language="python")

    src = SourceRegistry.match_python_source("sys.argv[1]")
    assert src is not None
    assert src.category == "CLI_ARG"


def test_match_javascript_sources():
    assert SourceRegistry.is_source("urlParams.get('q')", language="javascript")
    assert SourceRegistry.is_source("location.search", language="javascript")
    assert SourceRegistry.is_source("req.query.id", language="javascript")
    assert SourceRegistry.is_source("req.body.name", language="javascript")

    src = SourceRegistry.match_javascript_source("location.search")
    assert src is not None
    assert src.category == "DOM_INPUT"


def test_safe_non_sources():
    assert not SourceRegistry.is_source("int(123)", language="python")
    assert not SourceRegistry.is_source("math.sqrt(4)", language="python")
    assert not SourceRegistry.is_source("console.log('hello')", language="javascript")

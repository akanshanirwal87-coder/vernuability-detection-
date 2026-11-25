"""
Source Registry for SecureCode AI.
Identifies user-controlled and untrusted input entry points in Python and JavaScript/TypeScript.
Distinguishes between HTTP params, route params, request bodies, environment variables, CLI arguments, and DOM inputs.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set
import re


@dataclass(frozen=True)
class SourceDefinition:
    identifier: str
    category: str  # "HTTP_QUERY", "HTTP_BODY", "HTTP_HEADER", "CLI_ARG", "ENV_VAR", "DOM_INPUT", "STORAGE"
    language: str  # "python", "javascript", "all"
    description: str
    taint_level: float = 0.95  # Initial taint confidence


class SourceRegistry:
    """Registry of untrusted input sources for static and dataflow taint analysis."""

    # Python user-controlled input sources
    PYTHON_CALL_SOURCES: Dict[str, SourceDefinition] = {
        # Flask / Werkzeug
        "request.args.get": SourceDefinition("request.args.get", "HTTP_QUERY", "python", "Flask URL query parameter"),
        "request.form.get": SourceDefinition("request.form.get", "HTTP_BODY", "python", "Flask form body parameter"),
        "request.values.get": SourceDefinition("request.values.get", "HTTP_QUERY", "python", "Flask combined query/form values"),
        "request.headers.get": SourceDefinition("request.headers.get", "HTTP_HEADER", "python", "Flask HTTP request header"),
        "request.cookies.get": SourceDefinition("request.cookies.get", "HTTP_HEADER", "python", "Flask request cookie"),
        # Django
        "request.GET.get": SourceDefinition("request.GET.get", "HTTP_QUERY", "python", "Django GET query parameter"),
        "request.POST.get": SourceDefinition("request.POST.get", "HTTP_BODY", "python", "Django POST body parameter"),
        # FastAPI / Starlette
        "request.query_params.get": SourceDefinition("request.query_params.get", "HTTP_QUERY", "python", "FastAPI query parameter"),
        # CLI & System Input
        "input": SourceDefinition("input", "CLI_ARG", "python", "Console standard input"),
        "sys.stdin.read": SourceDefinition("sys.stdin.read", "CLI_ARG", "python", "Standard input stream read"),
        "sys.stdin.readline": SourceDefinition("sys.stdin.readline", "CLI_ARG", "python", "Standard input stream line read"),
        # Network & Socket
        "socket.recv": SourceDefinition("socket.recv", "NETWORK_INPUT", "python", "Raw socket network reception"),
    }

    PYTHON_ATTR_SOURCES: Dict[str, SourceDefinition] = {
        "sys.argv": SourceDefinition("sys.argv", "CLI_ARG", "python", "Command line arguments array"),
        "request.args": SourceDefinition("request.args", "HTTP_QUERY", "python", "Flask request arguments mapping"),
        "request.form": SourceDefinition("request.form", "HTTP_BODY", "python", "Flask form body mapping"),
        "request.data": SourceDefinition("request.data", "HTTP_BODY", "python", "Raw HTTP request payload"),
        "request.json": SourceDefinition("request.json", "HTTP_BODY", "python", "Parsed JSON HTTP request payload"),
        "request.GET": SourceDefinition("request.GET", "HTTP_QUERY", "python", "Django GET query dictionary"),
        "request.POST": SourceDefinition("request.POST", "HTTP_BODY", "python", "Django POST body dictionary"),
        "request.query_params": SourceDefinition("request.query_params", "HTTP_QUERY", "python", "FastAPI query params"),
    }

    # JavaScript user-controlled input sources
    JS_ATTR_SOURCES: Dict[str, SourceDefinition] = {
        "location.search": SourceDefinition("location.search", "DOM_INPUT", "javascript", "Window location query string"),
        "location.hash": SourceDefinition("location.hash", "DOM_INPUT", "javascript", "Window location URL hash fragment"),
        "location.href": SourceDefinition("location.href", "DOM_INPUT", "javascript", "Full browser window URL"),
        "document.URL": SourceDefinition("document.URL", "DOM_INPUT", "javascript", "Document URL property"),
        "document.documentURI": SourceDefinition("document.documentURI", "DOM_INPUT", "javascript", "Document URI"),
        "document.referrer": SourceDefinition("document.referrer", "DOM_INPUT", "javascript", "HTTP Referrer header in DOM"),
        "window.name": SourceDefinition("window.name", "DOM_INPUT", "javascript", "Window object name attribute"),
        "document.cookie": SourceDefinition("document.cookie", "DOM_INPUT", "javascript", "Browser document cookie string"),
        "req.query": SourceDefinition("req.query", "HTTP_QUERY", "javascript", "Express request query dictionary"),
        "req.params": SourceDefinition("req.params", "HTTP_QUERY", "javascript", "Express route parameters"),
        "req.body": SourceDefinition("req.body", "HTTP_BODY", "javascript", "Express parsed request body"),
        "req.headers": SourceDefinition("req.headers", "HTTP_HEADER", "javascript", "Express HTTP request headers"),
    }

    JS_CALL_SOURCES: Dict[str, SourceDefinition] = {
        "URLSearchParams.get": SourceDefinition("URLSearchParams.get", "DOM_INPUT", "javascript", "URL search parameter getter"),
        "urlParams.get": SourceDefinition("urlParams.get", "DOM_INPUT", "javascript", "Extracted URL search parameter"),
        "params.get": SourceDefinition("params.get", "DOM_INPUT", "javascript", "Extracted route parameter"),
        "localStorage.getItem": SourceDefinition("localStorage.getItem", "STORAGE", "javascript", "HTML5 LocalStorage read"),
        "sessionStorage.getItem": SourceDefinition("sessionStorage.getItem", "STORAGE", "javascript", "HTML5 SessionStorage read"),
    }

    @classmethod
    def match_python_source(cls, expr_text: str) -> Optional[SourceDefinition]:
        """Matches a Python expression against known untrusted sources."""
        cleaned = expr_text.strip()
        for pattern, src in cls.PYTHON_CALL_SOURCES.items():
            if pattern in cleaned:
                return src
        for pattern, src in cls.PYTHON_ATTR_SOURCES.items():
            if re.search(rf"\b{re.escape(pattern)}\b", cleaned):
                return src
        return None

    @classmethod
    def match_javascript_source(cls, expr_text: str) -> Optional[SourceDefinition]:
        """Matches a JavaScript expression against known untrusted sources."""
        cleaned = expr_text.strip()
        for pattern, src in cls.JS_CALL_SOURCES.items():
            if pattern in cleaned:
                return src
        for pattern, src in cls.JS_ATTR_SOURCES.items():
            if re.search(rf"\b{re.escape(pattern)}\b", cleaned):
                return src
        return None

    @classmethod
    def is_source(cls, expr_text: str, language: str = "python") -> bool:
        """Determines if the given expression matches a registered input source."""
        if language.lower() == "python":
            return cls.match_python_source(expr_text) is not None
        elif language.lower() in ("javascript", "typescript"):
            return cls.match_javascript_source(expr_text) is not None
        return False

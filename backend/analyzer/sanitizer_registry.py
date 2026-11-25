"""
Sanitizer Registry for SecureCode AI.
Maintains verified, context-specific sanitizers and security guards.
IMPORTANT: Does NOT treat an arbitrary function as a sanitizer simply because its name contains "sanitize".
Only true cryptographic, encoding, casting, canonicalizing, or parameterizing operations are accepted.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Callable, Any
import ast
import re


@dataclass(frozen=True)
class SanitizerDefinition:
    identifier: str
    target_cwe: str          # CWE identifier this sanitizer defuses
    language: str            # "python", "javascript", "all"
    description: str
    is_structural_guard: bool = False  # e.g. isinstance(x, int), parameter binding (? or %s)


class SanitizerRegistry:
    """Registry of verified sanitizers and defense mechanisms."""

    # Python Verified Sanitizers mapped by CWE
    PYTHON_SANITIZERS: Dict[str, Dict[str, SanitizerDefinition]] = {
        "CWE-89": {  # SQL Injection Sanitizers
            "int": SanitizerDefinition("int", "CWE-89", "python", "Casting input to integer prevents SQL string escaping"),
            "float": SanitizerDefinition("float", "CWE-89", "python", "Casting input to float prevents SQL syntax injection"),
            "uuid.UUID": SanitizerDefinition("uuid.UUID", "CWE-89", "python", "UUID format validation eliminates SQL metacharacters"),
        },
        "CWE-78": {  # Command Injection Sanitizers
            "shlex.quote": SanitizerDefinition("shlex.quote", "CWE-78", "python", "POSIX shell quotation escaping metacharacters"),
            "pipes.quote": SanitizerDefinition("pipes.quote", "CWE-78", "python", "Legacy shell parameter escaping"),
        },
        "CWE-22": {  # Path Traversal Sanitizers
            "os.path.basename": SanitizerDefinition("os.path.basename", "CWE-22", "python", "Strips directory separators and path traversal components"),
            "pathlib.Path.name": SanitizerDefinition("pathlib.Path.name", "CWE-22", "python", "Extracts basename component from Path object"),
            "secure_filename": SanitizerDefinition("secure_filename", "CWE-22", "python", "Werkzeug secure filename sanitizer"),
        },
        "CWE-79": {  # XSS Sanitizers
            "html.escape": SanitizerDefinition("html.escape", "CWE-79", "python", "Standard HTML entity escaping (&, <, >, \", ')"),
            "markupsafe.escape": SanitizerDefinition("markupsafe.escape", "CWE-79", "python", "MarkupSafe context-aware HTML escaping"),
            "django.utils.html.escape": SanitizerDefinition("django.utils.html.escape", "CWE-79", "python", "Django framework HTML entity escaping"),
        },
        "CWE-502": {  # Deserialization Sanitizers
            "json.loads": SanitizerDefinition("json.loads", "CWE-502", "python", "Standard non-executable JSON parser"),
            "json.load": SanitizerDefinition("json.load", "CWE-502", "python", "Stream-based JSON deserialization"),
            "yaml.safe_load": SanitizerDefinition("yaml.safe_load", "CWE-502", "python", "Safe PyYAML loader avoiding arbitrary object instantiation"),
            "ast.literal_eval": SanitizerDefinition("ast.literal_eval", "CWE-502", "python", "Evaluates string strictly as Python literal data structure"),
        },
        "CWE-327": {  # Cryptographic Sanitizers
            "hashlib.sha256": SanitizerDefinition("hashlib.sha256", "CWE-327", "python", "NIST-approved SHA-256 secure hash"),
            "hashlib.sha512": SanitizerDefinition("hashlib.sha512", "CWE-327", "python", "NIST-approved SHA-512 secure hash"),
            "argon2.PasswordHasher": SanitizerDefinition("argon2.PasswordHasher", "CWE-327", "python", "Argon2id password hashing algorithm"),
            "bcrypt.hashpw": SanitizerDefinition("bcrypt.hashpw", "CWE-327", "python", "Bcrypt key derivation function"),
        },
    }

    # JavaScript Verified Sanitizers mapped by CWE
    JS_SANITIZERS: Dict[str, Dict[str, SanitizerDefinition]] = {
        "CWE-79": {
            "DOMPurify.sanitize": SanitizerDefinition("DOMPurify.sanitize", "CWE-79", "javascript", "DOMPurify XSS HTML sanitizer"),
            "encodeURIComponent": SanitizerDefinition("encodeURIComponent", "CWE-79", "javascript", "URL parameter encoding"),
            "validator.escape": SanitizerDefinition("validator.escape", "CWE-79", "javascript", "HTML entity escaping library"),
        },
        "CWE-22": {
            "path.basename": SanitizerDefinition("path.basename", "CWE-22", "javascript", "Node.js path basename stripper"),
        },
        "CWE-502": {
            "JSON.parse": SanitizerDefinition("JSON.parse", "CWE-502", "javascript", "Standard JSON safe parser"),
        },
    }

    @classmethod
    def is_sanitizer(cls, func_call_name: str, cwe: str, language: str = "python") -> bool:
        """
        Determines whether a function call is a verified sanitizer for the specified CWE.
        Strict verification: does NOT accept unverified functions.
        """
        clean_name = func_call_name.strip()
        table = cls.PYTHON_SANITIZERS if language.lower() == "python" else cls.JS_SANITIZERS
        cwe_sanitizers = table.get(cwe, {})

        if clean_name in cwe_sanitizers:
            return True

        # Check suffixes (e.g. "sanitizer = html.escape" or module qualifier)
        for key in cwe_sanitizers.keys():
            if clean_name.endswith(f".{key}") or clean_name == key:
                return True

        return False

    @classmethod
    def is_parameterized_query(cls, sql_text: str) -> bool:
        """
        Verifies whether an SQL string relies strictly on prepared statement placeholders
        (? or %s or :name or $1) without dynamic string concatenation.
        """
        has_placeholders = bool(re.search(r"(\?|%s|:[a-zA-Z_][a-zA-Z0-9_]*|\$[1-9]\d*)", sql_text))
        has_concat = bool(re.search(r"(\+|f[\"']|\.format|\% )", sql_text))
        return has_placeholders and not has_concat

    @classmethod
    def is_safe_path_containment(cls, code_snippet: str) -> bool:
        """
        Checks whether code enforces path containment:
        e.g., target = os.path.abspath(...); target.startswith(BASE_DIR)
        """
        c = code_snippet.lower()
        has_abspath = "os.path.abspath" in c or "path.resolve" in c or "pathlib" in c
        has_containment = "startswith" in c or "startswith(base" in c or "startswith(safe" in c
        has_basename = "basename" in c or "secure_filename" in c
        return (has_abspath and has_containment) or has_basename

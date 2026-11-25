"""
Sink Registry for SecureCode AI.
Catalog of security-sensitive execution sinks across Python and JavaScript.
Maps each sink to MITRE CWE, OWASP Top 10 category, default severity, and remediation guidance.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class SinkDefinition:
    identifier: str
    function_or_attr: str
    category: str
    cwe: str
    owasp: str
    default_severity: str
    language: str
    description: str
    arg_indices_checked: List[int] = field(default_factory=lambda: [0])
    requires_dynamic_check: bool = True  # True if dynamic/untrusted string triggers the flaw
    remediation_template: str = ""
    remediation_explanation: str = ""


class SinkRegistry:
    """Central registry of dangerous sinks for static AST and dataflow taint analysis."""

    PYTHON_SINKS: Dict[str, SinkDefinition] = {
        # SQL Injection (CWE-89)
        "execute": SinkDefinition(
            identifier="py_sql_execute",
            function_or_attr="execute",
            category="SQL_INJECTION",
            cwe="CWE-89",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="python",
            description="Database cursor or connection query execution sink with potential dynamic SQL.",
            arg_indices_checked=[0],
            remediation_template="cursor.execute('SELECT * FROM table WHERE col = %s', (param,))",
            remediation_explanation="Pass query parameters in the secondary argument tuple rather than concatenating into the query string.",
        ),
        "executemany": SinkDefinition(
            identifier="py_sql_executemany",
            function_or_attr="executemany",
            category="SQL_INJECTION",
            cwe="CWE-89",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="python",
            description="Database batch query execution sink.",
            arg_indices_checked=[0],
            remediation_template="cursor.executemany('INSERT INTO table VALUES (%s)', params_list)",
            remediation_explanation="Use prepared parameter tuples for batch insertions.",
        ),
        "raw": SinkDefinition(
            identifier="py_django_raw",
            function_or_attr="raw",
            category="SQL_INJECTION",
            cwe="CWE-89",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="python",
            description="Django ORM raw SQL query method.",
            arg_indices_checked=[0],
            remediation_template="Model.objects.raw('SELECT * FROM app_model WHERE id = %s', [param])",
            remediation_explanation="Supply query arguments through the translations list argument.",
        ),

        # Command Injection (CWE-78)
        "os.system": SinkDefinition(
            identifier="py_os_system",
            function_or_attr="os.system",
            category="COMMAND_INJECTION",
            cwe="CWE-78",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="python",
            description="Direct execution of system shell command via os.system.",
            arg_indices_checked=[0],
            remediation_template="subprocess.run(['command', arg], shell=False, check=True)",
            remediation_explanation="Invoke commands without a shell using subprocess.run with argument vectors.",
        ),
        "os.popen": SinkDefinition(
            identifier="py_os_popen",
            function_or_attr="os.popen",
            category="COMMAND_INJECTION",
            cwe="CWE-78",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="python",
            description="Piped shell command invocation via os.popen.",
            arg_indices_checked=[0],
            remediation_template="subprocess.Popen(['command', arg], stdout=subprocess.PIPE, shell=False)",
            remediation_explanation="Use subprocess.Popen with shell=False and strict array arguments.",
        ),
        "subprocess.run": SinkDefinition(
            identifier="py_subprocess_run",
            function_or_attr="subprocess.run",
            category="COMMAND_INJECTION",
            cwe="CWE-78",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="python",
            description="Subprocess invocation with potential shell=True parameter.",
            arg_indices_checked=[0],
            remediation_template="subprocess.run(['executable', safe_arg], shell=False, check=True)",
            remediation_explanation="Ensure shell=False and pass arguments as a structured list.",
        ),
        "subprocess.Popen": SinkDefinition(
            identifier="py_subprocess_popen",
            function_or_attr="subprocess.Popen",
            category="COMMAND_INJECTION",
            cwe="CWE-78",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="python",
            description="Subprocess process creation with potential shell=True parameter.",
            arg_indices_checked=[0],
            remediation_template="subprocess.Popen(['executable', safe_arg], shell=False)",
            remediation_explanation="Avoid shell=True and pass command arguments in a list.",
        ),

        # Path Traversal (CWE-22)
        "open": SinkDefinition(
            identifier="py_file_open",
            function_or_attr="open",
            category="PATH_TRAVERSAL",
            cwe="CWE-22",
            owasp="A01:2021-Broken Access Control",
            default_severity="HIGH",
            language="python",
            description="Built-in file open sink vulnerable to path traversal if path contains '../'.",
            arg_indices_checked=[0],
            remediation_template="safe_path = os.path.abspath(os.path.join(BASE_DIR, os.path.basename(user_path)))\nif not safe_path.startswith(BASE_DIR): raise ValueError('Access Denied')",
            remediation_explanation="Sanitize filename with os.path.basename and verify canonical root containment.",
        ),
        "send_file": SinkDefinition(
            identifier="py_send_file",
            function_or_attr="send_file",
            category="PATH_TRAVERSAL",
            cwe="CWE-22",
            owasp="A01:2021-Broken Access Control",
            default_severity="HIGH",
            language="python",
            description="Flask send_file utility serving file paths to clients.",
            arg_indices_checked=[0],
            remediation_template="send_from_directory(SAFE_UPLOAD_DIR, secure_filename(filename))",
            remediation_explanation="Use send_from_directory with secure_filename to prevent parent directory climbing.",
        ),

        # Insecure Deserialization (CWE-502)
        "pickle.loads": SinkDefinition(
            identifier="py_pickle_loads",
            function_or_attr="pickle.loads",
            category="UNSAFE_DESERIALIZATION",
            cwe="CWE-502",
            owasp="A08:2021-Software and Data Integrity Failures",
            default_severity="CRITICAL",
            language="python",
            description="Arbitrary Python object deserialization via pickle.loads.",
            arg_indices_checked=[0],
            remediation_template="import json\ndata = json.loads(payload)",
            remediation_explanation="Use structured safe serialization formats like JSON instead of pickle.",
        ),
        "pickle.load": SinkDefinition(
            identifier="py_pickle_load",
            function_or_attr="pickle.load",
            category="UNSAFE_DESERIALIZATION",
            cwe="CWE-502",
            owasp="A08:2021-Software and Data Integrity Failures",
            default_severity="CRITICAL",
            language="python",
            description="Arbitrary Python object deserialization from file stream.",
            arg_indices_checked=[0],
            remediation_template="import json\ndata = json.load(stream)",
            remediation_explanation="Deserialize data with json.load or schema-validated data structures.",
        ),
        "yaml.load": SinkDefinition(
            identifier="py_yaml_load",
            function_or_attr="yaml.load",
            category="UNSAFE_DESERIALIZATION",
            cwe="CWE-502",
            owasp="A08:2021-Software and Data Integrity Failures",
            default_severity="CRITICAL",
            language="python",
            description="PyYAML unsafe deserialization loader.",
            arg_indices_checked=[0],
            remediation_template="data = yaml.safe_load(yaml_string)",
            remediation_explanation="Always use yaml.safe_load or specify Loader=yaml.SafeLoader.",
        ),

        # Dynamic Code Evaluation (CWE-95)
        "eval": SinkDefinition(
            identifier="py_eval",
            function_or_attr="eval",
            category="DYNAMIC_EVALUATION",
            cwe="CWE-95",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="python",
            description="Dynamic Python code evaluation with arbitrary code execution capability.",
            arg_indices_checked=[0],
            remediation_template="import ast\ndata = ast.literal_eval(payload)",
            remediation_explanation="Replace eval with ast.literal_eval for safe literal data structures.",
        ),
        "exec": SinkDefinition(
            identifier="py_exec",
            function_or_attr="exec",
            category="DYNAMIC_EVALUATION",
            cwe="CWE-95",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="python",
            description="Dynamic Python statement execution.",
            arg_indices_checked=[0],
            remediation_template="# Avoid dynamic code execution; use predefined dispatch dictionaries",
            remediation_explanation="Refactor logic to invoke specific registered callable handlers rather than executing raw strings.",
        ),

        # Insecure Cryptography (CWE-327)
        "hashlib.md5": SinkDefinition(
            identifier="py_crypto_md5",
            function_or_attr="hashlib.md5",
            category="INSECURE_CRYPTOGRAPHY",
            cwe="CWE-327",
            owasp="A02:2021-Cryptographic Failures",
            default_severity="MEDIUM",
            language="python",
            description="Use of collision-vulnerable MD5 digest algorithm.",
            arg_indices_checked=[],
            requires_dynamic_check=False,
            remediation_template="hashlib.sha256(data.encode('utf-8')).hexdigest()",
            remediation_explanation="Upgrade hashing to SHA-256 / SHA-3 for integrity or Argon2id/bcrypt for passwords.",
        ),
        "hashlib.sha1": SinkDefinition(
            identifier="py_crypto_sha1",
            function_or_attr="hashlib.sha1",
            category="INSECURE_CRYPTOGRAPHY",
            cwe="CWE-327",
            owasp="A02:2021-Cryptographic Failures",
            default_severity="MEDIUM",
            language="python",
            description="Use of broken SHA-1 digest algorithm.",
            arg_indices_checked=[],
            requires_dynamic_check=False,
            remediation_template="hashlib.sha256(data.encode('utf-8')).hexdigest()",
            remediation_explanation="Upgrade to SHA-256 or stronger digest mechanisms.",
        ),

        # Insecure Temporary File (CWE-377)
        "tempfile.mktemp": SinkDefinition(
            identifier="py_tempfile_mktemp",
            function_or_attr="tempfile.mktemp",
            category="INSECURE_TEMP_FILE",
            cwe="CWE-377",
            owasp="A01:2021-Broken Access Control",
            default_severity="MEDIUM",
            language="python",
            description="Race-condition vulnerable mktemp creates filenames prone to symlink attacks.",
            arg_indices_checked=[],
            requires_dynamic_check=False,
            remediation_template="with tempfile.NamedTemporaryFile(delete=True) as tf: tf.write(data)",
            remediation_explanation="Use tempfile.NamedTemporaryFile or mkstemp which atomically creates files with safe permissions.",
        ),

        # Server-Side Request Forgery / SSRF (CWE-918)
        "requests.get": SinkDefinition(
            identifier="py_requests_get",
            function_or_attr="requests.get",
            category="SSRF",
            cwe="CWE-918",
            owasp="A10:2021-Server-Side Request Forgery",
            default_severity="HIGH",
            language="python",
            description="Outbound HTTP GET request vulnerable to SSRF if target URL is user-controlled.",
            arg_indices_checked=[0],
            remediation_template="if target_domain not in ALLOWED_DOMAINS: raise ValueError('Invalid destination')",
            remediation_explanation="Validate scheme (https only), resolve hostname, and reject private/loopback IP address ranges.",
        ),
        "urllib.request.urlopen": SinkDefinition(
            identifier="py_urlopen",
            function_or_attr="urllib.request.urlopen",
            category="SSRF",
            cwe="CWE-918",
            owasp="A10:2021-Server-Side Request Forgery",
            default_severity="HIGH",
            language="python",
            description="Outbound URL opening via standard urllib library.",
            arg_indices_checked=[0],
            remediation_template="validate_outbound_url(target_url)",
            remediation_explanation="Enforce domain allowlisting and prevent loopback IP requests.",
        ),
    }

    JS_SINKS: Dict[str, SinkDefinition] = {
        # Cross-Site Scripting (CWE-79)
        "innerHTML": SinkDefinition(
            identifier="js_dom_innerhtml",
            function_or_attr="innerHTML",
            category="CROSS_SITE_SCRIPTING",
            cwe="CWE-79",
            owasp="A03:2021-Injection",
            default_severity="HIGH",
            language="javascript",
            description="Unsafe DOM write via innerHTML enables client script execution.",
            remediation_template="element.textContent = safeText; // or DOMPurify.sanitize(markup)",
            remediation_explanation="Use textContent for non-HTML strings, or pass through DOMPurify before setting innerHTML.",
        ),
        "document.write": SinkDefinition(
            identifier="js_dom_docwrite",
            function_or_attr="document.write",
            category="CROSS_SITE_SCRIPTING",
            cwe="CWE-79",
            owasp="A03:2021-Injection",
            default_severity="HIGH",
            language="javascript",
            description="Direct document write stream injection.",
            remediation_template="document.getElementById('target').textContent = text",
            remediation_explanation="Do not use document.write; use standard DOM element text manipulation.",
        ),

        # Command Injection (CWE-78)
        "child_process.exec": SinkDefinition(
            identifier="js_child_exec",
            function_or_attr="child_process.exec",
            category="COMMAND_INJECTION",
            cwe="CWE-78",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="javascript",
            description="Node.js shell command invocation.",
            remediation_template="child_process.execFile(executable, [arg1, arg2], { shell: false })",
            remediation_explanation="Use child_process.execFile with parameter arrays to bypass shell metacharacter parsing.",
        ),
        "execSync": SinkDefinition(
            identifier="js_child_execsync",
            function_or_attr="execSync",
            category="COMMAND_INJECTION",
            cwe="CWE-78",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="javascript",
            description="Synchronous shell execution.",
            remediation_template="execFileSync(binary, [arg], { shell: false })",
            remediation_explanation="Switch to execFileSync with array parameters.",
        ),

        # Dynamic Code Evaluation (CWE-95)
        "eval": SinkDefinition(
            identifier="js_eval",
            function_or_attr="eval",
            category="DYNAMIC_EVALUATION",
            cwe="CWE-95",
            owasp="A03:2021-Injection",
            default_severity="CRITICAL",
            language="javascript",
            description="JavaScript eval() evaluates string as arbitrary code.",
            remediation_template="JSON.parse(dataString)",
            remediation_explanation="Parse serialized objects with JSON.parse instead of eval.",
        ),

        # Prototype Pollution (CWE-1321)
        "__proto__": SinkDefinition(
            identifier="js_proto_pollution",
            function_or_attr="__proto__",
            category="PROTOTYPE_POLLUTION",
            cwe="CWE-1321",
            owasp="A03:2021-Injection",
            default_severity="HIGH",
            language="javascript",
            description="Modification of Object.prototype via __proto__ property assignment.",
            remediation_template="const safeObj = Object.create(null); // or validate key !== '__proto__'",
            remediation_explanation="Create objects with null prototype or reject __proto__, constructor, and prototype keys during recursive merging.",
        ),
    }

    @classmethod
    def get_python_sink(cls, name_or_attr: str) -> Optional[SinkDefinition]:
        """Looks up a Python sink by function name or attribute path."""
        if name_or_attr in cls.PYTHON_SINKS:
            return cls.PYTHON_SINKS[name_or_attr]
        # Match trailing method name (e.g. cursor.execute -> execute)
        parts = name_or_attr.split(".")
        method = parts[-1]
        if method in cls.PYTHON_SINKS:
            return cls.PYTHON_SINKS[method]
        return None

    @classmethod
    def get_js_sink(cls, name_or_attr: str) -> Optional[SinkDefinition]:
        """Looks up a JavaScript sink by function or property name."""
        if name_or_attr in cls.JS_SINKS:
            return cls.JS_SINKS[name_or_attr]
        parts = name_or_attr.split(".")
        prop = parts[-1]
        if prop in cls.JS_SINKS:
            return cls.JS_SINKS[prop]
        return None

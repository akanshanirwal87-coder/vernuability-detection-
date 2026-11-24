import ast
import re
import uuid
from typing import List, Dict, Any, Tuple

class PythonAstScanner:
    def __init__(self, source_code: str, file_name: str = "main.py"):
        self.source_code = source_code
        self.file_name = file_name
        self.lines = source_code.splitlines()
        self.findings: List[Dict[str, Any]] = []
        self.imports: List[str] = []
        self.functions_count = 0
        self.total_nodes = 0
        self.sinks_identified = 0
        self.variable_assignments: Dict[str, Dict[str, Any]] = {}

    def scan(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        try:
            tree = ast.parse(self.source_code)
        except SyntaxError as e:
            return [{
                "id": f"err-{uuid.uuid4().hex[:6]}",
                "title": "Syntax Error in Source Code",
                "category": "SYNTAX_ERROR",
                "severity": "LOW",
                "cwe": "CWE-1007",
                "owaspCategory": "Code Quality",
                "file": self.file_name,
                "startLine": e.lineno or 1,
                "endLine": e.lineno or 1,
                "confidence": 1.0,
                "description": f"Source code contains a syntax error: {e.msg}",
                "evidence": e.text.strip() if e.text else "",
                "impact": "Code cannot be parsed into an AST for security analysis.",
                "vulnerableCode": e.text.strip() if e.text else "",
                "remediationCode": "# Correct the syntax error",
                "remediationExplanation": "Fix syntax errors to allow AST compilation.",
                "bestPractices": ["Validate code syntax before automated static security scanning."],
                "references": ["https://docs.python.org/3/library/ast.html"],
                "remediationStatus": "OPEN",
                "validationStatus": "NOT_VALIDATED"
            }], {
                "nodesCount": 0,
                "functionsFound": 0,
                "importsFound": [],
                "sinksIdentified": 0
            }

        # First pass: collect metadata, imports, and variable assignments
        for node in ast.walk(tree):
            self.total_nodes += 1
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    self.imports.append(alias.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions_count += 1
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.variable_assignments[target.id] = {
                            "node": node.value,
                            "line": node.lineno
                        }

        # Second pass: check for security vulnerabilities
        self._check_sql_injection(tree)
        self._check_command_injection(tree)
        self._check_hardcoded_secrets(tree)
        self._check_path_traversal(tree)
        self._check_insecure_crypto(tree)
        self._check_unsafe_deserialization(tree)
        self._check_ssrf(tree)
        self._check_insecure_config(tree)
        self._check_insecure_temp_file(tree)
        self._check_xxe(tree)

        ast_summary = {
            "nodesCount": self.total_nodes,
            "functionsFound": self.functions_count,
            "importsFound": list(set(self.imports)),
            "sinksIdentified": self.sinks_identified
        }

        return self.findings, ast_summary

    def _get_line_code(self, start: int, end: int) -> str:
        s = max(0, start - 1)
        e = min(len(self.lines), end)
        return "\n".join(self.lines[s:e])

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        """Check if an expression uses string concatenation, formatting, or f-strings."""
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Mod)):
                return True
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        return False

    def _check_sql_injection(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id

                if func_name in ("execute", "executemany", "raw_sql", "raw"):
                    self.sinks_identified += 1
                    if node.args:
                        arg0 = node.args[0]
                        is_vuln = False
                        evidence = ""
                        data_flow = []

                        # Case 1: Direct dynamic string inside execute()
                        if self._is_dynamic_string(arg0):
                            is_vuln = True
                            evidence = self._get_line_code(node.lineno, node.lineno)
                        # Case 2: Variable passed to execute() was defined dynamically
                        elif isinstance(arg0, ast.Name) and arg0.id in self.variable_assignments:
                            assigned_info = self.variable_assignments[arg0.id]
                            if self._is_dynamic_string(assigned_info["node"]):
                                is_vuln = True
                                evidence = f"{self._get_line_code(assigned_info['line'], assigned_info['line'])}\n{self._get_line_code(node.lineno, node.lineno)}"
                                data_flow = [
                                    {
                                        "step": 1,
                                        "label": "Source: Variable Concatenation",
                                        "codeSnippet": self._get_line_code(assigned_info["line"], assigned_info["line"]),
                                        "line": assigned_info["line"],
                                        "type": "TRANSFORM",
                                        "description": f"Variable `{arg0.id}` constructed with unescaped dynamic string concatenation."
                                    },
                                    {
                                        "step": 2,
                                        "label": "Sink: Database Query Execution",
                                        "codeSnippet": self._get_line_code(node.lineno, node.lineno),
                                        "line": node.lineno,
                                        "type": "SINK",
                                        "description": f"Dynamic query string passed to `{func_name}()` without parameterized bindings."
                                    }
                                ]

                        if is_vuln:
                            start_l = node.lineno
                            end_l = node.end_lineno or node.lineno
                            if data_flow:
                                start_l = min(data_flow[0]["line"], start_l)
                            
                            self.findings.append({
                                "id": f"fnd-sqli-{uuid.uuid4().hex[:6]}",
                                "title": "SQL Injection via Dynamic String Query",
                                "category": "SQL_INJECTION",
                                "severity": "CRITICAL",
                                "cwe": "CWE-89",
                                "owaspCategory": "A03:2021-Injection",
                                "file": self.file_name,
                                "startLine": start_l,
                                "endLine": end_l,
                                "confidence": 0.95,
                                "description": "Dynamic string construction detected in SQL execution context. Untrusted input alters database syntax.",
                                "evidence": evidence,
                                "impact": "Allows attackers to bypass authentication, read or destroy database contents, and execute unauthorized commands.",
                                "dataFlow": data_flow if data_flow else None,
                                "vulnerableCode": evidence,
                                "remediationCode": "cursor.execute(\"SELECT * FROM table WHERE col = ?\", (param,))",
                                "remediationExplanation": "Replace dynamic string concatenation with parameterized prepared statements.",
                                "bestPractices": [
                                    "Use parameterized queries with placeholders (? or %s).",
                                    "Use ORM query builders (SQLAlchemy/Django ORM).",
                                    "Validate input types before executing queries."
                                ],
                                "references": [
                                    "https://cwe.mitre.org/data/definitions/89.html",
                                    "https://owasp.org/Top10/A03_2021-Injection/"
                                ],
                                "remediationStatus": "OPEN",
                                "validationStatus": "NOT_VALIDATED"
                            })

    def _check_command_injection(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                is_cmd_sink = False
                func_repr = ""
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("system", "popen"):
                        is_cmd_sink = True
                        func_repr = f"os.{node.func.attr}"
                    elif node.func.attr in ("run", "Popen", "call", "check_output"):
                        # Check if shell=True is passed
                        for kw in node.keywords:
                            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                is_cmd_sink = True
                                func_repr = f"subprocess.{node.func.attr}(shell=True)"
                elif isinstance(node.func, ast.Name) and node.func.id in ("system", "popen"):
                    is_cmd_sink = True
                    func_repr = node.func.id

                if is_cmd_sink and node.args:
                    self.sinks_identified += 1
                    arg0 = node.args[0]
                    is_vuln = False
                    evidence = ""
                    data_flow = []

                    if self._is_dynamic_string(arg0):
                        is_vuln = True
                        evidence = self._get_line_code(node.lineno, node.lineno)
                    elif isinstance(arg0, ast.Name) and arg0.id in self.variable_assignments:
                        assign_info = self.variable_assignments[arg0.id]
                        if self._is_dynamic_string(assign_info["node"]):
                            is_vuln = True
                            evidence = f"{self._get_line_code(assign_info['line'], assign_info['line'])}\n{self._get_line_code(node.lineno, node.lineno)}"
                            data_flow = [
                                {
                                    "step": 1,
                                    "label": "Source: Unsanitized Command Construction",
                                    "codeSnippet": self._get_line_code(assign_info["line"], assign_info["line"]),
                                    "line": assign_info["line"],
                                    "type": "TRANSFORM",
                                    "description": f"Command string `{arg0.id}` assembled using dynamic concatenation."
                                },
                                {
                                    "step": 2,
                                    "label": "Sink: Shell Command Execution",
                                    "codeSnippet": self._get_line_code(node.lineno, node.lineno),
                                    "line": node.lineno,
                                    "type": "SINK",
                                    "description": f"Command dispatched to `{func_repr}` with shell execution enabled."
                                }
                            ]

                    if is_vuln:
                        self.findings.append({
                            "id": f"fnd-cmd-{uuid.uuid4().hex[:6]}",
                            "title": "Command Injection via System Shell Execution",
                            "category": "COMMAND_INJECTION",
                            "severity": "CRITICAL",
                            "cwe": "CWE-78",
                            "owaspCategory": "A03:2021-Injection",
                            "file": self.file_name,
                            "startLine": node.lineno,
                            "endLine": node.end_lineno or node.lineno,
                            "confidence": 0.98,
                            "description": f"Dynamic input passed to shell interpreter via `{func_repr}` allowing arbitrary command execution.",
                            "evidence": evidence,
                            "impact": "Remote code execution with application process privileges, leading to server takeover.",
                            "dataFlow": data_flow if data_flow else None,
                            "vulnerableCode": evidence,
                            "remediationCode": 'subprocess.run(["command", arg], shell=False, check=True)',
                            "remediationExplanation": "Use subprocess.run() with shell=False and pass arguments as an explicit array of strings.",
                            "bestPractices": [
                                "Never execute commands through a system shell with user inputs.",
                                "Pass commands as lists without shell=True.",
                                "Validate and restrict arguments using strict allowlists."
                            ],
                            "references": [
                                "https://cwe.mitre.org/data/definitions/78.html",
                                "https://owasp.org/Top10/A03_2021-Injection/"
                            ],
                            "remediationStatus": "OPEN",
                            "validationStatus": "NOT_VALIDATED"
                        })

    def _check_hardcoded_secrets(self, tree: ast.AST):
        secret_patterns = re.compile(r'(?i)(api[_-]?key|secret|password|passwd|token|auth[_-]?token|stripe|private[_-]?key)')
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and secret_patterns.search(target.id):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            # If secret string length is >= 10 and not obviously a placeholder
                            if len(val) >= 8 and not val.startswith("your_") and not val.startswith("dummy_"):
                                self.sinks_identified += 1
                                evidence = self._get_line_code(node.lineno, node.lineno)
                                self.findings.append({
                                    "id": f"fnd-cred-{uuid.uuid4().hex[:6]}",
                                    "title": "Hardcoded Sensitive Credential / Secret",
                                    "category": "HARDCODED_CREDENTIALS",
                                    "severity": "HIGH",
                                    "cwe": "CWE-798",
                                    "owaspCategory": "A07:2021-Identification and Authentication Failures",
                                    "file": self.file_name,
                                    "startLine": node.lineno,
                                    "endLine": node.end_lineno or node.lineno,
                                    "confidence": 0.94,
                                    "description": f"Variable `{target.id}` contains hardcoded secret token directly in source code.",
                                    "evidence": evidence,
                                    "impact": "Credentials committed to repositories can be extracted by attackers to access private APIs and databases.",
                                    "vulnerableCode": evidence,
                                    "remediationCode": f'{target.id} = os.getenv("{target.id.upper()}")',
                                    "remediationExplanation": "Extract secrets into environment variables or use a secret management service.",
                                    "bestPractices": [
                                        "Use environment variables (os.getenv) for all secret configuration.",
                                        "Store production credentials in secrets vaults.",
                                        "Add .env and credential files to .gitignore."
                                    ],
                                    "references": ["https://cwe.mitre.org/data/definitions/798.html"],
                                    "remediationStatus": "OPEN",
                                    "validationStatus": "NOT_VALIDATED"
                                })

    def _check_path_traversal(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "open":
                    if node.args:
                        arg0 = node.args[0]
                        is_vuln = False
                        if self._is_dynamic_string(arg0):
                            is_vuln = True
                        elif isinstance(arg0, ast.Name) and arg0.id in self.variable_assignments:
                            if self._is_dynamic_string(self.variable_assignments[arg0.id]["node"]):
                                is_vuln = True

                        if is_vuln:
                            self.sinks_identified += 1
                            evidence = self._get_line_code(node.lineno, node.lineno)
                            self.findings.append({
                                "id": f"fnd-path-{uuid.uuid4().hex[:6]}",
                                "title": "Path Traversal in File Access",
                                "category": "PATH_TRAVERSAL",
                                "severity": "HIGH",
                                "cwe": "CWE-22",
                                "owaspCategory": "A01:2021-Broken Access Control",
                                "file": self.file_name,
                                "startLine": node.lineno,
                                "endLine": node.end_lineno or node.lineno,
                                "confidence": 0.91,
                                "description": "File path constructed dynamically without validation, allowing directory traversal with '../'.",
                                "evidence": evidence,
                                "impact": "Allows attackers to read or overwrite arbitrary sensitive files outside the intended root folder.",
                                "vulnerableCode": evidence,
                                "remediationCode": "safe_path = os.path.abspath(os.path.join(BASE_DIR, os.path.basename(user_input)))",
                                "remediationExplanation": "Sanitize filenames using os.path.basename and enforce prefix containment with os.path.abspath.",
                                "bestPractices": [
                                    "Extract only basename to strip traversal characters.",
                                    "Verify the resolved path starts with the allowed root directory.",
                                    "Avoid direct filesystem access using user-provided paths."
                                ],
                                "references": ["https://cwe.mitre.org/data/definitions/22.html"],
                                "remediationStatus": "OPEN",
                                "validationStatus": "NOT_VALIDATED"
                            })

    def _check_insecure_crypto(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in ("md5", "sha1"):
                    evidence = self._get_line_code(node.lineno, node.lineno)
                    self.findings.append({
                        "id": f"fnd-crypto-{uuid.uuid4().hex[:6]}",
                        "title": f"Insecure Cryptographic Hash ({node.func.attr.upper()})",
                        "category": "INSECURE_CRYPTOGRAPHY",
                        "severity": "MEDIUM",
                        "cwe": "CWE-327",
                        "owaspCategory": "A02:2021-Cryptographic Failures",
                        "file": self.file_name,
                        "startLine": node.lineno,
                        "endLine": node.end_lineno or node.lineno,
                        "confidence": 0.92,
                        "description": f"Use of cryptographically weak hash algorithm `{node.func.attr}`. Vulnerable to collision attacks.",
                        "evidence": evidence,
                        "impact": "Attackers can compute collisions to forge tokens, digital signatures, or certificates.",
                        "vulnerableCode": evidence,
                        "remediationCode": "hashlib.sha256(data).hexdigest()",
                        "remediationExplanation": "Upgrade to SHA-256 or SHA-3 for general hashing, or Argon2/bcrypt for passwords.",
                        "bestPractices": [
                            "Use SHA-256 or SHA-512 instead of MD5 or SHA-1.",
                            "Use password hashing algorithms like Argon2id or bcrypt."
                        ],
                        "references": ["https://cwe.mitre.org/data/definitions/327.html"],
                        "remediationStatus": "OPEN",
                        "validationStatus": "NOT_VALIDATED"
                    })

    def _check_unsafe_deserialization(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in ("loads", "load"):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                        evidence = self._get_line_code(node.lineno, node.lineno)
                        self.findings.append({
                            "id": f"fnd-deser-{uuid.uuid4().hex[:6]}",
                            "title": "Unsafe Deserialization via pickle.loads",
                            "category": "UNSAFE_DESERIALIZATION",
                            "severity": "CRITICAL",
                            "cwe": "CWE-502",
                            "owaspCategory": "A08:2021-Software and Data Integrity Failures",
                            "file": self.file_name,
                            "startLine": node.lineno,
                            "endLine": node.end_lineno or node.lineno,
                            "confidence": 0.97,
                            "description": "Deserializing untrusted data with Python's pickle module allows arbitrary code execution via __reduce__.",
                            "evidence": evidence,
                            "impact": "Complete remote code execution upon deserializing crafted payload.",
                            "vulnerableCode": evidence,
                            "remediationCode": "json.loads(data)",
                            "remediationExplanation": "Use safe data serialization formats like JSON, MessagePack, or Protocol Buffers.",
                            "bestPractices": [
                                "Never deserialize untrusted input with pickle.",
                                "Use JSON or cryptographic HMAC signatures if binary serialization is required."
                            ],
                            "references": ["https://cwe.mitre.org/data/definitions/502.html"],
                            "remediationStatus": "OPEN",
                            "validationStatus": "NOT_VALIDATED"
                        })

    def _check_ssrf(self, tree: ast.AST):
        """Detect Server-Side Request Forgery (CWE-918) via unvalidated HTTP client calls."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                is_http_sink = False
                sink_label = ""
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("get", "post", "put", "delete", "request") and isinstance(node.func.value, ast.Name) and node.func.value.id in ("requests", "session", "client", "http"):
                        is_http_sink = True
                        sink_label = f"{node.func.value.id}.{node.func.attr}"
                    elif node.func.attr == "urlopen" and isinstance(node.func.value, (ast.Name, ast.Attribute)):
                        is_http_sink = True
                        sink_label = "urllib.request.urlopen"

                if is_http_sink and node.args:
                    self.sinks_identified += 1
                    arg0 = node.args[0]
                    is_vuln = False
                    data_flow = []

                    if self._is_dynamic_string(arg0):
                        is_vuln = True
                    elif isinstance(arg0, ast.Name) and arg0.id in self.variable_assignments:
                        assign_info = self.variable_assignments[arg0.id]
                        if self._is_dynamic_string(assign_info["node"]) or any(kw in arg0.id.lower() for kw in ("url", "target", "host", "endpoint", "path")):
                            is_vuln = True
                            data_flow = [
                                {
                                    "step": 1,
                                    "label": "Source: Untrusted URL / Destination",
                                    "codeSnippet": self._get_line_code(assign_info["line"], assign_info["line"]),
                                    "line": assign_info["line"],
                                    "type": "SOURCE",
                                    "description": f"Target address `{arg0.id}` derived from dynamic parameters."
                                },
                                {
                                    "step": 2,
                                    "label": "Sink: Outbound HTTP Request",
                                    "codeSnippet": self._get_line_code(node.lineno, node.lineno),
                                    "line": node.lineno,
                                    "type": "SINK",
                                    "description": f"Outbound network request dispatched by `{sink_label}` without IP allowlist validation."
                                }
                            ]

                    if is_vuln:
                        evidence = self._get_line_code(node.lineno, node.lineno)
                        self.findings.append({
                            "id": f"fnd-ssrf-{uuid.uuid4().hex[:6]}",
                            "title": "Server-Side Request Forgery (SSRF) via Dynamic HTTP Call",
                            "category": "COMMAND_INJECTION",
                            "severity": "HIGH",
                            "cwe": "CWE-918",
                            "owaspCategory": "A10:2021-Server-Side Request Forgery (SSRF)",
                            "file": self.file_name,
                            "startLine": node.lineno,
                            "endLine": node.end_lineno or node.lineno,
                            "confidence": 0.93,
                            "description": f"Untrusted network request initiated to an external destination via `{sink_label}` without allowlisting.",
                            "evidence": evidence,
                            "impact": "Attackers can probe internal metadata endpoints (e.g. 169.254.169.254), scan internal ports, and pivot into the internal network.",
                            "dataFlow": data_flow if data_flow else None,
                            "vulnerableCode": evidence,
                            "remediationCode": "import ipaddress, urllib.parse\n# Parse and validate against strict allowed domains and reject private/loopback IP ranges\nparsed = urllib.parse.urlparse(target_url)\nif parsed.netloc not in ALLOWED_DOMAINS:\n    raise ValueError('Disallowed destination')",
                            "remediationExplanation": "Enforce strict allowlists of allowed domains/schemes and block access to RFC-1918 private subnets and cloud metadata endpoints (169.254.169.254).",
                            "bestPractices": [
                                "Validate and restrict destination URLs against an allowlist.",
                                "Disable HTTP redirects in client libraries.",
                                "Segment network egress and block internal loopback/metadata IP addresses."
                            ],
                            "references": [
                                "https://cwe.mitre.org/data/definitions/918.html",
                                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
                            ],
                            "remediationStatus": "OPEN",
                            "validationStatus": "NOT_VALIDATED"
                        })

    def _check_insecure_config(self, tree: ast.AST):
        """Detect Insecure Debug Mode & Permissive CORS (CWE-489 / CWE-942)."""
        for node in ast.walk(tree):
            # Check app.run(debug=True)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                    for kw in node.keywords:
                        if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            evidence = self._get_line_code(node.lineno, node.lineno)
                            self.findings.append({
                                "id": f"fnd-debug-{uuid.uuid4().hex[:6]}",
                                "title": "Framework Debug Mode Enabled in Production Context",
                                "category": "HARDCODED_CREDENTIALS",
                                "severity": "HIGH",
                                "cwe": "CWE-489",
                                "owaspCategory": "A05:2021-Security Misconfiguration",
                                "file": self.file_name,
                                "startLine": node.lineno,
                                "endLine": node.end_lineno or node.lineno,
                                "confidence": 0.98,
                                "description": "Application server initiated with debug=True, which enables interactive interactive console debuggers and stack trace exposure.",
                                "evidence": evidence,
                                "impact": "Interactive debuggers (like Werkzeug pin/console) allow adversaries to execute arbitrary Python commands on the server.",
                                "vulnerableCode": evidence,
                                "remediationCode": "app.run(debug=False)",
                                "remediationExplanation": "Disable debug mode in production environments and configure structured logging.",
                                "bestPractices": [
                                    "Ensure debug=False in production deployments.",
                                    "Read debug configuration from environment variables with a safe false default."
                                ],
                                "references": ["https://cwe.mitre.org/data/definitions/489.html"],
                                "remediationStatus": "OPEN",
                                "validationStatus": "NOT_VALIDATED"
                            })

    def _check_insecure_temp_file(self, tree: ast.AST):
        """Detect Insecure Temporary File Creation (CWE-377)."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "mktemp":
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "tempfile":
                        evidence = self._get_line_code(node.lineno, node.lineno)
                        self.findings.append({
                            "id": f"fnd-temp-{uuid.uuid4().hex[:6]}",
                            "title": "Insecure Temporary File Generation via tempfile.mktemp",
                            "category": "PATH_TRAVERSAL",
                            "severity": "MEDIUM",
                            "cwe": "CWE-377",
                            "owaspCategory": "A01:2021-Broken Access Control",
                            "file": self.file_name,
                            "startLine": node.lineno,
                            "endLine": node.end_lineno or node.lineno,
                            "confidence": 0.96,
                            "description": "tempfile.mktemp() is deprecated and vulnerable to symlink race condition (TOCTOU) attacks.",
                            "evidence": evidence,
                            "impact": "Attackers can predict or race file creation to hijack file handles or overwrite arbitrary system files.",
                            "vulnerableCode": evidence,
                            "remediationCode": "with tempfile.NamedTemporaryFile(delete=False) as temp_file:\n    temp_path = temp_file.name",
                            "remediationExplanation": "Use tempfile.NamedTemporaryFile() which safely creates the file with atomic 0600 permissions.",
                            "bestPractices": [
                                "Use tempfile.NamedTemporaryFile or mkstemp() for safe atomic creation.",
                                "Avoid deprecated mktemp() in all security-sensitive contexts."
                            ],
                            "references": ["https://cwe.mitre.org/data/definitions/377.html"],
                            "remediationStatus": "OPEN",
                            "validationStatus": "NOT_VALIDATED"
                        })

    def _check_xxe(self, tree: ast.AST):
        """Detect XML External Entity (XXE) Injection (CWE-611)."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in ("fromstring", "parse"):
                    mod_repr = ""
                    if isinstance(node.func.value, ast.Attribute):
                        mod_repr = node.func.value.attr
                    elif isinstance(node.func.value, ast.Name):
                        mod_repr = node.func.value.id

                    if mod_repr in ("ElementTree", "etree", "minidom"):
                        evidence = self._get_line_code(node.lineno, node.lineno)
                        self.findings.append({
                            "id": f"fnd-xxe-{uuid.uuid4().hex[:6]}",
                            "title": "XML External Entity (XXE) Injection Risk",
                            "category": "COMMAND_INJECTION",
                            "severity": "HIGH",
                            "cwe": "CWE-611",
                            "owaspCategory": "A05:2021-Security Misconfiguration",
                            "file": self.file_name,
                            "startLine": node.lineno,
                            "endLine": node.end_lineno or node.lineno,
                            "confidence": 0.90,
                            "description": f"Parsing XML via standard `{mod_repr}.{node.func.attr}` without disabling DTD / external entities exposes the application to XXE.",
                            "evidence": evidence,
                            "impact": "Enables arbitrary local file read (e.g., /etc/passwd), server-side request forgery, and denial of service (Billion Laughs attack).",
                            "vulnerableCode": evidence,
                            "remediationCode": "import defusedxml.ElementTree as ET\nroot = ET.fromstring(xml_data)",
                            "remediationExplanation": "Replace standard xml.etree with defusedxml, which automatically disallows DTD entities and external entity expansion.",
                            "bestPractices": [
                                "Use defusedxml for parsing untrusted XML data.",
                                "Disable DTD processing and external entity resolution in XML parsers."
                            ],
                            "references": ["https://cwe.mitre.org/data/definitions/611.html"],
                            "remediationStatus": "OPEN",
                            "validationStatus": "NOT_VALIDATED"
                        })

    def get_ast_tree(self) -> Dict[str, Any]:
        """Produce a hierarchical AST node graph for frontend visualization and analysis."""
        try:
            tree = ast.parse(self.source_code)
        except SyntaxError:
            return {"name": "SyntaxError", "type": "Error", "role": "SINK", "description": "Failed to compile AST"}

        def node_to_dict(node: ast.AST, depth: int = 0) -> Dict[str, Any]:
            node_type = type(node).__name__
            lineno = getattr(node, "lineno", None)
            col_offset = getattr(node, "col_offset", None)
            
            # Determine security classification
            role = "SAFE"
            description = f"Standard AST node ({node_type})"

            # Sinks
            if isinstance(node, ast.Call):
                func_str = ""
                if isinstance(node.func, ast.Attribute):
                    func_str = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_str = node.func.id
                
                if func_str in ("execute", "executemany", "system", "popen", "run", "loads", "mktemp", "fromstring", "md5", "sha1"):
                    role = "SINK"
                    description = f"Potential sensitive execution sink `{func_str}()`"
                else:
                    description = f"Function invocation `{func_str}()`"
            # Transforms
            elif isinstance(node, (ast.BinOp, ast.JoinedStr)):
                role = "TRANSFORM"
                description = "Dynamic string concatenation or interpolation"
            # Sources
            elif isinstance(node, ast.Name) and any(src in node.id.lower() for src in ("user", "input", "param", "req", "query", "payload")):
                role = "SOURCE"
                description = f"Potential untrusted source variable `{node.id}`"

            label = node_type
            if isinstance(node, ast.FunctionDef):
                label = f"Function: {node.name}"
            elif isinstance(node, ast.ClassDef):
                label = f"Class: {node.name}"
            elif isinstance(node, ast.Name):
                label = f"Var: {node.id}"
            elif isinstance(node, ast.Constant):
                val_repr = repr(node.value)
                if len(val_repr) > 25:
                    val_repr = val_repr[:22] + "..."
                label = f"Const: {val_repr}"
            elif isinstance(node, ast.Call):
                func_name = getattr(node.func, 'attr', getattr(node.func, 'id', 'call'))
                label = f"Call: {func_name}()"
            elif isinstance(node, ast.Attribute):
                label = f"Attr: .{node.attr}"
            elif isinstance(node, ast.Assign):
                label = "Assign (=)"

            children = []
            if depth < 6:
                for field, value in ast.iter_fields(node):
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, ast.AST):
                                children.append(node_to_dict(item, depth + 1))
                    elif isinstance(value, ast.AST):
                        children.append(node_to_dict(value, depth + 1))

            result = {
                "name": label,
                "type": node_type,
                "role": role,
                "description": description,
                "lineno": lineno,
                "colOffset": col_offset
            }
            if children:
                result["children"] = children
            return result

        return node_to_dict(tree)


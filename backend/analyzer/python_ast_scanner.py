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


import re
import uuid
from typing import List, Dict, Any, Tuple

class JavaScriptScanner:
    def __init__(self, source_code: str, file_name: str = "script.js"):
        self.source_code = source_code
        self.file_name = file_name
        self.lines = source_code.splitlines()
        self.findings: List[Dict[str, Any]] = []

    def scan(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        sinks_count = 0
        nodes_count = len(self.lines) * 4 # heuristic estimate

        for idx, line in enumerate(self.lines):
            line_no = idx + 1
            line_trimmed = line.strip()

            # 1. Cross-Site Scripting (XSS) via innerHTML or dangerouslySetInnerHTML
            if re.search(r'\b(innerHTML|outerHTML)\s*=', line_trimmed) or 'dangerouslySetInnerHTML' in line_trimmed:
                # Suppress if sanitized via DOMPurify or textContent
                if 'DOMPurify.sanitize' not in line_trimmed and 'encodeURIComponent' not in line_trimmed:
                    if '+' in line_trimmed or '${' in line_trimmed or 'params' in line_trimmed or 'query' in line_trimmed or 'userInput' in line_trimmed:
                        sinks_count += 1
                        self.findings.append({
                            "id": f"fnd-xss-{uuid.uuid4().hex[:6]}",
                            "title": "Cross-Site Scripting (XSS) via Unsanitized DOM Write",
                            "category": "CROSS_SITE_SCRIPTING",
                            "severity": "HIGH",
                            "cwe": "CWE-79",
                            "owaspCategory": "A03:2021-Injection",
                            "file": self.file_name,
                            "startLine": line_no,
                            "endLine": line_no,
                            "confidence": 0.94,
                            "description": "Untrusted dynamic string rendered directly to DOM via innerHTML without HTML entity encoding.",
                            "evidence": line_trimmed,
                            "impact": "Enables session hijacking, keystroke logging, credential harvesting, and arbitrary client script execution.",
                            "dataFlow": [
                                {
                                    "step": 1,
                                    "label": "Source: Client Parameter",
                                    "codeSnippet": "urlParams.get('q')",
                                    "line": max(1, line_no - 3),
                                    "type": "SOURCE",
                                    "description": "Unsanitized user query received from window.location."
                                },
                                {
                                    "step": 2,
                                    "label": "Sink: DOM HTML Injection",
                                    "codeSnippet": line_trimmed,
                                    "line": line_no,
                                    "type": "SINK",
                                    "description": "Direct assignment to innerHTML bypasses DOM sanitization."
                                }
                            ],
                            "vulnerableCode": line_trimmed,
                            "remediationCode": "element.textContent = safeText; // or DOMPurify.sanitize(userInput)",
                            "remediationExplanation": "Use textContent for plain text, or sanitize using DOMPurify before rendering HTML markup.",
                            "bestPractices": [
                                "Prefer element.textContent or element.innerText instead of innerHTML.",
                                "Use a trusted sanitizer library such as DOMPurify.",
                                "Adopt modern frontend frameworks with built-in output encoding (React/Vue)."
                            ],
                            "references": ["https://cwe.mitre.org/data/definitions/79.html"],
                            "remediationStatus": "OPEN",
                            "validationStatus": "NOT_VALIDATED"
                        })

            # 2a. Dynamic Code Execution (eval, Function)
            if re.search(r'\b(eval|Function)\s*\(', line_trimmed):
                sinks_count += 1
                self.findings.append({
                    "id": f"fnd-evaljs-{uuid.uuid4().hex[:6]}",
                    "title": "Unsafe Dynamic Code Evaluation via eval()",
                    "category": "COMMAND_INJECTION",
                    "severity": "CRITICAL",
                    "cwe": "CWE-95",
                    "owaspCategory": "A03:2021-Injection",
                    "file": self.file_name,
                    "startLine": line_no,
                    "endLine": line_no,
                    "confidence": 0.97,
                    "description": "Direct invocation of eval() with dynamic argument allows arbitrary script execution.",
                    "evidence": line_trimmed,
                    "impact": "Arbitrary code execution within client browser or host Node.js process.",
                    "vulnerableCode": line_trimmed,
                    "remediationCode": "JSON.parse(dataString)",
                    "remediationExplanation": "Use JSON.parse() instead of eval() to deserialize structured data.",
                    "bestPractices": [
                        "Never pass user-controlled strings to eval().",
                        "Use JSON.parse for serialization parsing."
                    ],
                    "references": ["https://cwe.mitre.org/data/definitions/95.html"],
                    "remediationStatus": "OPEN",
                    "validationStatus": "NOT_VALIDATED"
                })

            # 2b. OS Command Execution (child_process.exec, execSync)
            if re.search(r'\b(child_process\.exec|execSync)\s*\(', line_trimmed):
                sinks_count += 1
                self.findings.append({
                    "id": f"fnd-cmdjs-{uuid.uuid4().hex[:6]}",
                    "title": "Command Injection via Shell Execution (child_process.exec)",
                    "category": "COMMAND_INJECTION",
                    "severity": "CRITICAL",
                    "cwe": "CWE-78",
                    "owaspCategory": "A03:2021-Injection",
                    "file": self.file_name,
                    "startLine": line_no,
                    "endLine": line_no,
                    "confidence": 0.96,
                    "description": "Invocation of shell interpreter with dynamic command string in Node.js environment.",
                    "evidence": line_trimmed,
                    "impact": "Arbitrary operating system command execution on server host.",
                    "vulnerableCode": line_trimmed,
                    "remediationCode": "child_process.execFile(binaryPath, argsArray, { shell: false })",
                    "remediationExplanation": "Use child_process.execFile() with structured argument arrays to avoid shell spawning.",
                    "bestPractices": [
                        "Use child_process.execFile with parameter arrays.",
                        "Avoid spawning shell interpreters with unsanitized arguments."
                    ],
                    "references": ["https://cwe.mitre.org/data/definitions/78.html"],
                    "remediationStatus": "OPEN",
                    "validationStatus": "NOT_VALIDATED"
                })

            # 3. Hardcoded Secrets
            secret_match = re.search(r'(?i)(jwt_secret|api_key|token|auth_token|stripe_key)\s*[:=]\s*["\']([^"\']{10,})["\']', line_trimmed)
            if secret_match:
                sinks_count += 1
                raw_secret = secret_match.group(2)
                masked_line = line_trimmed.replace(raw_secret, raw_secret[:4] + "***REDACTED***")
                self.findings.append({
                    "id": f"fnd-secretjs-{uuid.uuid4().hex[:6]}",
                    "title": "Hardcoded Secret / Token in JavaScript Code",
                    "category": "HARDCODED_CREDENTIALS",
                    "severity": "HIGH",
                    "cwe": "CWE-798",
                    "owaspCategory": "A07:2021-Identification and Authentication Failures",
                    "file": self.file_name,
                    "startLine": line_no,
                    "endLine": line_no,
                    "confidence": 0.93,
                    "description": "Sensitive credentials embedded in JavaScript source, accessible to users or public repositories.",
                    "evidence": masked_line,
                    "impact": "Exposure of cryptographic signing secrets or third-party API credentials.",
                    "vulnerableCode": masked_line,
                    "remediationCode": "process.env.JWT_SECRET",
                    "remediationExplanation": "Reference secrets through server-side environment variables.",
                    "bestPractices": [
                        "Do not bundle private keys or production secrets in frontend bundles.",
                        "Use environment variables on Node.js backends."
                    ],
                    "references": ["https://cwe.mitre.org/data/definitions/798.html"],
                    "remediationStatus": "OPEN",
                    "validationStatus": "NOT_VALIDATED"
                })

            # 4. Prototype Pollution (CWE-1321)
            if re.search(r'(\b__proto__\b|\[\s*["\']__proto__["\']\s*\]|\[\s*["\']constructor["\']\s*\]|\[\s*["\']prototype["\']\s*\])', line_trimmed):
                sinks_count += 1
                self.findings.append({
                    "id": f"fnd-proto-{uuid.uuid4().hex[:6]}",
                    "title": "Prototype Pollution via Object Property Assignment",
                    "category": "COMMAND_INJECTION",
                    "severity": "CRITICAL",
                    "cwe": "CWE-1321",
                    "owaspCategory": "A03:2021-Injection",
                    "file": self.file_name,
                    "startLine": line_no,
                    "endLine": line_no,
                    "confidence": 0.95,
                    "description": "Direct modification of Object.prototype via __proto__ or constructor.prototype alters global application behavior.",
                    "evidence": line_trimmed,
                    "impact": "Can cause denial of service, bypass authentication checks, or lead to remote code execution in Node.js applications.",
                    "vulnerableCode": line_trimmed,
                    "remediationCode": "const safeObj = Object.create(null); // or validate key !== '__proto__' && key !== 'constructor'",
                    "remediationExplanation": "Use Object.create(null) for dictionary objects with no prototype, or validate and freeze prototypes.",
                    "bestPractices": [
                        "Use Object.freeze(Object.prototype) to prevent mutation.",
                        "Block assignment to properties named '__proto__', 'constructor', and 'prototype'."
                    ],
                    "references": ["https://cwe.mitre.org/data/definitions/1321.html"],
                    "remediationStatus": "OPEN",
                    "validationStatus": "NOT_VALIDATED"
                })

            # 5. Node.js Path Traversal in File Operations (CWE-22)
            if re.search(r'\bfs\.(readFile|readFileSync|createReadStream|writeFile|unlink)\s*\(', line_trimmed):
                if '+' in line_trimmed or '${' in line_trimmed or 'req.' in line_trimmed or 'params' in line_trimmed or 'query' in line_trimmed:
                    sinks_count += 1
                    self.findings.append({
                        "id": f"fnd-pathjs-{uuid.uuid4().hex[:6]}",
                        "title": "Path Traversal in Node.js File System Call",
                        "category": "PATH_TRAVERSAL",
                        "severity": "HIGH",
                        "cwe": "CWE-22",
                        "owaspCategory": "A01:2021-Broken Access Control",
                        "file": self.file_name,
                        "startLine": line_no,
                        "endLine": line_no,
                        "confidence": 0.92,
                        "description": "File system access invoked with user-controlled input without path normalization or boundary containment.",
                        "evidence": line_trimmed,
                        "impact": "Enables attackers to traverse directories and read or overwrite arbitrary sensitive system files.",
                        "vulnerableCode": line_trimmed,
                        "remediationCode": "const safePath = path.resolve(BASE_DIR, path.basename(userPath));\nif (!safePath.startsWith(BASE_DIR)) throw new Error('Access denied');",
                        "remediationExplanation": "Enforce strict root path validation using path.resolve and path.basename.",
                        "bestPractices": [
                            "Use path.basename to strip directory traversal sequences.",
                            "Verify resolved path starts with allowed base directory."
                        ],
                        "references": ["https://cwe.mitre.org/data/definitions/22.html"],
                        "remediationStatus": "OPEN",
                        "validationStatus": "NOT_VALIDATED"
                    })

            # 6. Catastrophic Regex Backtracking / ReDoS (CWE-1333)
            if re.search(r'/(?:\([^\)]*\+[\)]*\+)|(?:\([^\)]*\*[\)]*\*)/', line_trimmed):
                sinks_count += 1
                self.findings.append({
                    "id": f"fnd-redos-{uuid.uuid4().hex[:6]}",
                    "title": "Regular Expression Denial of Service (ReDoS) Risk",
                    "category": "COMMAND_INJECTION",
                    "severity": "MEDIUM",
                    "cwe": "CWE-1333",
                    "owaspCategory": "A05:2021-Security Misconfiguration",
                    "file": self.file_name,
                    "startLine": line_no,
                    "endLine": line_no,
                    "confidence": 0.89,
                    "description": "Nested quantifier detected in regular expression (e.g. (a+)+), triggering exponential backtracking on crafted input.",
                    "evidence": line_trimmed,
                    "impact": "Exhausts CPU resources, locking the Node.js event loop and rendering the service unresponsive.",
                    "vulnerableCode": line_trimmed,
                    "remediationCode": "const safeRegex = /^[a-zA-Z0-9_-]+$/; // simplify without nested quantifiers",
                    "remediationExplanation": "Refactor regular expressions to avoid overlapping and nested quantifiers, or use non-backtracking regex engines.",
                    "bestPractices": [
                        "Avoid nested repetitions like (a+)+ or (x*)*.",
                        "Use RE2 or timeout-bounded regex validators."
                    ],
                    "references": ["https://cwe.mitre.org/data/definitions/1333.html"],
                    "remediationStatus": "OPEN",
                    "validationStatus": "NOT_VALIDATED"
                })

        ast_summary = {
            "nodesCount": nodes_count,
            "functionsFound": max(1, len(re.findall(r'\bfunction\b|\=\>|\bclass\b', self.source_code))),
            "importsFound": list(set(re.findall(r'(?:import.*?from\s+[\'"](.*?)[\'"]|require\([\'"](.*?)[\'"]\))', self.source_code))),
            "sinksIdentified": sinks_count
        }

        return self.findings, ast_summary

    def get_ast_tree(self) -> Dict[str, Any]:
        """Produce a hierarchical AST-like node structure from JavaScript code."""
        children = []
        for idx, line in enumerate(self.lines):
            line_trimmed = line.strip()
            if not line_trimmed:
                continue
            line_no = idx + 1
            role = "SAFE"
            desc = "Statement"

            if any(k in line_trimmed for k in ("eval(", "child_process", "exec(", "innerHTML", "__proto__", "fs.read")):
                role = "SINK"
                desc = "Critical execution sink or DOM write"
            elif any(k in line_trimmed for k in ("+", "${", "concat", "params", "query")):
                role = "TRANSFORM"
                desc = "Dynamic string concatenation or property transform"
            elif any(k in line_trimmed for k in ("req.body", "req.query", "urlParams", "userInput", "target")):
                role = "SOURCE"
                desc = "Untrusted input source"

            node_name = "Statement"
            if line_trimmed.startswith("function ") or "=>" in line_trimmed:
                node_name = f"Function: {line_trimmed[:30]}"
            elif line_trimmed.startswith("import ") or line_trimmed.startswith("const {"):
                node_name = f"Import: {line_trimmed[:30]}"
            elif line_trimmed.startswith("const ") or line_trimmed.startswith("let ") or line_trimmed.startswith("var "):
                node_name = f"Decl: {line_trimmed[:30]}"
            else:
                node_name = line_trimmed[:35]

            children.append({
                "name": node_name,
                "type": "JSStatement",
                "role": role,
                "description": desc,
                "lineno": line_no,
                "colOffset": 0
            })

        return {
            "name": f"Program ({self.file_name})",
            "type": "Program",
            "role": "SAFE",
            "description": "Top-level JavaScript/TypeScript module",
            "lineno": 1,
            "colOffset": 0,
            "children": children[:30] # Limit to top 30 statements for clear display
        }


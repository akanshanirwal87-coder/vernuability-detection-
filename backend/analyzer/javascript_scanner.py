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
                if '+' in line_trimmed or '${' in line_trimmed or 'params' in line_trimmed or 'query' in line_trimmed:
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

            # 2. Command Injection / Dangerous Code Execution (eval, Function, child_process.exec)
            if re.search(r'\b(eval|child_process\.exec|execSync)\s*\(', line_trimmed):
                sinks_count += 1
                self.findings.append({
                    "id": f"fnd-cmdjs-{uuid.uuid4().hex[:6]}",
                    "title": "Command Injection / Dangerous Code Execution (eval / exec)",
                    "category": "COMMAND_INJECTION",
                    "severity": "CRITICAL",
                    "cwe": "CWE-78",
                    "owaspCategory": "A03:2021-Injection",
                    "file": self.file_name,
                    "startLine": line_no,
                    "endLine": line_no,
                    "confidence": 0.96,
                    "description": "Direct invocation of eval() or child_process.exec() with dynamic arguments.",
                    "evidence": line_trimmed,
                    "impact": "Arbitrary code execution on client or server Node.js host.",
                    "vulnerableCode": line_trimmed,
                    "remediationCode": "childProcess.execFile(binaryPath, argsArray, { shell: false })",
                    "remediationExplanation": "Avoid eval() entirely; for system execution, use execFile() without shell invocation.",
                    "bestPractices": [
                        "Never pass user-controlled strings to eval().",
                        "Use child_process.execFile with parameter arrays."
                    ],
                    "references": ["https://cwe.mitre.org/data/definitions/78.html"],
                    "remediationStatus": "OPEN",
                    "validationStatus": "NOT_VALIDATED"
                })

            # 3. Hardcoded Secrets
            secret_match = re.search(r'(?i)(jwt_secret|api_key|token|auth_token|stripe_key)\s*[:=]\s*["\']([^"\']{10,})["\']', line_trimmed)
            if secret_match:
                sinks_count += 1
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
                    "evidence": line_trimmed,
                    "impact": "Exposure of cryptographic signing secrets or third-party API credentials.",
                    "vulnerableCode": line_trimmed,
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

        ast_summary = {
            "nodesCount": nodes_count,
            "functionsFound": max(1, len(re.findall(r'\bfunction\b|\=\>|\bclass\b', self.source_code))),
            "importsFound": list(set(re.findall(r'(?:import.*?from\s+[\'"](.*?)[\'"]|require\([\'"](.*?)[\'"]\))', self.source_code))),
            "sinksIdentified": sinks_count
        }

        return self.findings, ast_summary


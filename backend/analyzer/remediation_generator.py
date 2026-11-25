"""
Remediation Generator for SecureCode AI.
Synthesizes secure, context-aware code replacements for common vulnerability classes:
- SQL Injection (parameterized bindings)
- Command Injection (argument arrays without shell)
- XSS (textContent / DOMPurify)
- Path Traversal (basename & canonical containment)
- Hardcoded Credentials (environment variable lookup)
- Unsafe Deserialization (JSON safe parser)
- Dynamic Evaluation (literal_eval)
"""

from typing import Dict, Any, Optional
import re
from .cwe_mapper import CWEMapper


class RemediationGenerator:
    """Generates idiomatic, secure replacement code snippets for detected vulnerabilities."""

    @classmethod
    def generate_remediation(
        cls,
        cwe: str,
        vulnerable_code: str,
        language: str = "python",
        variable_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Produces a secure code recommendation, explanation, and guidance.
        """
        norm_cwe = CWEMapper.normalize_cwe(cwe)
        lang = language.lower()
        cleaned_code = vulnerable_code.strip()

        # 1. SQL Injection (CWE-89)
        if norm_cwe == "CWE-89":
            if lang == "python":
                code = "cursor.execute('SELECT * FROM users WHERE id = %s', (clean_id,))"
            else:
                code = "db.query('SELECT * FROM users WHERE id = $1', [cleanId]);"
            return {
                "cwe": "CWE-89",
                "title": "Use Parameterized Prepared Statements",
                "suggestedCode": code,
                "explanation": "Replace dynamic string concatenation with parameterized prepared statements. The database driver handles character escaping automatically.",
                "bestPractices": [
                    "Never construct SQL statements using string concatenation or f-strings.",
                    "Use parameterized placeholders (? or %s) and supply parameters in secondary arguments.",
                    "Adopt an Object-Relational Mapper (ORM) with parameterized query builders.",
                ],
            }

        # 2. Command Injection (CWE-78)
        if norm_cwe == "CWE-78":
            if lang == "python":
                code = "subprocess.run(['ping', '-c', '1', safe_arg], shell=False, check=True)"
            else:
                code = "child_process.execFile('ping', ['-c', '1', safeArg], { shell: false });"
            return {
                "cwe": "CWE-78",
                "title": "Execute Commands without a Shell",
                "suggestedCode": code,
                "explanation": "Avoid shell invocation by setting shell=False and passing arguments as discrete array elements.",
                "bestPractices": [
                    "Never invoke system shells with unsanitized arguments.",
                    "Use subprocess.run with shell=False and list arguments.",
                    "Prefer standard library APIs over operating system CLI utilities.",
                ],
            }

        # 3. Path Traversal (CWE-22)
        if norm_cwe == "CWE-22":
            if lang == "python":
                code = (
                    "safe_name = os.path.basename(user_path)\n"
                    "target_path = os.path.abspath(os.path.join(BASE_DIR, safe_name))\n"
                    "if not target_path.startswith(BASE_DIR):\n"
                    "    raise ValueError('Path traversal attempt detected')\n"
                    "with open(target_path, 'r') as f:\n"
                    "    content = f.read()"
                )
            else:
                code = (
                    "const safeName = path.basename(userPath);\n"
                    "const targetPath = path.resolve(BASE_DIR, safeName);\n"
                    "if (!targetPath.startsWith(BASE_DIR)) {\n"
                    "    throw new Error('Access Denied');\n"
                    "}\n"
                    "const content = fs.readFileSync(targetPath, 'utf8');"
                )
            return {
                "cwe": "CWE-22",
                "title": "Enforce Basename and Canonical Directory Containment",
                "suggestedCode": code,
                "explanation": "Strip directory separators with basename and verify that canonical resolved path begins with the designated base directory.",
                "bestPractices": [
                    "Sanitize all file paths with os.path.basename.",
                    "Enforce canonical containment using os.path.abspath and startswith().",
                ],
            }

        # 4. Cross-Site Scripting (CWE-79)
        if norm_cwe == "CWE-79":
            if lang == "python":
                code = "import html\nsafe_output = html.escape(user_input)"
            else:
                code = "element.textContent = userInput; // or DOMPurify.sanitize(markup)"
            return {
                "cwe": "CWE-79",
                "title": "Encode HTML Entities or Use textContent",
                "suggestedCode": code,
                "explanation": "Do not render untrusted strings to innerHTML. Use textContent for plain text or DOMPurify.sanitize() for rich markup.",
                "bestPractices": [
                    "Prefer element.textContent over innerHTML.",
                    "Sanitize untrusted HTML with DOMPurify.",
                    "Use modern frameworks with automatic template encoding (React/Vue).",
                ],
            }

        # 5. Hardcoded Credentials (CWE-798)
        if norm_cwe == "CWE-798":
            var = variable_name or "API_KEY"
            if lang == "python":
                code = f"{var} = os.getenv('{var.upper()}')"
            else:
                code = f"const {var} = process.env.{var.upper()};"
            return {
                "cwe": "CWE-798",
                "title": "Extract Secrets to Environment Variables",
                "suggestedCode": code,
                "explanation": "Retrieve credentials from environment variables or a secure key management system at runtime.",
                "bestPractices": [
                    "Never commit credentials, API tokens, or keys to source control.",
                    "Load configurations via environment variables (.env).",
                    "Add sensitive configuration files to .gitignore.",
                ],
            }

        # 6. Unsafe Deserialization (CWE-502)
        if norm_cwe == "CWE-502":
            if lang == "python":
                code = "import json\ndata = json.loads(payload)"
            else:
                code = "const data = JSON.parse(payload);"
            return {
                "cwe": "CWE-502",
                "title": "Use Safe JSON Deserialization",
                "suggestedCode": code,
                "explanation": "Avoid arbitrary object deserializers like pickle. Use standard structured serialization formats like JSON.",
                "bestPractices": [
                    "Never deserialize untrusted payloads with pickle or yaml.load.",
                    "Use json.loads() or yaml.safe_load().",
                ],
            }

        # 7. Dynamic Code Evaluation (CWE-95)
        if norm_cwe == "CWE-95":
            code = "import ast\nsafe_result = ast.literal_eval(payload)"
            return {
                "cwe": "CWE-95",
                "title": "Replace eval() with ast.literal_eval()",
                "suggestedCode": code,
                "explanation": "Use ast.literal_eval() to safely parse strings into Python literal data structures without executing code.",
                "bestPractices": [
                    "Never execute arbitrary strings with eval() or exec().",
                    "Use ast.literal_eval() for safe evaluation of literal data structures.",
                ],
            }

        # Generic fallback
        return {
            "cwe": norm_cwe,
            "title": f"Secure Remediation for {norm_cwe}",
            "suggestedCode": "# Implement input validation and safe API parameters",
            "explanation": "Apply defensive coding patterns: validate inputs, enforce bounds, and use safe APIs.",
            "bestPractices": ["Enforce input validation", "Follow principle of least privilege"],
        }

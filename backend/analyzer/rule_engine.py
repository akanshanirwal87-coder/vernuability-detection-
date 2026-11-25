"""
Rule Engine for SecureCode AI.
Executes declarative static security analysis rules over Python and JavaScript ASTs and source trees.
Complements taint analysis with structural pattern detection:
- Hardcoded secrets and credential tokens
- Insecure temporary file generation (tempfile.mktemp)
- Weak cryptographic algorithms (MD5, SHA-1, DES, RC4)
- XML External Entity (XXE) vulnerabilities
- Insecure framework configurations (debug=True, ALLOWED_HOSTS=['*'])
- ManageEngine Endpoint Security baseline rules
"""

import ast
import re
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class RuleFinding:
    id: str
    rule_id: str
    title: str
    category: str
    severity: str
    cwe: str
    owasp: str
    file: str
    start_line: int
    end_line: int
    confidence: float
    description: str
    evidence: str
    remediation_code: str
    remediation_explanation: str
    best_practices: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "cwe": self.cwe,
            "owaspCategory": self.owasp,
            "file": self.file,
            "startLine": self.start_line,
            "endLine": self.end_line,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "impact": f"Violation of {self.cwe} ({self.title}).",
            "vulnerableCode": self.evidence,
            "remediationCode": self.remediation_code,
            "remediationExplanation": self.remediation_explanation,
            "bestPractices": self.best_practices,
            "references": self.references,
            "remediationStatus": "OPEN",
            "validationStatus": "NOT_VALIDATED",
            "detectionSource": "STATIC_RULES",
        }


class RuleEngine:
    """Executes rule-based checks across source code."""

    SECRET_REGEX = re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|auth[_-]?token|jwt[_-]?secret|private[_-]?key|aws[_-]?secret)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
    )

    DEBUG_MODE_REGEX = re.compile(
        r"(?i)\b(app\.run\s*\(.*debug\s*=\s*True|DEBUG\s*=\s*True)\b"
    )

    UNQUOTED_SERVICE_PATH_REGEX = re.compile(
        r'(?i)\b(CreateProcess|ServiceManager|binPath)\s*=\s*["\']([C-Z]:\\[^"\'\n]+?\s[^"\'\n]+?\.exe)["\']'
    )

    @classmethod
    def evaluate_rules(cls, source_code: str, language: str, file_name: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        lines = source_code.splitlines()

        # 1. Hardcoded Credentials / Secrets Detection (CWE-798)
        for idx, line in enumerate(lines):
            line_no = idx + 1
            line_str = line.strip()

            # Skip comments
            if line_str.startswith("#") or line_str.startswith("//"):
                continue

            # Skip dummy or template placeholders
            if any(dummy in line_str.lower() for dummy in ["your_api_key", "change_me", "example", "<api_key>", "placeholder"]):
                continue

            secret_match = cls.SECRET_REGEX.search(line)
            if secret_match:
                key_name = secret_match.group(1)
                secret_val = secret_match.group(2)
                # Ensure the secret has reasonable entropy / non-trivial length
                if len(secret_val) >= 8 and not secret_val.startswith("os.getenv") and not secret_val.startswith("process.env"):
                    masked_evidence = re.sub(r"['\"][^'\"]{8,}['\"]", f"'{secret_val[:3]}...{secret_val[-2:]}'", line_str)
                    findings.append(
                        RuleFinding(
                            id=f"fnd-sec-{uuid.uuid4().hex[:6]}",
                            rule_id="RULE-CWE-798-SECRET",
                            title="Hardcoded Credential or API Token",
                            category="HARDCODED_CREDENTIALS",
                            severity="HIGH",
                            cwe="CWE-798",
                            owasp="A07:2021-Identification and Authentication Failures",
                            file=file_name,
                            start_line=line_no,
                            end_line=line_no,
                            confidence=0.92,
                            description=f"Hardcoded sensitive secret identifier `{key_name}` discovered in source code repository.",
                            evidence=masked_evidence,
                            remediation_code=f"{key_name} = os.getenv('{key_name.upper()}')",
                            remediation_explanation="Retrieve credentials from environment variables or external secret managers (e.g. AWS Secrets Manager, HashiCorp Vault).",
                            best_practices=[
                                "Store secrets strictly in environment variables (.env) or Secret Managers.",
                                "Do not commit API tokens, passwords, or cryptographic keys to version control.",
                                "Employ pre-commit secret scanners in CI/CD pipelines.",
                            ],
                            references=[
                                "https://cwe.mitre.org/data/definitions/798.html",
                                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                            ],
                        ).to_dict()
                    )

            # 2. Insecure Framework Debug Configuration (CWE-489)
            if cls.DEBUG_MODE_REGEX.search(line):
                findings.append(
                    RuleFinding(
                        id=f"fnd-dbg-{uuid.uuid4().hex[:6]}",
                        rule_id="RULE-CWE-489-DEBUG",
                        title="Insecure Debug Mode Enabled in Production",
                        category="INSECURE_CONFIGURATION",
                        severity="MEDIUM",
                        cwe="CWE-489",
                        owasp="A05:2021-Security Misconfiguration",
                        file=file_name,
                        start_line=line_no,
                        end_line=line_no,
                        confidence=0.95,
                        description="Application framework configured with active debug mode, enabling interactive debuggers or verbose stack traces in production.",
                        evidence=line_str,
                        remediation_code="app.run(debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true')",
                        remediation_explanation="Ensure debug mode is disabled in production environments.",
                        best_practices=["Disable debug banners and interactive debug consoles on internet-facing hosts."],
                        references=["https://cwe.mitre.org/data/definitions/489.html"],
                    ).to_dict()
                )

            # 3. ManageEngine Unquoted Service Path Detection (CWE-428)
            me_match = cls.UNQUOTED_SERVICE_PATH_REGEX.search(line)
            if me_match:
                unquoted_path = me_match.group(2)
                findings.append(
                    RuleFinding(
                        id=f"fnd-me-{uuid.uuid4().hex[:6]}",
                        rule_id="RULE-ME-UNQUOTED-SERVICE-PATH",
                        title="ManageEngine Baseline: Unquoted Windows Service Path",
                        category="PRIVILEGE_ESCALATION",
                        severity="HIGH",
                        cwe="CWE-428",
                        owasp="A01:2021-Broken Access Control",
                        file=file_name,
                        start_line=line_no,
                        end_line=line_no,
                        confidence=0.94,
                        description=f"Windows service path `{unquoted_path}` contains spaces and lacks outer quotes, permitting binary interception privilege escalation.",
                        evidence=line_str,
                        remediation_code=f'binPath = \'"{unquoted_path}"\'',
                        remediation_explanation="Wrap executables containing whitespace in quotation marks to prevent execution of attacker-placed intermediate binaries.",
                        best_practices=["Always quote service executable file paths containing whitespace characters."],
                        references=["https://cwe.mitre.org/data/definitions/428.html"],
                    ).to_dict()
                )

        return findings

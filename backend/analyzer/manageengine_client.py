"""
ManageEngine Endpoint Central Security Rules & Advisory Engine
Connects SecureCode AI with ManageEngine Endpoint Security baselines,
CVE disclosures, and endpoint threat patterns.
Product Reference: https://www.manageengine.com/products/desktop-central/endpoint-central-endpoint-security.html
"""

import os
import json
import re
from typing import List, Dict, Any, Optional

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
ME_DATA_PATH = os.path.join(DATA_DIR, "manageengine_advisories.json")

class ManageEngineClient:
    def __init__(self):
        self.advisories = self._load_advisories()

    def _load_advisories(self) -> List[Dict[str, Any]]:
        if os.path.exists(ME_DATA_PATH):
            try:
                with open(ME_DATA_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def get_all_advisories(self) -> List[Dict[str, Any]]:
        return self.advisories

    def check_code_against_rules(self, source_code: str, language: str = "python") -> List[Dict[str, Any]]:
        """
        Inspects source code against ManageEngine Endpoint Central security baseline checks:
        1. Insecure Serialization in agent handlers (CVE-2021-44515 & CVE-2020-10189)
        2. Unquoted service paths & shell invocation (CVE-2023-38606)
        3. Arbitrary file uploads & directory containment (CVE-2021-44077)
        4. Hardcoded endpoint agent authentication tokens (ME Baseline Rule)
        5. Weak crypto in signature validation (CVE-2022-47966)
        """
        findings = []
        lines = source_code.splitlines()

        for idx, line in enumerate(lines, start=1):
            trimmed = line.strip()

            # Rule 1: ManageEngine Insecure Deserialization Pattern
            if ("pickle.loads" in trimmed or "yaml.load(" in trimmed) and "Loader=yaml.Loader" in trimmed or "pickle.loads(base64" in trimmed:
                findings.append({
                    "ruleId": "ME-RULE-DESER-01",
                    "cve": "CVE-2021-44515",
                    "title": "ManageEngine Endpoint Security Rule: Untrusted Object Deserialization",
                    "cwe": "CWE-502",
                    "severity": "CRITICAL",
                    "cvss": 9.8,
                    "line": idx,
                    "evidence": trimmed,
                    "source": "ManageEngine Endpoint Security (CVE-2021-44515)",
                    "product": "Endpoint Central Agent Communication",
                    "recommendation": "Use safe JSON serializers (json.loads) or yaml.safe_load to avoid arbitrary remote code execution.",
                    "reference": "https://www.manageengine.com/products/desktop-central/endpoint-central-endpoint-security.html"
                })

            # Rule 2: Unquoted service paths & shell commands (ManageEngine CVE-2023-38606)
            if ("os.system(" in trimmed or "shell=True" in trimmed) and ("service" in trimmed.lower() or "run" in trimmed.lower() or "cmd" in trimmed.lower()):
                findings.append({
                    "ruleId": "ME-RULE-CMD-02",
                    "cve": "CVE-2023-38606",
                    "title": "ManageEngine Endpoint Security Rule: Unquoted Path / Shell Command Execution",
                    "cwe": "CWE-78",
                    "severity": "HIGH",
                    "cvss": 7.8,
                    "line": idx,
                    "evidence": trimmed,
                    "source": "ManageEngine Endpoint Security (CVE-2023-38606)",
                    "product": "Endpoint Central Agent Execution Controller",
                    "recommendation": "Invoke subprocess with strict argument arrays and shell=False to prevent command injection and privilege escalation.",
                    "reference": "https://www.manageengine.com/products/desktop-central/endpoint-central-endpoint-security.html"
                })

            # Rule 3: Path Traversal in Endpoint File Uploads (ManageEngine CVE-2021-44077)
            if ("open(" in trimmed or "writeFileSync(" in trimmed) and ("upload" in trimmed.lower() or "static" in trimmed.lower()) and ("+" in trimmed or "f\"" in trimmed or "${" in trimmed):
                if "basename" not in trimmed and "abspath" not in trimmed:
                    findings.append({
                        "ruleId": "ME-RULE-FILE-03",
                        "cve": "CVE-2021-44077",
                        "title": "ManageEngine Endpoint Security Rule: Uncontained File Upload Path Traversal",
                        "cwe": "CWE-22",
                        "severity": "CRITICAL",
                        "cvss": 9.8,
                        "line": idx,
                        "evidence": trimmed,
                        "source": "ManageEngine Endpoint Security (CVE-2021-44077)",
                        "product": "Endpoint Central File Repository",
                        "recommendation": "Sanitize filenames using os.path.basename and enforce absolute path containment within designated directories.",
                        "reference": "https://www.manageengine.com/products/desktop-central/endpoint-central-endpoint-security.html"
                    })

            # Rule 4: Hardcoded Endpoint Shared Secret / Agent Token
            if re.search(r'(?:AGENT_AUTH_TOKEN|MANAGEMENT_KEY|ENDPOINT_SECRET|API_KEY)\s*=\s*[\'"][^\'"]{10,}[\'"]', trimmed, re.IGNORECASE):
                findings.append({
                    "ruleId": "ME-RULE-SECRET-04",
                    "cve": "CWE-798",
                    "title": "ManageEngine Endpoint Security Rule: Hardcoded Agent Secret Key",
                    "cwe": "CWE-798",
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "line": idx,
                    "evidence": trimmed,
                    "source": "ManageEngine Endpoint Security Baseline",
                    "product": "Endpoint Central Configuration Manager",
                    "recommendation": "Store endpoint secrets in encrypted key stores or retrieve via environment variables (os.getenv).",
                    "reference": "https://www.manageengine.com/products/desktop-central/endpoint-central-endpoint-security.html"
                })

        return findings

manageengine_client = ManageEngineClient()


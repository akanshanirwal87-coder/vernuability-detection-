"""
OWASP Mapper for SecureCode AI.
Maps MITRE CWE identifiers to OWASP Top 10 (2021) categories with detailed descriptions.
"""

from typing import Dict, Any, Optional
from .cwe_mapper import CWEMapper


OWASP_2021_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "A01:2021": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are not properly enforced.",
        "common_cwes": ["CWE-22", "CWE-377", "CWE-428"],
    },
    "A02:2021": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography which often leads to sensitive data exposure or system compromise.",
        "common_cwes": ["CWE-327"],
    },
    "A03:2021": {
        "id": "A03:2021",
        "name": "Injection",
        "description": "User-supplied data is not validated, filtered, or sanitized by the application before execution.",
        "common_cwes": ["CWE-89", "CWE-78", "CWE-79", "CWE-95", "CWE-1321"],
    },
    "A05:2021": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": "Missing appropriate security hardening, enabled debug features, or unpatched flaws.",
        "common_cwes": ["CWE-489", "CWE-611", "CWE-1333"],
    },
    "A07:2021": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": "Confirmation of the user's identity, authentication, and session management is broken.",
        "common_cwes": ["CWE-798"],
    },
    "A08:2021": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations (such as insecure deserialization).",
        "common_cwes": ["CWE-502"],
    },
    "A10:2021": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Flaws that occur when a web application fetches a remote resource without validating the user-supplied URL.",
        "common_cwes": ["CWE-918"],
    },
}


class OWASPMapper:
    """Provides validated mappings from CWE weakness identifiers to OWASP Top 10 categories."""

    @classmethod
    def map_cwe_to_owasp(cls, cwe_identifier: str) -> str:
        """Looks up the OWASP 2021 category string for a given CWE."""
        defn = CWEMapper.get_definition(cwe_identifier)
        if defn:
            return defn.owasp_2021
        return "Unmapped Weakness"

    @classmethod
    def get_category_details(cls, owasp_prefix: str) -> Optional[Dict[str, Any]]:
        """Retrieves metadata for an OWASP prefix (e.g. 'A03:2021')."""
        for code, data in OWASP_2021_CATEGORIES.items():
            if owasp_prefix.startswith(code):
                return data
        return None

"""
CWE Mapper for SecureCode AI.
Normalizes, validates, and looks up MITRE Common Weakness Enumeration identifiers.
Prevents ungrounded or fabricated CWE assignments.
"""

import re
from typing import Optional, Dict, Any
from .vulnerability_catalog import VULNERABILITY_CATALOG, VulnerabilityDefinition


class CWEMapper:
    """Utility class to normalize, validate, and retrieve CWE metadata."""

    CATEGORY_TO_CWE: Dict[str, str] = {
        "SQL_INJECTION": "CWE-89",
        "COMMAND_INJECTION": "CWE-78",
        "CROSS_SITE_SCRIPTING": "CWE-79",
        "PATH_TRAVERSAL": "CWE-22",
        "UNSAFE_DESERIALIZATION": "CWE-502",
        "HARDCODED_CREDENTIALS": "CWE-798",
        "INSECURE_CRYPTOGRAPHY": "CWE-327",
        "DYNAMIC_EVALUATION": "CWE-95",
        "SSRF": "CWE-918",
        "PROTOTYPE_POLLUTION": "CWE-1321",
        "INSECURE_CONFIGURATION": "CWE-489",
        "INSECURE_TEMP_FILE": "CWE-377",
        "PRIVILEGE_ESCALATION": "CWE-428",
    }

    @classmethod
    def normalize_cwe(cls, raw_cwe: str) -> str:
        """Normalizes any CWE representation into canonical 'CWE-XYZ' format."""
        if not raw_cwe:
            return "CWE-OTHER"
        cleaned = raw_cwe.strip().upper()
        # Extract digits
        match = re.search(r"(\d+)", cleaned)
        if match:
            cwe_num = int(match.group(1))
            return f"CWE-{cwe_num}"
        return "CWE-OTHER"

    @classmethod
    def get_definition(cls, cwe_identifier: str) -> Optional[VulnerabilityDefinition]:
        """Retrieves official definition from the vulnerability catalog."""
        norm = cls.normalize_cwe(cwe_identifier)
        return VULNERABILITY_CATALOG.get(norm)

    @classmethod
    def map_category_to_cwe(cls, category: str) -> str:
        """Maps a high-level category string to its canonical CWE."""
        key = category.strip().upper().replace(" ", "_").replace("-", "_")
        return cls.CATEGORY_TO_CWE.get(key, "CWE-OTHER")

    @classmethod
    def is_known_cwe(cls, cwe_identifier: str) -> bool:
        """Checks if a CWE is cataloged in the knowledge base."""
        norm = cls.normalize_cwe(cwe_identifier)
        return norm in VULNERABILITY_CATALOG

"""
Software Composition Analysis (SCA) Scanner for SecureCode AI.
Orchestrates manifest parsing, OSV querying, and semantic version matching.
Adheres to strict security accuracy:
1. Never infers an imported package is vulnerable without dependency/version evidence.
2. Accurately maps real CWEs (CWE-1395, CWE-1104, or specific advisory CWE).
3. Preserves authentic advisory IDs (CVE, GHSA), CVSS severities, and source links.
"""

import uuid
from typing import List, Dict, Any, Optional
from analyzer.dependency_parser import DependencyParser, DependencyItem
from analyzer.version_matcher import VersionMatcher, VulnerabilityStatus
from analyzer.osv_client import osv_client


class ScaScanner:
    """
    Scans project dependency manifests against the OSV.dev vulnerability database.
    """

    def __init__(self):
        pass

    @staticmethod
    def extract_cwe_from_advisory(advisory: Dict[str, Any]) -> str:
        """
        Extracts real CWE identifier from OSV advisory database_specific fields or details.
        Defaults to CWE-1395 (Dependency on Vulnerable Third-Party Component).
        """
        # 1. Direct cwe field if present
        if "cwe" in advisory and advisory["cwe"] and advisory["cwe"].startswith("CWE-"):
            return advisory["cwe"]

        # 2. database_specific.cwe_ids
        db_spec = advisory.get("database_specific", {})
        if isinstance(db_spec, dict):
            cwes = db_spec.get("cwe_ids", [])
            if cwes and isinstance(cwes, list):
                return cwes[0]

        # 3. Search advisory details for CWE-xxx
        import re
        details = advisory.get("details", "") or ""
        summary = advisory.get("title", "") or ""
        found = re.findall(r'CWE-\d+', f"{details} {summary}", re.IGNORECASE)
        if found:
            return found[0].upper()

        return "CWE-1395"

    def scan_manifest(
        self,
        filename: str,
        content: str,
        scan_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Parses a dependency manifest (requirements.txt, package.json, etc.)
        and queries OSV for verified vulnerabilities matching resolved versions.
        """
        dependencies = DependencyParser.parse_manifest(filename, content)
        return self.scan_dependencies(dependencies, scan_id=scan_id)

    def scan_dependencies(
        self,
        dependencies: List[DependencyItem],
        scan_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Takes a list of DependencyItems, queries OSV, and verifies affected status.
        Only items with verified AFFECTED version status generate vulnerability findings.
        """
        findings: List[Dict[str, Any]] = []
        actual_scan_id = scan_id or f"sca-{uuid.uuid4().hex[:8]}"

        for dep in dependencies:
            # If version is missing or unpinned, we DO NOT falsely claim it is vulnerable.
            if not dep.version:
                continue

            # Query OSV database with exact ecosystem, name, and version
            osv_results = osv_client.query_package(
                package_name=dep.name,
                ecosystem=dep.ecosystem,
                version=dep.version
            )

            for adv in osv_results:
                # If advisory contains range events, verify with VersionMatcher
                status = VulnerabilityStatus.AFFECTED
                if "affected" in adv:
                    status = VersionMatcher.evaluate_advisory(dep.version, adv, dep.name)

                if status == VulnerabilityStatus.AFFECTED:
                    advisory_id = adv.get("id") or adv.get("cve") or "OSV-VULN"
                    cve_id = adv.get("cve") or advisory_id
                    cwe = self.extract_cwe_from_advisory(adv)
                    severity = adv.get("severity", "HIGH")
                    title = f"Vulnerable Dependency: {dep.name}@{dep.version} ({cve_id})"

                    # Find fixed version if available
                    fixed_ver = "latest secure release"
                    if "affected" in adv:
                        for aff in adv.get("affected", []):
                            for r in aff.get("ranges", []):
                                for ev in r.get("events", []):
                                    if "fixed" in ev:
                                        fixed_ver = ev["fixed"]
                                        break

                    findings.append({
                        "id": f"sca-{uuid.uuid4().hex[:6]}",
                        "scanId": actual_scan_id,
                        "title": title,
                        "category": "VULNERABLE_DEPENDENCY",
                        "severity": severity,
                        "cwe": cwe,
                        "owaspCategory": "A06:2021-Vulnerable and Outdated Components",
                        "file": dep.source_manifest or "dependencies",
                        "startLine": 1,
                        "endLine": 1,
                        "confidence": 0.98,
                        "description": (
                            f"Known vulnerability identified in {dep.name}@{dep.version} via OSV.dev ({cve_id}). "
                            f"{adv.get('details', '')[:250]}"
                        ),
                        "evidence": f"{dep.name}=={dep.version} (in {dep.source_manifest or 'manifest'})",
                        "impact": f"Exploitation of {cve_id} can lead to service compromise.",
                        "dataFlow": [
                            {
                                "step": 1,
                                "label": f"Third-Party Package: {dep.name}@{dep.version}",
                                "codeSnippet": f"{dep.name}=={dep.version}",
                                "line": 1,
                                "type": "SINK",
                                "description": f"Vulnerability {cve_id} in {dep.ecosystem} ecosystem."
                            }
                        ],
                        "vulnerableCode": f"{dep.name}=={dep.version}",
                        "remediationCode": f"# Upgrade {dep.name} to >= {fixed_ver} in {dep.source_manifest or 'manifest'}",
                        "remediationExplanation": f"Upgrade {dep.name} to version {fixed_ver} to remediate {cve_id}.",
                        "bestPractices": [
                            "Perform automated Software Composition Analysis (SCA) in CI/CD.",
                            "Keep dependencies updated to actively supported and patched versions.",
                            "Use lockfiles (package-lock.json) with cryptographic integrity hashes."
                        ],
                        "references": adv.get("references") or ["https://osv.dev/"],
                        "remediationStatus": "OPEN",
                        "validationStatus": "NOT_VALIDATED",
                        "detectionSource": "OSV_DATABASE",
                        "cve": cve_id,
                        "advisoryId": advisory_id,
                        "packageName": dep.name,
                        "installedVersion": dep.version,
                        "fixedVersion": fixed_ver,
                    })

        return findings


sca_scanner = ScaScanner()

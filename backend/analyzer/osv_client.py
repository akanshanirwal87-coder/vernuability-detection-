"""
OSV.dev REST API Client & Dependency Vulnerability Checker
Connects SecureCode AI with Google's Open Source Vulnerabilities (OSV) database.
API Documentation: https://osv.dev/
"""

import os
import json
import threading
import tempfile
import requests
from typing import List, Dict, Any, Optional

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
CACHE_FILE = os.path.join(CACHE_DIR, "osv_local_cache.json")


class OsvClient:
    def __init__(self, timeout: int = 4):
        self.timeout = timeout
        self._lock = threading.Lock()
        self._session = requests.Session()
        self.local_cache = self._load_cache()

    def _load_cache(self) -> Dict[str, Any]:
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self):
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(dir=CACHE_DIR, prefix="osv_cache_", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self.local_cache, f, indent=2)
                os.replace(tmp_path, CACHE_FILE)
            except Exception:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
        except Exception:
            pass

    def query_package(self, package_name: str, ecosystem: str = "PyPI", version: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Queries the OSV.dev API for vulnerabilities in a package.
        Supports PyPI, npm, and other open source ecosystems.
        """
        cache_key = f"{ecosystem}:{package_name}:{version or 'latest'}"
        with self._lock:
            if cache_key in self.local_cache:
                return self.local_cache[cache_key]

        payload: Dict[str, Any] = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        if version:
            payload["version"] = version

        try:
            response = self._session.post(OSV_QUERY_URL, json=payload, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                formatted = []
                for v in vulns:
                    aliases = v.get("aliases", [])
                    cve_id = next((a for a in aliases if a.startswith("CVE-")), v.get("id"))
                    
                    # Extract CVSS or severity
                    severity = "HIGH"
                    sev_list = v.get("severity", [])
                    if sev_list and isinstance(sev_list, list):
                        score = sev_list[0].get("score", "")
                        if "CVSS:3" in score:
                            severity = "CRITICAL" if "AV:N" in score and "AC:L" in score else "HIGH"

                    formatted.append({
                        "id": v.get("id"),
                        "cve": cve_id,
                        "title": v.get("summary") or f"Vulnerability in {package_name}",
                        "details": v.get("details", ""),
                        "severity": severity,
                        "package": package_name,
                        "ecosystem": ecosystem,
                        "published": v.get("published"),
                        "references": [r.get("url") for r in v.get("references", []) if r.get("url")][:3],
                        "source": "https://osv.dev/",
                        "affected": v.get("affected", []),
                        "database_specific": v.get("database_specific", {})
                    })
                
                with self._lock:
                    self.local_cache[cache_key] = formatted
                    self._save_cache()
                return formatted
        except Exception:
            # Fallback gracefully if network times out
            pass

        with self._lock:
            return self.local_cache.get(cache_key, [])

    def scan_imports(self, imports: List[str], language: str = "python", versions: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Scans imported packages against the OSV database only when version evidence is available.
        Does NOT falsely flag an import as vulnerable if no dependency version evidence is provided.
        """
        ecosystem = "PyPI" if language.lower() == "python" else "npm"
        findings = []

        if not versions:
            # Without dependency version evidence, do not infer vulnerability
            return []

        # Known standard libraries to ignore
        stdlib = {
            "os", "sys", "re", "json", "ast", "math", "time", "datetime", "uuid",
            "subprocess", "hashlib", "shutil", "tempfile", "urllib", "sqlite3",
            "pathlib", "collections", "itertools", "functools", "typing", "base64",
            "fs", "path", "http", "events", "util", "crypto", "stream", "buffer"
        }

        for imp in imports:
            clean_pkg = imp.split(".")[0].strip().lower()
            if not clean_pkg or clean_pkg in stdlib:
                continue

            pkg_ver = versions.get(clean_pkg)
            if not pkg_ver:
                # No version evidence for this package -> do not flag
                continue

            results = self.query_package(clean_pkg, ecosystem=ecosystem, version=pkg_ver)
            if results:
                top = results[0]
                findings.append({
                    "packageName": clean_pkg,
                    "version": pkg_ver,
                    "ecosystem": ecosystem,
                    "advisoryId": top["id"],
                    "cve": top["cve"],
                    "title": top["title"],
                    "severity": top["severity"],
                    "references": top["references"],
                    "details": top["details"][:200] + "..." if len(top["details"]) > 200 else top["details"]
                })

        return findings

osv_client = OsvClient()


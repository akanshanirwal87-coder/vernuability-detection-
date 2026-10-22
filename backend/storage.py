import sqlite3
import json
import os
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")

class ScanStorage:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    project_name TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    language TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    duration_ms INTEGER,
                    lines_analyzed INTEGER,
                    source_code TEXT,
                    highest_severity TEXT,
                    findings_count_json TEXT,
                    ast_summary_json TEXT,
                    is_demo INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cwe TEXT,
                    owasp_category TEXT,
                    file TEXT,
                    start_line INTEGER,
                    end_line INTEGER,
                    confidence REAL,
                    description TEXT,
                    evidence TEXT,
                    impact TEXT,
                    data_flow_json TEXT,
                    vulnerable_code TEXT,
                    remediation_code TEXT,
                    remediation_explanation TEXT,
                    best_practices_json TEXT,
                    references_json TEXT,
                    remediation_status TEXT DEFAULT 'OPEN',
                    validation_status TEXT DEFAULT 'NOT_VALIDATED',
                    validation_notes TEXT,
                    detection_source TEXT DEFAULT 'AST',
                    cve TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                )
            """)
            # Safe schema migrations for existing SQLite DBs
            for col in [("scans", "ml_analysis_json", "TEXT"), ("scans", "osv_findings_json", "TEXT"), ("scans", "me_rules_json", "TEXT")]:
                try:
                    conn.execute(f"ALTER TABLE {col[0]} ADD COLUMN {col[1]} {col[2]}")
                except Exception:
                    pass
            for col in [("findings", "detection_source", "TEXT DEFAULT 'AST'"), ("findings", "cve", "TEXT")]:
                try:
                    conn.execute(f"ALTER TABLE {col[0]} ADD COLUMN {col[1]} {col[2]}")
                except Exception:
                    pass
            conn.commit()
        self._seed_demo_if_empty()

    def _seed_demo_if_empty(self):
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM scans")
            count = cursor.fetchone()[0]
            if count == 0:
                demo_scan = {
                    "id": "scan-demo-01",
                    "projectName": "PaymentGateway-Core-Service",
                    "fileName": "auth_and_payments.py",
                    "language": "python",
                    "createdAt": "2026-10-11T06:00:00Z",
                    "completedAt": "2026-10-11T06:00:04Z",
                    "status": "COMPLETED",
                    "durationMs": 4210,
                    "linesAnalyzed": 482,
                    "sourceCode": """# PaymentGateway Core Service (Demonstration File)
import sqlite3
import os
import requests
import hashlib

STRIPE_API_SECRET = "stripe_demo_test_secret_key_placeholder_9921"

def get_user_profile(username: str):
    conn = sqlite3.connect("production.db")
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation creates SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user

def ping_host(target_host: str):
    # VULNERABLE: Command injection via shell concatenation
    command = "ping -c 1 " + target_host
    os.system(command)
    return {"status": "dispatched"}

def read_user_document(filename: str):
    base_dir = "/var/www/uploads/"
    # VULNERABLE: Path traversal
    file_path = base_dir + filename
    with open(file_path, "r") as f:
        return f.read()

def generate_fingerprint(data: str):
    # VULNERABLE: Insecure MD5 hash
    return hashlib.md5(data.encode()).hexdigest()
""",
                    "highestSeverity": "CRITICAL",
                    "findingsCount": {
                        "critical": 2,
                        "high": 2,
                        "medium": 1,
                        "low": 0,
                        "total": 5
                    },
                    "astSummary": {
                        "nodesCount": 312,
                        "functionsFound": 4,
                        "importsFound": ["sqlite3", "os", "requests", "hashlib"],
                        "sinksIdentified": 4
                    },
                    "isDemo": True,
                    "findings": [
                        {
                            "id": "fnd-sqli-01",
                            "scanId": "scan-demo-01",
                            "title": "SQL Injection via Unsanitized Query Parameter",
                            "category": "SQL_INJECTION",
                            "severity": "CRITICAL",
                            "cwe": "CWE-89",
                            "owaspCategory": "A03:2021-Injection",
                            "file": "auth_and_payments.py",
                            "startLine": 13,
                            "endLine": 14,
                            "confidence": 0.96,
                            "description": "User-controlled parameter `username` is directly concatenated into a raw SQL query executed by cursor.execute without using parameter placeholders.",
                            "evidence": 'query = "SELECT * FROM users WHERE username = \'" + username + "\'"\ncursor.execute(query)',
                            "impact": "An attacker can inject arbitrary SQL statements, allowing authentication bypass, unauthorized data exfiltration, database corruption, or administrative privilege escalation.",
                            "dataFlow": [
                                {
                                    "step": 1,
                                    "label": "Source: Untrusted Parameter",
                                    "codeSnippet": "def get_user_profile(username: str):",
                                    "line": 9,
                                    "type": "SOURCE",
                                    "description": "Parameter `username` enters the application scope from untrusted client input."
                                },
                                {
                                    "step": 2,
                                    "label": "Transform: Direct String Concatenation",
                                    "codeSnippet": 'query = "SELECT * FROM users WHERE username = \'" + username + "\'"',
                                    "line": 13,
                                    "type": "TRANSFORM",
                                    "description": "String concatenation merges untrusted input directly into the executable SQL grammar without encoding."
                                },
                                {
                                    "step": 3,
                                    "label": "Sink: Database Query Execution",
                                    "codeSnippet": "cursor.execute(query)",
                                    "line": 14,
                                    "type": "SINK",
                                    "description": "Vulnerable SQL string passed to database driver execution context."
                                }
                            ],
                            "vulnerableCode": '    query = "SELECT * FROM users WHERE username = \'" + username + "\'"\n    cursor.execute(query)',
                            "remediationCode": '    query = "SELECT * FROM users WHERE username = ?"\n    cursor.execute(query, (username,))',
                            "remediationExplanation": "Parameterized queries (prepared statements) ensure the database engine treats input strictly as data values, preventing user input from altering query grammar.",
                            "bestPractices": [
                                "Always use parameter substitution with placeholder tuples (?) or named bindings (:param).",
                                "Never concatenate, interpolate, or format strings into SQL statements.",
                                "Adopt Object-Relational Mappers (ORMs) such as SQLAlchemy with proper abstraction."
                            ],
                            "references": [
                                "https://cwe.mitre.org/data/definitions/89.html",
                                "https://owasp.org/Top10/A03_2021-Injection/"
                            ],
                            "remediationStatus": "OPEN",
                            "validationStatus": "NOT_VALIDATED"
                        },
                        {
                            "id": "fnd-cmd-02",
                            "scanId": "scan-demo-01",
                            "title": "Command Injection in System Utility Dispatcher",
                            "category": "COMMAND_INJECTION",
                            "severity": "CRITICAL",
                            "cwe": "CWE-78",
                            "owaspCategory": "A03:2021-Injection",
                            "file": "auth_and_payments.py",
                            "startLine": 21,
                            "endLine": 22,
                            "confidence": 0.98,
                            "description": "Untrusted hostname input is passed directly to `os.system()` with shell execution semantics enabled.",
                            "evidence": 'command = "ping -c 1 " + target_host\nos.system(command)',
                            "impact": "Remote code execution (RCE) on the host operating system with the privileges of the running application process.",
                            "dataFlow": [
                                {
                                    "step": 1,
                                    "label": "Source: Network Target Input",
                                    "codeSnippet": "def ping_host(target_host: str):",
                                    "line": 19,
                                    "type": "SOURCE",
                                    "description": "Client supplied network address parameter."
                                },
                                {
                                    "step": 2,
                                    "label": "Transform: Shell Command Formatting",
                                    "codeSnippet": 'command = "ping -c 1 " + target_host',
                                    "line": 21,
                                    "type": "TRANSFORM",
                                    "description": "Direct string concatenation without shell meta-character sanitization."
                                },
                                {
                                    "step": 3,
                                    "label": "Sink: Operating System Shell",
                                    "codeSnippet": "os.system(command)",
                                    "line": 22,
                                    "type": "SINK",
                                    "description": "OS shell interprets operators like ;, &, |, $() to execute arbitrary commands."
                                }
                            ],
                            "vulnerableCode": '    command = "ping -c 1 " + target_host\n    os.system(command)',
                            "remediationCode": '    subprocess.run(["ping", "-c", "1", target_host], shell=False, check=True)',
                            "remediationExplanation": "Use subprocess.run with argument arrays and shell=False to prevent shell interpreters from parsing shell meta-characters.",
                            "bestPractices": [
                                "Disallow direct shell invocation (avoid os.system, os.popen, shell=True).",
                                "Validate inputs with strict allowlists.",
                                "Execute programs using explicit argument vectors."
                            ],
                            "references": [
                                "https://cwe.mitre.org/data/definitions/78.html"
                            ],
                            "remediationStatus": "OPEN",
                            "validationStatus": "NOT_VALIDATED"
                        },
                        {
                            "id": "fnd-cred-03",
                            "scanId": "scan-demo-01",
                            "title": "Hardcoded Production API Secret",
                            "category": "HARDCODED_CREDENTIALS",
                            "severity": "HIGH",
                            "cwe": "CWE-798",
                            "owaspCategory": "A07:2021-Identification and Authentication Failures",
                            "file": "auth_and_payments.py",
                            "startLine": 7,
                            "endLine": 7,
                            "confidence": 0.94,
                            "description": "High-entropy cryptographic token matching Stripe live secret key pattern detected in plaintext source code.",
                            "evidence": 'STRIPE_API_SECRET = "stripe_demo_test_secret_key_placeholder_9921"',
                            "impact": "Exposed secret permits unauthorized financial transactions and credential theft.",
                            "vulnerableCode": 'STRIPE_API_SECRET = "stripe_demo_test_secret_key_placeholder_9921"',
                            "remediationCode": 'STRIPE_API_SECRET = os.getenv("STRIPE_API_SECRET")\nif not STRIPE_API_SECRET:\n    raise RuntimeError("Missing STRIPE_API_SECRET")',
                            "remediationExplanation": "Extract secrets into environment variables or use a secret management service.",
                            "bestPractices": [
                                "Extract credentials into environment variables or secrets managers.",
                                "Add secret scanning pre-commit hooks to git repositories."
                            ],
                            "references": [
                                "https://cwe.mitre.org/data/definitions/798.html"
                            ],
                            "remediationStatus": "OPEN",
                            "validationStatus": "NOT_VALIDATED"
                        },
                        {
                            "id": "fnd-path-04",
                            "scanId": "scan-demo-01",
                            "title": "Path Traversal via Unvalidated File Path",
                            "category": "PATH_TRAVERSAL",
                            "severity": "HIGH",
                            "cwe": "CWE-22",
                            "owaspCategory": "A01:2021-Broken Access Control",
                            "file": "auth_and_payments.py",
                            "startLine": 27,
                            "endLine": 29,
                            "confidence": 0.91,
                            "description": "User-specified filename is joined directly with a base directory without verifying whether the canonical path escapes the root directory.",
                            "evidence": 'file_path = base_dir + filename\nwith open(file_path, "r") as f:\n    return f.read()',
                            "impact": "Arbitrary filesystem read access, allowing retrieval of sensitive system configuration (/etc/passwd) and credentials.",
                            "vulnerableCode": '    file_path = base_dir + filename\n    with open(file_path, "r") as f:\n        return f.read()',
                            "remediationCode": '    safe_name = os.path.basename(filename)\n    resolved = os.path.abspath(os.path.join(base_dir, safe_name))\n    if not resolved.startswith(base_dir):\n        raise PermissionError("Access forbidden")\n    with open(resolved, "r") as f:\n        return f.read()',
                            "remediationExplanation": "Extract the basename to prevent path modifiers (../) and verify the resolved absolute path starts with the allowed root directory path.",
                            "bestPractices": [
                                "Use os.path.basename to strip directory traversal sequences.",
                                "Canonicalize paths using os.path.realpath and enforce prefix containment."
                            ],
                            "references": [
                                "https://cwe.mitre.org/data/definitions/22.html"
                            ],
                            "remediationStatus": "OPEN",
                            "validationStatus": "NOT_VALIDATED"
                        },
                        {
                            "id": "fnd-crypto-05",
                            "scanId": "scan-demo-01",
                            "title": "Use of Broken Cryptographic Hash Algorithm (MD5)",
                            "category": "INSECURE_CRYPTOGRAPHY",
                            "severity": "MEDIUM",
                            "cwe": "CWE-327",
                            "owaspCategory": "A02:2021-Cryptographic Failures",
                            "file": "auth_and_payments.py",
                            "startLine": 33,
                            "endLine": 34,
                            "confidence": 0.89,
                            "description": "Application uses hashlib.md5 for hashing sensitive data. MD5 is cryptographically broken and vulnerable to collision attacks.",
                            "evidence": 'return hashlib.md5(data.encode()).hexdigest()',
                            "impact": "Collision attacks permit forgery of digital signatures, checksums, and token verification.",
                            "vulnerableCode": 'def generate_fingerprint(data: str):\n    return hashlib.md5(data.encode()).hexdigest()',
                            "remediationCode": 'def generate_fingerprint(data: str):\n    return hashlib.sha256(data.encode()).hexdigest()',
                            "remediationExplanation": "Upgrade legacy hash algorithms (MD5, SHA1) to modern cryptographic standards like SHA-256.",
                            "bestPractices": [
                                "Never use MD5 or SHA1 for integrity checks.",
                                "Use SHA-256 or SHA-3 for general hashing."
                            ],
                            "references": [
                                "https://cwe.mitre.org/data/definitions/327.html"
                            ],
                            "remediationStatus": "OPEN",
                            "validationStatus": "NOT_VALIDATED"
                        }
                    ]
                }
                self.save_scan(demo_scan)

    def save_scan(self, scan_data: Dict[str, Any]):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scans (
                    id, project_name, file_name, language, created_at, completed_at,
                    status, duration_ms, lines_analyzed, source_code, highest_severity,
                    findings_count_json, ast_summary_json, is_demo,
                    ml_analysis_json, osv_findings_json, me_rules_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_data["id"],
                scan_data["projectName"],
                scan_data.get("fileName", "code.py"),
                scan_data["language"],
                scan_data["createdAt"],
                scan_data.get("completedAt"),
                scan_data["status"],
                scan_data.get("durationMs", 0),
                scan_data.get("linesAnalyzed", 0),
                scan_data.get("sourceCode", ""),
                scan_data.get("highestSeverity", "LOW"),
                json.dumps(scan_data.get("findingsCount", {})),
                json.dumps(scan_data.get("astSummary", {})),
                1 if scan_data.get("isDemo") else 0,
                json.dumps(scan_data.get("mlAnalysis", {})) if scan_data.get("mlAnalysis") else None,
                json.dumps(scan_data.get("osvFindings", [])) if scan_data.get("osvFindings") else None,
                json.dumps(scan_data.get("manageEngineRules", [])) if scan_data.get("manageEngineRules") else None
            ))

            # Insert findings
            for f in scan_data.get("findings", []):
                conn.execute("""
                    INSERT OR REPLACE INTO findings (
                        id, scan_id, title, category, severity, cwe, owasp_category,
                        file, start_line, end_line, confidence, description, evidence,
                        impact, data_flow_json, vulnerable_code, remediation_code,
                        remediation_explanation, best_practices_json, references_json,
                        remediation_status, validation_status, validation_notes,
                        detection_source, cve
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f["id"],
                    scan_data["id"],
                    f["title"],
                    f["category"],
                    f["severity"],
                    f.get("cwe", ""),
                    f.get("owaspCategory", ""),
                    f.get("file", ""),
                    f.get("startLine", 1),
                    f.get("endLine", 1),
                    f.get("confidence", 0.9),
                    f.get("description", ""),
                    f.get("evidence", ""),
                    f.get("impact", ""),
                    json.dumps(f.get("dataFlow")) if f.get("dataFlow") else None,
                    f.get("vulnerableCode", ""),
                    f.get("remediationCode", ""),
                    f.get("remediationExplanation", ""),
                    json.dumps(f.get("bestPractices", [])),
                    json.dumps(f.get("references", [])),
                    f.get("remediationStatus", "OPEN"),
                    f.get("validationStatus", "NOT_VALIDATED"),
                    f.get("validationNotes"),
                    f.get("detectionSource", "AST"),
                    f.get("cve")
                ))
            conn.commit()

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None

            findings_cursor = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
            findings = []
            for f_row in findings_cursor.fetchall():
                findings.append({
                    "id": f_row["id"],
                    "scanId": f_row["scan_id"],
                    "title": f_row["title"],
                    "category": f_row["category"],
                    "severity": f_row["severity"],
                    "cwe": f_row["cwe"],
                    "owaspCategory": f_row["owasp_category"],
                    "file": f_row["file"],
                    "startLine": f_row["start_line"],
                    "endLine": f_row["end_line"],
                    "confidence": f_row["confidence"],
                    "description": f_row["description"],
                    "evidence": f_row["evidence"],
                    "impact": f_row["impact"],
                    "dataFlow": json.loads(f_row["data_flow_json"]) if f_row["data_flow_json"] else None,
                    "vulnerableCode": f_row["vulnerable_code"],
                    "remediationCode": f_row["remediation_code"],
                    "remediationExplanation": f_row["remediation_explanation"],
                    "bestPractices": json.loads(f_row["best_practices_json"]) if f_row["best_practices_json"] else [],
                    "references": json.loads(f_row["references_json"]) if f_row["references_json"] else [],
                    "remediationStatus": f_row["remediation_status"],
                    "validationStatus": f_row["validation_status"],
                    "validationNotes": f_row["validation_notes"],
                    "detectionSource": f_row["detection_source"] if "detection_source" in f_row.keys() else "AST",
                    "cve": f_row["cve"] if "cve" in f_row.keys() else None
                })

            return {
                "id": row["id"],
                "projectName": row["project_name"],
                "fileName": row["file_name"],
                "language": row["language"],
                "createdAt": row["created_at"],
                "completedAt": row["completed_at"],
                "status": row["status"],
                "durationMs": row["duration_ms"],
                "linesAnalyzed": row["lines_analyzed"],
                "sourceCode": row["source_code"],
                "highestSeverity": row["highest_severity"],
                "findingsCount": json.loads(row["findings_count_json"]) if row["findings_count_json"] else {},
                "astSummary": json.loads(row["ast_summary_json"]) if row["ast_summary_json"] else {},
                "mlAnalysis": json.loads(row["ml_analysis_json"]) if ("ml_analysis_json" in row.keys() and row["ml_analysis_json"]) else None,
                "osvFindings": json.loads(row["osv_findings_json"]) if ("osv_findings_json" in row.keys() and row["osv_findings_json"]) else None,
                "manageEngineRules": json.loads(row["me_rules_json"]) if ("me_rules_json" in row.keys() and row["me_rules_json"]) else None,
                "findings": findings,
                "isDemo": bool(row["is_demo"])
            }

    def list_scans(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM scans ORDER BY created_at DESC")
            scans = []
            for row in cursor.fetchall():
                findings_count = json.loads(row["findings_count_json"]) if row["findings_count_json"] else {}
                scans.append({
                    "id": row["id"],
                    "projectName": row["project_name"],
                    "fileName": row["file_name"],
                    "language": row["language"],
                    "createdAt": row["created_at"],
                    "totalFindings": findings_count.get("total", 0),
                    "highestSeverity": row["highest_severity"],
                    "status": row["status"],
                    "isDemo": bool(row["is_demo"])
                })
            return scans

    def update_finding_validation(self, finding_id: str, status: str, notes: str):
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE findings 
                SET validation_status = ?, validation_notes = ?, remediation_status = ?
                WHERE id = ?
            """, (status, notes, 'REMEDIATED' if status == 'VALIDATION_PASSED' else 'OPEN', finding_id))
            conn.commit()

    def delete_scan(self, scan_id: str):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()


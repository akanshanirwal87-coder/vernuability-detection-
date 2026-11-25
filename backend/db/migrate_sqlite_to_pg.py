"""
SQLite-to-PostgreSQL Migration Utility for SecureCode AI.
Safely migrates historical scans and findings from existing SQLite storage
to the new PostgreSQL / SQLAlchemy production schema without modifying or deleting scans.db.
"""

import os
import sys
import sqlite3
import json
from datetime import datetime, timezone
from typing import Dict, Any, List

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import settings
from db.database import engine, SessionLocal, Base
from db.models import Scan, Finding, User, Project


def parse_datetime(val: Any) -> datetime:
    """Safely parse datetime string or return current UTC time."""
    if not val:
        return datetime.now(timezone.utc)
    if isinstance(val, datetime):
        return val
    try:
        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def migrate_data(sqlite_path: str = settings.DB_PATH) -> Dict[str, int]:
    """
    Reads records from existing SQLite scans.db and transfers them to the SQLAlchemy database.
    """
    if not os.path.isfile(sqlite_path):
        print(f"Source SQLite database not found at {sqlite_path}. Nothing to migrate.")
        return {"scans_migrated": 0, "findings_migrated": 0}

    # Ensure tables exist in target database
    Base.metadata.create_all(bind=engine)

    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    session = SessionLocal()
    scans_migrated = 0
    findings_migrated = 0

    try:
        # Check if scans table exists in SQLite
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
        if not cursor.fetchone():
            print("No 'scans' table found in source SQLite.")
            return {"scans_migrated": 0, "findings_migrated": 0}

        cursor.execute("SELECT * FROM scans")
        sqlite_scans = cursor.fetchall()

        for s_row in sqlite_scans:
            s_dict = dict(s_row)
            scan_id = s_dict["id"]

            # Avoid duplicate migration
            existing_scan = session.get(Scan, scan_id)
            if existing_scan:
                continue

            created_at = parse_datetime(s_dict.get("created_at"))
            completed_at = parse_datetime(s_dict.get("completed_at")) if s_dict.get("completed_at") else None

            # Calculate risk score
            counts_raw = s_dict.get("findings_count_json") or "{}"
            try:
                counts = json.loads(counts_raw)
            except Exception:
                counts = {}
            crit = counts.get("critical", 0)
            high = counts.get("high", 0)
            total = counts.get("total", 0)
            risk_score = min(100, crit * 30 + high * 15 + max(0, total - crit - high) * 5)

            new_scan = Scan(
                id=scan_id,
                project_name=s_dict.get("project_name", "Migrated Project"),
                file_name=s_dict.get("file_name", "source_code"),
                language=s_dict.get("language", "python"),
                status=s_dict.get("status", "COMPLETED"),
                risk_score=risk_score,
                highest_severity=s_dict.get("highest_severity", "LOW"),
                duration_ms=s_dict.get("duration_ms", 0),
                lines_analyzed=s_dict.get("lines_analyzed", 0),
                source_code=s_dict.get("source_code"),
                findings_count_json=s_dict.get("findings_count_json"),
                ast_summary_json=s_dict.get("ast_summary_json"),
                started_at=created_at,
                completed_at=completed_at,
                created_at=created_at,
            )
            session.add(new_scan)
            scans_migrated += 1

        session.commit()

        # Migrate findings
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        if cursor.fetchone():
            cursor.execute("SELECT * FROM findings")
            sqlite_findings = cursor.fetchall()

            for f_row in sqlite_findings:
                f_dict = dict(f_row)
                finding_id = f_dict["id"]

                existing_f = session.get(Finding, finding_id)
                if existing_f:
                    continue

                new_finding = Finding(
                    id=finding_id,
                    scan_id=f_dict["scan_id"],
                    title=f_dict.get("title", "Vulnerability Finding"),
                    category=f_dict.get("category", "SECURITY_VULNERABILITY"),
                    severity=f_dict.get("severity", "MEDIUM"),
                    cwe=f_dict.get("cwe"),
                    owasp_category=f_dict.get("owasp_category"),
                    file_path=f_dict.get("file") or f_dict.get("file_path") or "source_code",
                    start_line=f_dict.get("start_line", 1),
                    end_line=f_dict.get("end_line", 1),
                    confidence=float(f_dict.get("confidence", 0.9)),
                    description=f_dict.get("description"),
                    evidence=f_dict.get("evidence"),
                    impact=f_dict.get("impact"),
                    vulnerable_code=f_dict.get("vulnerable_code"),
                    remediation_code=f_dict.get("remediation_code"),
                    remediation_explanation=f_dict.get("remediation_explanation"),
                    remediation_status=f_dict.get("remediation_status", "OPEN"),
                    detection_source=f_dict.get("detection_source", "AST"),
                    cve=f_dict.get("cve"),
                    data_flow_json=f_dict.get("data_flow_json"),
                    best_practices_json=f_dict.get("best_practices_json"),
                    references_json=f_dict.get("references_json"),
                    created_at=datetime.now(timezone.utc),
                )
                session.add(new_finding)
                findings_migrated += 1

            session.commit()

        print(f"Migration completed successfully: {scans_migrated} scans, {findings_migrated} findings.")
        return {"scans_migrated": scans_migrated, "findings_migrated": findings_migrated}

    except Exception as e:
        session.rollback()
        print(f"Error during migration: {str(e)}")
        raise
    finally:
        session.close()
        conn.close()


if __name__ == "__main__":
    migrate_data()

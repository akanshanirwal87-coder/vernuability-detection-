# SecureCode AI — SQLite to PostgreSQL Migration Guide

This guide describes how to migrate the SecureCode AI storage backend from SQLite to a production-grade PostgreSQL database instance without data loss, downtime, or service disruption.

---

## 1. Prerequisites

1. **PostgreSQL Server**: PostgreSQL 14+ installed and running.
2. **Database & Credentials**:
   ```sql
   CREATE DATABASE securecode;
   CREATE USER securecode_user WITH ENCRYPTED PASSWORD 'your_strong_password';
   GRANT ALL PRIVILEGES ON DATABASE securecode TO securecode_user;
   ```
3. **Python Virtual Environment**:
   Ensure `psycopg` (v3) binary and `SQLAlchemy 2.x` are installed:
   ```bash
   pip install "psycopg[binary]>=3.1.0" "sqlalchemy>=2.0.0" "alembic>=1.13.0"
   ```

---

## 2. Environment Configuration

Copy or update your `.env` configuration file in the project root:

```bash
# PostgreSQL Production Connection URL:
DATABASE_URL=postgresql://securecode_user:your_strong_password@localhost:5432/securecode

# SQLite Fallback (Local Development & Offline Testing):
# DATABASE_URL=sqlite:///./scans.db
```

---

## 3. Running Alembic Schema Migrations

Apply the latest database migrations to initialize the target schema:

```bash
cd backend

# View current migration state
alembic current

# Upgrade database to latest revision
alembic upgrade head

# Inspect migration history
alembic history --verbose
```

### Rollback Procedure (If Needed):
To revert the migration:
```bash
alembic downgrade -1
```

---

## 4. Migrating Historical Data

SecureCode AI includes an automated, transactional migration script (`backend/db/migrate_sqlite_to_pg.py`) that reads all legacy scans, findings, and metadata from SQLite and inserts them into PostgreSQL with automatic ID preservation and duplicate prevention.

### Execute Migration:
```bash
cd backend
python -m db.migrate_sqlite_to_pg --source scans.db --target "$DATABASE_URL"
```

### Safety & Integrity Guarantees:
1. **Zero Data Destruction**: The existing `scans.db` is never deleted, truncated, or modified.
2. **Transactional Safety**: Insertions run inside an isolated SQLAlchemy transaction. If any record fails validation, the entire transaction is rolled back.
3. **Idempotent Upsert**: Running the migration multiple times safely checks for existing IDs and prevents duplicate record insertion.

---

## 5. Verification

Verify that the target PostgreSQL database contains all records:

```bash
# Check counts via python one-liner
python -c "
from db.database import get_db_session
from db.models import Scan, Finding
with get_db_session() as db:
    print('Scans count:', db.query(Scan).count())
    print('Findings count:', db.query(Finding).count())
"
```

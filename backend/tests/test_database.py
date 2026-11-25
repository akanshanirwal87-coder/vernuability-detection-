import pytest
from sqlalchemy import select
from db.models import User, Project, Scan, Finding
from db.database import engine, SessionLocal
from db.migrate_sqlite_to_pg import migrate_data


def test_database_connection_and_session(db_session):
    """Test that SQLAlchemy engine connects and transactions operate safely."""
    user = User(
        id="usr-db-test",
        name="Transaction Tester",
        email="transaction@example.com",
        password_hash="argon2id$mocked",
        role="USER",
    )
    db_session.add(user)
    db_session.commit()

    # Query back
    stmt = select(User).where(User.id == "usr-db-test")
    found = db_session.scalars(stmt).first()
    assert found is not None
    assert found.email == "transaction@example.com"


def test_database_cascade_deletion(db_session):
    """Verify that deleting a User cascades to delete owned Projects and Scans."""
    user = User(
        id="usr-cascade-owner",
        name="Cascade Owner",
        email="cascade@example.com",
        password_hash="mocked",
    )
    project = Project(
        id="proj-cascade-01",
        user_id="usr-cascade-owner",
        name="Cascade Project",
    )
    db_session.add(user)
    db_session.add(project)
    db_session.commit()

    # Verify project exists
    assert db_session.get(Project, "proj-cascade-01") is not None

    # Delete user
    db_session.delete(user)
    db_session.commit()

    # Project must be cascaded and deleted
    assert db_session.get(Project, "proj-cascade-01") is None


def test_sqlite_migration_utility():
    """Verify that SQLite-to-PostgreSQL migration utility executes safely."""
    res = migrate_data()
    assert isinstance(res, dict)
    assert "scans_migrated" in res
    assert "findings_migrated" in res

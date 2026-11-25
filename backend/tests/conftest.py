import os
import sys
import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

# Ensure backend root is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from core.config import settings
from db.database import Base, get_db
from db.models import User, Project, Scan, Finding, ScanJob
from core.security import hash_password, create_access_token
from main import app

# In-memory SQLite engine with StaticPool for fast, isolated test execution
TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Create all tables in memory once for test session."""
    Base.metadata.create_all(bind=TEST_ENGINE)
    yield
    Base.metadata.drop_all(bind=TEST_ENGINE)


@pytest.fixture
def db_session():
    """Provides a transactional database session per test with automatic rollback."""
    connection = TEST_ENGINE.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session: Session):
    """FastAPI TestClient with overridden get_db dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def normal_user(db_session: Session) -> User:
    """Fixture providing a persistent standard user."""
    user = User(
        id="usr-test-alice",
        name="Alice Developer",
        email="alice@example.com",
        password_hash=hash_password("AliceSecurePassword2026!"),
        role="USER",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def second_user(db_session: Session) -> User:
    """Fixture providing a second standard user for cross-user permission checks."""
    user = User(
        id="usr-test-bob",
        name="Bob Hacker",
        email="bob@example.com",
        password_hash=hash_password("BobSecurePassword2026!"),
        role="USER",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def admin_user(db_session: Session) -> User:
    """Fixture providing a persistent administrator user."""
    admin = User(
        id="usr-test-admin",
        name="Security Administrator",
        email="admin@securecode.ai",
        password_hash=hash_password("AdminSecurePassword2026!"),
        role="ADMIN",
        is_active=True,
    )
    db_session.add(admin)
    db_session.commit()
    db_session.refresh(admin)
    return admin


@pytest.fixture
def auth_headers(normal_user: User) -> dict:
    """Authorization headers for normal_user."""
    token = create_access_token(data={"sub": normal_user.id, "email": normal_user.email, "role": normal_user.role})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def second_user_headers(second_user: User) -> dict:
    """Authorization headers for second_user."""
    token = create_access_token(data={"sub": second_user.id, "email": second_user.email, "role": second_user.role})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers(admin_user: User) -> dict:
    """Authorization headers for admin_user."""
    token = create_access_token(data={"sub": admin_user.id, "email": admin_user.email, "role": admin_user.role})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_project(db_session: Session, normal_user: User) -> Project:
    """Fixture providing a sample project owned by normal_user."""
    project = Project(
        id="proj-sample-01",
        user_id=normal_user.id,
        name="E-Commerce Core",
        description="Payment gateway and cart services",
        repository_url="https://github.com/example/ecommerce",
    )
    db_session.add(project)
    db_session.commit()
    db_session.refresh(project)
    return project

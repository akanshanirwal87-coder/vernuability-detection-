import pytest
import os
import sys
import tempfile
from fastapi.testclient import TestClient

# Ensure backend directory is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app
from core.config import settings
from core.security import create_access_token, hash_password
from storage import ScanStorage


@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


@pytest.fixture
def admin_headers():
    """Headers for authenticated admin user."""
    token = create_access_token(data={"sub": settings.ADMIN_USERNAME, "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_api_key_headers():
    """Headers for admin API key authentication."""
    return {"X-API-Key": settings.ADMIN_API_KEY}


@pytest.fixture
def developer_headers():
    """Headers for authenticated non-admin developer user."""
    token = create_access_token(data={"sub": "dev_user", "role": "developer"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_requirements_content():
    return """
# Core requirements
requests==2.19.0
urllib3==1.24.1
fastapi>=0.100.0
# Commented line
flask==1.0.2; python_version >= '3.8'
"""


@pytest.fixture
def sample_package_json_content():
    return """{
  "name": "sample-app",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.15",
    "axios": "0.19.0"
  },
  "devDependencies": {
    "mocha": "^9.0.0"
  }
}"""

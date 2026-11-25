import os
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic import command

from db.database import Base


def test_models_metadata_registered():
    """Verify that all production tables are registered with SQLAlchemy metadata."""
    expected_tables = {"users", "projects", "scans", "findings", "refresh_tokens", "scan_jobs"}
    actual_tables = set(Base.metadata.tables.keys())
    for t in expected_tables:
        assert t in actual_tables, f"Table {t} must be registered in Base.metadata!"


def test_alembic_config_and_current_head():
    """Verify Alembic configuration file and script directory load without error."""
    alembic_ini_path = os.path.join(os.path.dirname(__file__), "..", "alembic.ini")
    assert os.path.isfile(alembic_ini_path)

    alembic_cfg = Config(alembic_ini_path)
    script = ScriptDirectory.from_config(alembic_cfg)
    heads = script.get_heads()
    assert len(heads) >= 1, "Alembic must have at least one head revision!"

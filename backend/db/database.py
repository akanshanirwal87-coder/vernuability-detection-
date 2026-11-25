import os
import sqlite3
from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session, DeclarativeBase

from core.config import settings


class Base(DeclarativeBase):
    """SQLAlchemy 2.x Declarative Base Class."""
    pass


def get_engine(db_url: str = settings.DATABASE_URL):
    """
    Creates a centralized SQLAlchemy 2.x Engine with appropriate pooling.
    Supports PostgreSQL (psycopg3) and SQLite with foreign key enforcement.
    """
    if db_url.startswith("sqlite"):
        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            echo=settings.DEBUG,
        )

        # Enforce foreign keys in SQLite
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            if isinstance(dbapi_connection, sqlite3.Connection):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        return engine

    # PostgreSQL configuration with connection pooling
    return create_engine(
        db_url,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=settings.DEBUG,
    )


engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency injection for database sessions.
    Ensures session closure and transaction safety per request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

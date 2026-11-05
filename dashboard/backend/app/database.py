"""
Database connection and session management for SecurePipeline.
Uses SQLite with transaction safety.
"""

from typing import Generator
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from .config import settings

# SQLite specific config: disable same-thread restriction for multi-threaded uvicorn
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency for providing database sessions per request with transaction rollback."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Columns added after the first live database was created.
# create_all() does not alter existing SQLite tables.
_FINDING_COLUMN_DDL = {
    "risk_score": "INTEGER DEFAULT 50",
    "priority": "VARCHAR(16) DEFAULT 'P2'",
    "risk_factors": "TEXT",
}


def migrate_schema(target_engine=None) -> None:
    """Adds prioritization columns to databases created before that feature."""
    use_engine = target_engine or engine
    inspector = inspect(use_engine)
    if "findings" not in inspector.get_table_names():
        return

    existing = {column["name"] for column in inspector.get_columns("findings")}
    with use_engine.begin() as conn:
        for name, ddl in _FINDING_COLUMN_DDL.items():
            if name not in existing:
                conn.execute(text(f"ALTER TABLE findings ADD COLUMN {name} {ddl}"))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings (priority)"
        ))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON findings (risk_score)"
        ))


def init_db(target_engine=None) -> None:
    """Creates all database tables defined in models, then applies schema upgrades."""
    use_engine = target_engine or engine
    Base.metadata.create_all(bind=use_engine)
    migrate_schema(use_engine)

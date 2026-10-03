import sqlite3

import pytest

from app.memory import MemoryStore


@pytest.mark.asyncio
async def test_fresh_database_initializes_complete_schema(tmp_path):
    database = tmp_path / "fresh" / "secure-agent.db"
    store = MemoryStore(database)

    await store.init()

    assert database.is_file()
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {
            "messages",
            "memories",
            "tasks",
            "audit_logs",
            "schedules",
            "schedule_runs",
            "documents",
            "document_chunks",
            "terminal_history",
            "security_reports",
            "permission_grants",
            "schema_migrations",
        } <= tables
        assert connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(1,), (2,), (3,), (4,)]

    # Initialization and migrations must be idempotent on an existing database.
    await store.init()


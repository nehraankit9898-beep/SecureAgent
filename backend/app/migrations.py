import sqlite3


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def _add(connection: sqlite3.Connection, table: str, definition: str) -> None:
    if definition.split()[0] not in _columns(connection, table):
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


def migration_001(connection: sqlite3.Connection) -> None:
    connection.executescript("""
    CREATE INDEX IF NOT EXISTS msg_idx ON messages(conversation_id,created_at);
    CREATE INDEX IF NOT EXISTS task_updated_idx ON tasks(updated_at DESC);
    CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_logs(created_at DESC);
    CREATE INDEX IF NOT EXISTS schedule_due_idx ON schedules(enabled,next_run);
    CREATE INDEX IF NOT EXISTS chunk_document_idx ON document_chunks(document_id,chunk_index);
    """)


def migration_002(connection: sqlite3.Connection) -> None:
    _add(connection,"schedules","policy TEXT NOT NULL DEFAULT '{}'")
    _add(connection,"schedules","cancelled INTEGER NOT NULL DEFAULT 0")
    _add(connection,"schedules","failure_count INTEGER NOT NULL DEFAULT 0")
    _add(connection,"documents","content_hash TEXT")
    _add(connection,"documents","version INTEGER NOT NULL DEFAULT 1")
    _add(connection,"documents","metadata TEXT NOT NULL DEFAULT '{}'")
    _add(connection,"documents","updated_at TEXT")
    _add(connection,"document_chunks","metadata TEXT NOT NULL DEFAULT '{}'")
    connection.executescript("""
    CREATE INDEX IF NOT EXISTS schedule_policy_idx ON schedules(enabled,cancelled,next_run);
    CREATE INDEX IF NOT EXISTS schedule_runs_idx ON schedule_runs(schedule_id,created_at DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS document_hash_idx ON documents(content_hash) WHERE content_hash IS NOT NULL;
    """)


def migration_003(connection):
    _add(connection,"schedules","lease_owner TEXT")
    _add(connection,"schedules","lease_expires TEXT")
    connection.execute("CREATE INDEX IF NOT EXISTS schedule_lease_idx ON schedules(enabled,cancelled,next_run,lease_expires)")


def migration_004(connection):
    connection.executescript("""
    CREATE TABLE IF NOT EXISTS terminal_history(
        id TEXT PRIMARY KEY,
        task_id TEXT,
        session_id TEXT,
        command TEXT NOT NULL,
        cwd TEXT,
        risk TEXT,
        approval TEXT,
        exit_code INTEGER,
        status TEXT,
        duration_ms INTEGER,
        stdout TEXT,
        stderr TEXT,
        truncated INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS terminal_history_created_idx ON terminal_history(created_at DESC);
    CREATE TABLE IF NOT EXISTS security_reports(
        id TEXT PRIMARY KEY,
        workflow TEXT NOT NULL,
        title TEXT,
        status TEXT,
        overall_severity TEXT,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS security_reports_created_idx ON security_reports(created_at DESC);
    CREATE TABLE IF NOT EXISTS permission_grants(
        id TEXT PRIMARY KEY,
        permission TEXT NOT NULL,
        scope TEXT NOT NULL,
        note TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT
    );
    """)
MIGRATIONS=[(1,migration_001),(2,migration_002),(3,migration_003),(4,migration_004)]


def run_migrations(connection: sqlite3.Connection) -> None:
    connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
    applied={row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
    for version,migration in MIGRATIONS:
        if version in applied:continue
        with connection:
            migration(connection)
            connection.execute("INSERT INTO schema_migrations(version) VALUES(?)",(version,))

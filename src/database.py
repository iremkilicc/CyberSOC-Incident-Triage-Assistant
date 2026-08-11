import sqlite3
import struct
import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATABASE_PATH = PROJECT_ROOT / "data" / "knowledge_index.db"
RUNTIME_DATA_DIR = Path(
    os.environ.get("LOCALAPPDATA", str(PROJECT_ROOT / "data"))
) / "CyberSOC"
HISTORY_DATABASE_PATH = RUNTIME_DATA_DIR / "cybersoc_history.db"
LEGACY_DATABASE_PATH = PROJECT_ROOT / "data" / "cybersoc.db"


KNOWLEDGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    source_type TEXT NOT NULL,
    scenario TEXT NOT NULL,
    source_url TEXT,
    license TEXT,
    content_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    chunk_index INTEGER NOT NULL,
    heading TEXT NOT NULL,
    content TEXT NOT NULL,
    embedding BLOB NOT NULL,
    embedding_dimensions INTEGER NOT NULL,
    embedding_model TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    UNIQUE (document_id, chunk_index)
);

"""

HISTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    scenario TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('system', 'user', 'assistant')),
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS case_state (
    conversation_id TEXT PRIMARY KEY,
    risk_level TEXT,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    missing_fields_json TEXT NOT NULL DEFAULT '[]',
    summary TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation_id
ON messages(conversation_id, id);
"""

SCHEMA = KNOWLEDGE_SCHEMA + """
CREATE INDEX IF NOT EXISTS idx_chunks_document_id ON chunks(document_id);
CREATE INDEX IF NOT EXISTS idx_documents_scenario ON documents(scenario);
"""


def get_connection() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)
    connection.commit()


def get_history_connection() -> sqlite3.Connection:
    """Open the per-user runtime DB; never modify a packaged knowledge index."""
    HISTORY_DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(HISTORY_DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_history_database(connection: sqlite3.Connection) -> None:
    connection.executescript(HISTORY_SCHEMA)
    connection.commit()


def migrate_legacy_history_if_needed(connection: sqlite3.Connection) -> bool:
    """Copy legacy history once without deleting or changing the old database."""
    existing = connection.execute("SELECT COUNT(*) FROM conversations").fetchone()[0]
    if existing or not LEGACY_DATABASE_PATH.exists():
        return False
    legacy = sqlite3.connect(LEGACY_DATABASE_PATH)
    try:
        tables = {
            row[0]
            for row in legacy.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if not {"conversations", "messages"}.issubset(tables):
            return False
        for table in ("conversations", "messages", "case_state"):
            if table not in tables:
                continue
            columns = [row[1] for row in legacy.execute(f"PRAGMA table_info({table})")]
            target_columns = {
                row[1] for row in connection.execute(f"PRAGMA table_info({table})")
            }
            columns = [name for name in columns if name in target_columns]
            names = ", ".join(f'"{name}"' for name in columns)
            rows = legacy.execute(f"SELECT {names} FROM {table}").fetchall()
            placeholders = ", ".join("?" for _ in columns)
            connection.executemany(
                f"INSERT OR IGNORE INTO {table} ({names}) VALUES ({placeholders})", rows
            )
        connection.commit()
        return True
    finally:
        legacy.close()


def serialize_embedding(values: list[float]) -> bytes:
    return struct.pack(f"<{len(values)}f", *values)


def deserialize_embedding(blob: bytes, dimensions: int) -> list[float]:
    return list(struct.unpack(f"<{dimensions}f", blob))

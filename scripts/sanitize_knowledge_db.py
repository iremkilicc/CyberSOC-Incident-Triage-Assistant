"""Create a knowledge-only index without copying runtime investigation data."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from database import DATABASE_PATH, initialize_database  # noqa: E402


def create_sanitized_index(source: Path, destination: Path = DATABASE_PATH) -> None:
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must be different files.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"Refusing to overwrite {destination}")

    source_connection = sqlite3.connect(source)
    destination_connection = sqlite3.connect(destination)
    try:
        initialize_database(destination_connection)
        for table in ("documents", "chunks"):
            columns = [row[1] for row in source_connection.execute(f"PRAGMA table_info({table})")]
            column_list = ", ".join(f'"{name}"' for name in columns)
            rows = source_connection.execute(f"SELECT {column_list} FROM {table}").fetchall()
            placeholders = ", ".join("?" for _ in columns)
            destination_connection.executemany(
                f"INSERT INTO {table} ({column_list}) VALUES ({placeholders})", rows
            )
        destination_connection.commit()
    finally:
        source_connection.close()
        destination_connection.close()


if __name__ == "__main__":
    source_path = Path(sys.argv[1]) if len(sys.argv) > 1 else PROJECT_ROOT / "data" / "cybersoc.db"
    create_sanitized_index(source_path)
    print(f"Sanitized knowledge index created: {DATABASE_PATH}")

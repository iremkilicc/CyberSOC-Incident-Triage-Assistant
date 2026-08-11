from __future__ import annotations

from uuid import uuid4

from database import (
    get_history_connection,
    initialize_history_database,
    migrate_legacy_history_if_needed,
)


def _open_history_database():
    connection = get_history_connection()
    initialize_history_database(connection)
    migrate_legacy_history_if_needed(connection)
    return connection


def create_conversation(title: str = "Yeni SOC İncelemesi") -> str:
    conversation_id = uuid4().hex
    connection = _open_history_database()

    try:
        connection.execute(
            "INSERT INTO conversations (id, title) VALUES (?, ?)",
            (conversation_id, title.strip() or "Yeni SOC İncelemesi"),
        )
        connection.commit()
        return conversation_id
    finally:
        connection.close()


def add_message(conversation_id: str, role: str, content: str) -> None:
    if role not in {"user", "assistant", "system"}:
        raise ValueError("Geçersiz mesaj rolü.")

    clean_content = content.strip()

    if not clean_content:
        raise ValueError("Boş mesaj kaydedilemez.")

    connection = _open_history_database()

    try:
        connection.execute(
            """
            INSERT INTO messages (conversation_id, role, content)
            VALUES (?, ?, ?)
            """,
            (conversation_id, role, clean_content),
        )
        connection.execute(
            """
            UPDATE conversations
            SET updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (conversation_id,),
        )
        connection.commit()
    finally:
        connection.close()


def get_messages(
    conversation_id: str,
    *,
    limit: int | None = None,
) -> list[dict[str, str]]:
    connection = _open_history_database()

    try:

        if limit is None:
            rows = connection.execute(
                """
                SELECT role, content, created_at
                FROM messages
                WHERE conversation_id = ?
                ORDER BY id ASC
                """,
                (conversation_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT role, content, created_at
                FROM (
                    SELECT id, role, content, created_at
                    FROM messages
                    WHERE conversation_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                )
                ORDER BY id ASC
                """,
                (conversation_id, max(1, limit)),
            ).fetchall()

        return [dict(row) for row in rows]
    finally:
        connection.close()


def list_conversations(limit: int = 30) -> list[dict[str, str]]:
    connection = _open_history_database()

    try:
        rows = connection.execute(
            """
            SELECT id, title, status, created_at, updated_at
            FROM conversations
            ORDER BY updated_at DESC, created_at DESC
            LIMIT ?
            """,
            (max(1, limit),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def list_conversations_with_last_reply(limit: int = 30) -> list[dict[str, str]]:
    """List conversations plus the newest assistant reply of each, in one query."""
    connection = _open_history_database()

    try:
        rows = connection.execute(
            """
            SELECT
                c.id,
                c.title,
                c.status,
                c.created_at,
                c.updated_at,
                (
                    SELECT m.content
                    FROM messages m
                    WHERE m.conversation_id = c.id AND m.role = 'assistant'
                    ORDER BY m.id DESC
                    LIMIT 1
                ) AS last_reply
            FROM conversations c
            ORDER BY c.updated_at DESC, c.created_at DESC
            LIMIT ?
            """,
            (max(1, limit),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def rename_conversation(conversation_id: str, title: str) -> None:
    clean_title = " ".join(title.split())[:80]

    if not clean_title:
        return

    connection = _open_history_database()

    try:
        connection.execute(
            """
            UPDATE conversations
            SET title = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (clean_title, conversation_id),
        )
        connection.commit()
    finally:
        connection.close()


def replace_last_assistant_message(conversation_id: str, content: str) -> bool:
    """Atomically replace the newest reply after regeneration succeeds."""
    clean_content = content.strip()

    if not clean_content:
        raise ValueError("Boş mesaj kaydedilemez.")

    connection = _open_history_database()

    try:
        cursor = connection.execute(
            """
            UPDATE messages
            SET content = ?, created_at = CURRENT_TIMESTAMP
            WHERE id = (
                SELECT id
                FROM messages
                WHERE conversation_id = ? AND role = 'assistant'
                ORDER BY id DESC
                LIMIT 1
            )
            """,
            (clean_content, conversation_id),
        )
        connection.execute(
            """
            UPDATE conversations
            SET updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (conversation_id,),
        )
        connection.commit()
        return cursor.rowcount > 0
    finally:
        connection.close()


def delete_conversation(conversation_id: str) -> None:
    connection = _open_history_database()

    try:
        connection.execute(
            "DELETE FROM conversations WHERE id = ?",
            (conversation_id,),
        )
        connection.commit()
    finally:
        connection.close()


def delete_all_conversations() -> None:
    connection = _open_history_database()

    try:
        connection.execute("DELETE FROM conversations")
        connection.commit()
    finally:
        connection.close()

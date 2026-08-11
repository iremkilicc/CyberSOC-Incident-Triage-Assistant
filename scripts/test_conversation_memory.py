from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import database  # noqa: E402
from conversation_service import (  # noqa: E402
    add_message,
    create_conversation,
    delete_conversation,
    get_messages,
    list_conversations,
    rename_conversation,
)


def main() -> None:
    original_path = database.HISTORY_DATABASE_PATH

    try:
        with TemporaryDirectory() as directory:
            database.HISTORY_DATABASE_PATH = Path(directory) / "test_conversations.db"
            conversation_id = create_conversation()
            add_message(conversation_id, "user", "Test alarmı")
            add_message(conversation_id, "assistant", "Test cevabı")
            rename_conversation(conversation_id, "PowerShell Testi")

            messages = get_messages(conversation_id)
            conversations = list_conversations()
            checks = {
                "conversation_created": any(
                    item["id"] == conversation_id for item in conversations
                ),
                "messages_saved": [item["role"] for item in messages]
                == ["user", "assistant"],
                "title_updated": any(
                    item["id"] == conversation_id
                    and item["title"] == "PowerShell Testi"
                    for item in conversations
                ),
            }

            delete_conversation(conversation_id)
            checks["conversation_deleted"] = not get_messages(conversation_id)

            for name, passed in checks.items():
                print(f"{name}: {'OK' if passed else 'FAIL'}")

            if not all(checks.values()):
                raise SystemExit(1)

            print("\nTÜM CONVERSATION MEMORY TESTLERİ BAŞARILI.")
    finally:
        database.HISTORY_DATABASE_PATH = original_path


if __name__ == "__main__":
    main()

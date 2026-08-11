from __future__ import annotations

import re
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from conversation_service import (  # noqa: E402
    add_message,
    create_conversation,
    get_messages,
    rename_conversation,
)
from local_rag_engine import LocalRAGEngine  # noqa: E402
from rag_service import format_rag_response  # noqa: E402


EXIT_COMMANDS = {"çık", "cik", "exit", "quit", "q"}
NEW_COMMANDS = {"yeni", "new", "/new"}


def has_attached_exit_command(query: str) -> bool:
    return bool(
        re.search(
            r"[\s.!?](çık|cik|exit|quit|q)\s*$",
            query,
            flags=re.IGNORECASE,
        )
    )


def main() -> None:
    engine = LocalRAGEngine(app_name="CyberSOC-Terminal-Assistant")
    conversation_id = create_conversation()
    first_message = True

    print("\n" + "=" * 70)
    print("CYBERSOC INCIDENT TRIAGE ASSISTANT")
    print("=" * 70)
    print("Bir SOC alarmı veya olay açıklaması yaz.")
    print("Yeni konuşma: 'yeni' | Programdan çıkış: 'çık'")

    while True:
        try:
            print("\n" + "-" * 70)
            query = input("Sen: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCyberSOC Assistant kapatılıyor.")
            break

        if not query:
            print("Lütfen bir olay açıklaması yaz.")
            continue

        normalized_query = query.casefold()

        if normalized_query in EXIT_COMMANDS:
            print("\nCyberSOC Assistant kapatılıyor.")
            break

        if normalized_query in NEW_COMMANDS:
            conversation_id = create_conversation()
            first_message = True
            print("Yeni SOC konuşması oluşturuldu.")
            continue

        if has_attached_exit_command(query):
            print(
                "Mesajın sonuna çıkış komutu yapışmış görünüyor. "
                "Mesaj işlenmedi; çıkmak için yalnızca 'çık' yaz."
            )
            continue

        history = get_messages(conversation_id, limit=20)
        add_message(conversation_id, "user", query)

        if first_message:
            rename_conversation(conversation_id, query[:70])
            first_message = False

        try:
            result = engine.answer(query, history=history)
            formatted_answer = format_rag_response(result.response)
            add_message(conversation_id, "assistant", formatted_answer)

            print("\n" + "=" * 70)
            print("CYBERSOC CEVABI")
            print("=" * 70)

            if result.model_alias:
                print(f"Kullanılan model: {result.model_alias}\n")

            print(formatted_answer)
        except Exception as error:
            print("\nCevap üretilemedi:")
            print(error)


if __name__ == "__main__":
    main()

from pathlib import Path


def load_markdown_files(knowledge_base_path: str):
    """
    knowledge_base klasöründeki tüm .md dosyalarını okur.
    Her dosya için path ve content bilgisini döndürür.
    """

    kb_path = Path(knowledge_base_path)
    documents = []

    for file_path in kb_path.rglob("*.md"):
        content = file_path.read_text(encoding="utf-8")

        documents.append(
            {
                "path": str(file_path),
                "content": content
            }
        )

    return documents


if __name__ == "__main__":
    docs = load_markdown_files("knowledge_base")

    print(f"Toplam okunan doküman sayısı: {len(docs)}")

    for doc in docs:
        print("-", doc["path"])
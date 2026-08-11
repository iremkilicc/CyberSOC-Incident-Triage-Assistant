import hashlib
import re
from pathlib import Path

from database import get_connection, initialize_database, serialize_embedding


PROJECT_ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE_BASE_DIR = PROJECT_ROOT / "knowledge_base"
EMBEDDING_MODEL_ALIAS = "qwen3-embedding-0.6b"
MAX_CHUNK_CHARACTERS = 1800
EMBEDDING_BATCH_SIZE = 16


SOURCE_TYPE_BY_FOLDER = {
    "mitre": "mitre_attack",
    "nist": "nist_incident_response",
    "playbooks": "soc_playbook",
    "investigation_notes": "investigation_notes",
}


def calculate_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()

    return fallback


def detect_scenario(path: Path) -> str:
    name = path.name.lower()

    if any(
        marker in name
        for marker in (
            "credential_dump",
            "credential-dump",
            "lsass",
            "t1003",
            "process_access",
            "process-access",
        )
    ):
        return "credential_dumping"

    if any(
        marker in name
        for marker in (
            "data_exfil",
            "data-exfil",
            "cloud_storage_exfiltration",
            "cloud-storage-exfiltration",
            "mass_download",
            "t1530",
            "t1560",
            "t1567_002",
        )
    ):
        return "data_exfiltration"

    if any(
        marker in name
        for marker in (
            "bec",
            "mailbox_rule",
            "mailbox-rule",
            "email_forwarding_rule",
            "t1114_003",
            "t1657",
        )
    ):
        return "bec_mailbox"

    if any(
        marker in name
        for marker in (
            "oauth",
            "cloud_identity",
            "cloud-identity",
            "t1528",
            "impossible_travel",
            "token_access",
        )
    ):
        return "cloud_identity_oauth"

    if "brute" in name or "login" in name or "t1110" in name:
        return "brute_force"

    if "phishing" in name or "email" in name or "t1566" in name:
        return "phishing"

    if (
        "powershell" in name
        or "endpoint" in name
        or "t1059" in name
        or "scripting" in name
    ):
        return "suspicious_powershell"

    return "general"


def split_large_paragraph(paragraph: str, max_characters: int) -> list[str]:
    if len(paragraph) <= max_characters:
        return [paragraph]

    pieces = []
    current_lines = []
    current_length = 0

    for line in paragraph.splitlines():
        line_length = len(line) + 1

        if current_lines and current_length + line_length > max_characters:
            pieces.append("\n".join(current_lines).strip())
            current_lines = []
            current_length = 0

        current_lines.append(line)
        current_length += line_length

    if current_lines:
        pieces.append("\n".join(current_lines).strip())

    return [piece for piece in pieces if piece]


def build_section_chunks(
    heading: str,
    section_text: str,
    max_characters: int,
) -> list[dict]:
    raw_paragraphs = re.split(r"\n\s*\n", section_text.strip())
    paragraphs = []

    for paragraph in raw_paragraphs:
        paragraph = paragraph.strip()

        if paragraph:
            paragraphs.extend(
                split_large_paragraph(paragraph, max_characters)
            )

    if not paragraphs:
        return []

    chunks = []
    current_paragraphs = []

    for paragraph in paragraphs:
        candidate_body = "\n\n".join(current_paragraphs + [paragraph])
        candidate = f"{heading}\n\n{candidate_body}".strip()

        if current_paragraphs and len(candidate) > max_characters:
            content = f"{heading}\n\n" + "\n\n".join(current_paragraphs)
            chunks.append({"heading": heading, "content": content.strip()})
            current_paragraphs = [paragraph]
        else:
            current_paragraphs.append(paragraph)

    if current_paragraphs:
        content = f"{heading}\n\n" + "\n\n".join(current_paragraphs)
        chunks.append({"heading": heading, "content": content.strip()})

    return chunks


def chunk_markdown(text: str) -> list[dict]:
    sections = []
    current_heading = "Document Overview"
    current_lines = []

    def flush_section() -> None:
        section_text = "\n".join(current_lines).strip()

        if section_text:
            sections.append((current_heading, section_text))

    for line in text.splitlines():
        heading_match = re.match(r"^(#{1,4})\s+(.+)$", line)

        if heading_match:
            flush_section()
            current_heading = heading_match.group(2).strip()
            current_lines = []
        else:
            current_lines.append(line)

    flush_section()

    chunks = []

    for heading, section_text in sections:
        chunks.extend(
            build_section_chunks(
                heading,
                section_text,
                MAX_CHUNK_CHARACTERS,
            )
        )

    for index, chunk in enumerate(chunks):
        chunk["chunk_index"] = index

    return chunks


def embed_texts(embedding_client, texts: list[str]) -> list[list[float]]:
    embeddings = []

    for start in range(0, len(texts), EMBEDDING_BATCH_SIZE):
        batch = texts[start : start + EMBEDDING_BATCH_SIZE]
        response = embedding_client.generate_embeddings(batch)

        if len(response.data) != len(batch):
            raise RuntimeError("Embedding batch size ile sonuç sayısı eşleşmedi.")

        embeddings.extend(item.embedding for item in response.data)

    return embeddings


def ingest_document(connection, path: Path, embedding_client) -> tuple[bool, int]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    relative_path = path.relative_to(PROJECT_ROOT).as_posix()
    content_hash = calculate_hash(text)

    existing = connection.execute(
        "SELECT id, content_hash FROM documents WHERE source_path = ?",
        (relative_path,),
    ).fetchone()

    if existing and existing["content_hash"] == content_hash:
        print(f"SKIP: {relative_path} değişmemiş.")
        return False, 0

    chunks = chunk_markdown(text)

    if not chunks:
        print(f"SKIP: {relative_path} için chunk oluşturulamadı.")
        return False, 0

    print(f"EMBED: {relative_path} | chunk={len(chunks)}")
    embeddings = embed_texts(
        embedding_client,
        [chunk["content"] for chunk in chunks],
    )

    source_folder = path.relative_to(KNOWLEDGE_BASE_DIR).parts[0]
    source_type = SOURCE_TYPE_BY_FOLDER.get(source_folder, "knowledge_source")
    scenario = detect_scenario(path)
    title = extract_title(text, path.stem.replace("_", " ").title())

    with connection:
        connection.execute(
            """
            INSERT INTO documents (
                source_path,
                title,
                source_type,
                scenario,
                content_hash,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(source_path) DO UPDATE SET
                title = excluded.title,
                source_type = excluded.source_type,
                scenario = excluded.scenario,
                content_hash = excluded.content_hash,
                updated_at = CURRENT_TIMESTAMP
            """,
            (relative_path, title, source_type, scenario, content_hash),
        )

        document_id = connection.execute(
            "SELECT id FROM documents WHERE source_path = ?",
            (relative_path,),
        ).fetchone()["id"]

        connection.execute(
            "DELETE FROM chunks WHERE document_id = ?",
            (document_id,),
        )

        for chunk, embedding in zip(chunks, embeddings):
            connection.execute(
                """
                INSERT INTO chunks (
                    document_id,
                    chunk_index,
                    heading,
                    content,
                    embedding,
                    embedding_dimensions,
                    embedding_model
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    document_id,
                    chunk["chunk_index"],
                    chunk["heading"],
                    chunk["content"],
                    serialize_embedding(embedding),
                    len(embedding),
                    EMBEDDING_MODEL_ALIAS,
                ),
            )

    return True, len(chunks)


def main() -> None:
    from foundry_local_sdk import Configuration, FoundryLocalManager

    markdown_files = sorted(KNOWLEDGE_BASE_DIR.rglob("*.md"))

    if not markdown_files:
        raise FileNotFoundError("knowledge_base içinde Markdown dosyası bulunamadı.")

    connection = get_connection()
    initialize_database(connection)

    config = Configuration(app_name="CyberSOC-Ingestion")
    FoundryLocalManager.initialize(config)
    manager = FoundryLocalManager.instance

    model = manager.catalog.get_model(EMBEDDING_MODEL_ALIAS)
    model_loaded = False

    try:
        print(f"Embedding modeli hazırlanıyor: {EMBEDDING_MODEL_ALIAS}")
        model.download()
        model.load()
        model_loaded = True

        embedding_client = model.get_embedding_client()
        changed_documents = 0
        total_chunks = 0

        for path in markdown_files:
            changed, chunk_count = ingest_document(
                connection,
                path,
                embedding_client,
            )

            if changed:
                changed_documents += 1
                total_chunks += chunk_count

        document_count = connection.execute(
            "SELECT COUNT(*) FROM documents"
        ).fetchone()[0]
        chunk_count = connection.execute(
            "SELECT COUNT(*) FROM chunks"
        ).fetchone()[0]

        print("\nINGESTION TAMAMLANDI")
        print(f"Bu çalıştırmada güncellenen doküman: {changed_documents}")
        print(f"Bu çalıştırmada üretilen chunk: {total_chunks}")
        print(f"Veritabanındaki toplam doküman: {document_count}")
        print(f"Veritabanındaki toplam chunk: {chunk_count}")

    finally:
        if model_loaded:
            model.unload()

        connection.close()


if __name__ == "__main__":
    main()

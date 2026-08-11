from __future__ import annotations

import argparse
import math
from dataclasses import asdict, dataclass

from database import deserialize_embedding, get_connection, initialize_database


EMBEDDING_MODEL_ALIAS = "qwen3-embedding-0.6b"
QUERY_INSTRUCTION = (
    "Given a SOC analyst query or security alert, retrieve relevant "
    "incident-response guidance, investigation fields, playbooks, and "
    "MITRE ATT&CK context."
)
DEFAULT_TOP_K = 6
DEFAULT_MIN_SIMILARITY = 0.60
DEFAULT_MAX_CHUNKS_PER_DOCUMENT = 2


@dataclass(frozen=True)
class RetrievedChunk:
    chunk_id: int
    document_id: int
    chunk_index: int
    similarity: float
    source_path: str
    title: str
    source_type: str
    scenario: str
    heading: str
    content: str

    def to_dict(self) -> dict:
        return asdict(self)


def format_query_for_embedding(query: str) -> str:
    clean_query = " ".join(query.split())

    if not clean_query:
        raise ValueError("Arama sorgusu boş olamaz.")

    return f"Instruct: {QUERY_INSTRUCTION}\nQuery: {clean_query}"


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        raise ValueError(
            "Cosine similarity için vektör boyutları eşit olmalı: "
            f"{len(left)} != {len(right)}"
        )

    dot_product = 0.0
    left_norm_squared = 0.0
    right_norm_squared = 0.0

    for left_value, right_value in zip(left, right):
        dot_product += left_value * right_value
        left_norm_squared += left_value * left_value
        right_norm_squared += right_value * right_value

    if left_norm_squared == 0.0 or right_norm_squared == 0.0:
        return 0.0

    return dot_product / math.sqrt(left_norm_squared * right_norm_squared)


class VectorRetriever:
    def __init__(self, connection, embedding_client) -> None:
        self.connection = connection
        self.embedding_client = embedding_client

    def _embed_query(self, query: str) -> list[float]:
        formatted_query = format_query_for_embedding(query)
        response = self.embedding_client.generate_embedding(formatted_query)

        if not response.data:
            raise RuntimeError("Embedding modeli sorgu vektörü döndürmedi.")

        return response.data[0].embedding

    def _load_candidates(self, scenario: str | None = None):
        parameters: list[str] = [EMBEDDING_MODEL_ALIAS]
        scenario_filter = ""

        if scenario:
            scenario_filter = "AND d.scenario IN (?, 'general')"
            parameters.append(scenario)

        return self.connection.execute(
            f"""
            SELECT
                c.id AS chunk_id,
                c.document_id,
                c.chunk_index,
                c.heading,
                c.content,
                c.embedding,
                c.embedding_dimensions,
                d.source_path,
                d.title,
                d.source_type,
                d.scenario
            FROM chunks AS c
            JOIN documents AS d ON d.id = c.document_id
            WHERE c.embedding_model = ?
            {scenario_filter}
            """,
            parameters,
        ).fetchall()

    def search(
        self,
        query: str,
        *,
        top_k: int = DEFAULT_TOP_K,
        min_similarity: float | None = DEFAULT_MIN_SIMILARITY,
        max_chunks_per_document: int = DEFAULT_MAX_CHUNKS_PER_DOCUMENT,
        scenario: str | None = None,
    ) -> list[RetrievedChunk]:
        if top_k < 1:
            raise ValueError("top_k en az 1 olmalı.")

        if max_chunks_per_document < 1:
            raise ValueError("max_chunks_per_document en az 1 olmalı.")

        query_embedding = self._embed_query(query)
        candidates = self._load_candidates(scenario=scenario)

        if not candidates:
            raise RuntimeError(
                "Aranacak embedding bulunamadı. "
                "Önce python src\\ingest_knowledge_base.py çalıştırın."
            )

        ranked: list[RetrievedChunk] = []

        for row in candidates:
            dimensions = row["embedding_dimensions"]

            if dimensions != len(query_embedding):
                continue

            stored_embedding = deserialize_embedding(
                row["embedding"],
                dimensions,
            )
            similarity = cosine_similarity(query_embedding, stored_embedding)

            ranked.append(
                RetrievedChunk(
                    chunk_id=row["chunk_id"],
                    document_id=row["document_id"],
                    chunk_index=row["chunk_index"],
                    similarity=similarity,
                    source_path=row["source_path"],
                    title=row["title"],
                    source_type=row["source_type"],
                    scenario=row["scenario"],
                    heading=row["heading"],
                    content=row["content"],
                )
            )

        ranked.sort(key=lambda item: item.similarity, reverse=True)

        selected: list[RetrievedChunk] = []
        document_counts: dict[int, int] = {}

        for item in ranked:
            if min_similarity is not None and item.similarity < min_similarity:
                continue

            current_count = document_counts.get(item.document_id, 0)

            if current_count >= max_chunks_per_document:
                continue

            selected.append(item)
            document_counts[item.document_id] = current_count + 1

            if len(selected) >= top_k:
                break

        return selected


def print_results(results: list[RetrievedChunk]) -> None:
    if not results:
        print(
            "Uygun bağlam bulunamadı. Soru bilgi tabanının dışında olabilir "
            "veya benzerlik eşiğinin altında kalmış olabilir."
        )
        return

    for index, result in enumerate(results, start=1):
        preview = " ".join(result.content.split())[:220]
        print(
            f"\n{index}. skor={result.similarity:.4f} | "
            f"senaryo={result.scenario} | tür={result.source_type}"
        )
        print(f"   kaynak={result.source_path}")
        print(f"   başlık={result.heading}")
        print(f"   içerik={preview}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CyberSOC SQLite embedding veritabanında semantic arama yapar."
    )
    parser.add_argument("query", help="SOC sorusu veya güvenlik alarmı")
    parser.add_argument("--top-k", type=int, default=DEFAULT_TOP_K)
    parser.add_argument(
        "--min-score",
        type=float,
        default=DEFAULT_MIN_SIMILARITY,
        help="Minimum cosine similarity. Ham sonuçlar için -1 kullanın.",
    )
    return parser.parse_args()


def main() -> None:
    from foundry_local_sdk import Configuration, FoundryLocalManager

    arguments = parse_arguments()
    connection = get_connection()
    initialize_database(connection)

    config = Configuration(app_name="CyberSOC-Retrieval")
    FoundryLocalManager.initialize(config)
    manager = FoundryLocalManager.instance
    model = manager.catalog.get_model(EMBEDDING_MODEL_ALIAS)
    model_loaded = False

    try:
        print(f"Embedding modeli hazırlanıyor: {EMBEDDING_MODEL_ALIAS}")
        model.download()
        model.load()
        model_loaded = True

        retriever = VectorRetriever(
            connection,
            model.get_embedding_client(),
        )
        results = retriever.search(
            arguments.query,
            top_k=arguments.top_k,
            min_similarity=arguments.min_score,
        )
        print_results(results)
    finally:
        if model_loaded:
            model.unload()

        connection.close()


if __name__ == "__main__":
    main()

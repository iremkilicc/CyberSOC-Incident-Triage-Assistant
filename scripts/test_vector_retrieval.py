from __future__ import annotations

import sys
from pathlib import Path

from foundry_local_sdk import Configuration, FoundryLocalManager


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from database import get_connection, initialize_database  # noqa: E402
from vector_retriever import (  # noqa: E402
    DEFAULT_MIN_SIMILARITY,
    EMBEDDING_MODEL_ALIAS,
    VectorRetriever,
)


TEST_CASES = [
    {
        "name": "Brute force / hesap ele geçirme",
        "query": (
            "Bir kullanıcı hesabında 10 dakika içinde farklı IP adreslerinden "
            "250 başarısız giriş ve ardından başarılı oturum açma görüldü. "
            "SOC analisti neyi kontrol etmeli?"
        ),
        "expected_scenario": "brute_force",
    },
    {
        "name": "Phishing e-postası",
        "query": (
            "Kullanıcı, kurumsal giriş sayfasını taklit eden bağlantı içeren "
            "şüpheli bir e-posta aldı ve bağlantıya tıkladı. Hangi kanıtlar "
            "toplanmalı?"
        ),
        "expected_scenario": "phishing",
    },
    {
        "name": "Şüpheli PowerShell",
        "query": (
            "Endpoint üzerinde powershell.exe -EncodedCommand ile başlayan, "
            "dış bir adrese bağlantı kuran komut tespit edildi. İlk triaj "
            "adımları nelerdir?"
        ),
        "expected_scenario": "suspicious_powershell",
    },
    {
        "name": "Bilgi tabanı dışı soru",
        "query": "İstanbul'da hafta sonu hava nasıl olacak?",
        "expected_scenario": None,
    },
    {
        "name": "Bilgi tabanı dışı yemek sorusu",
        "query": "Kolay bir çikolatalı kek tarifi verir misin?",
        "expected_scenario": None,
    },
    {
        "name": "Bilgi tabanı dışı seyahat sorusu",
        "query": "Roma için üç günlük gezi planı hazırlar mısın?",
        "expected_scenario": None,
    },
    {
        "name": "Bilgi tabanı dışı film sorusu",
        "query": "Bu akşam izlemek için bir bilim kurgu filmi öner.",
        "expected_scenario": None,
    },
    {
        "name": "Bilgi tabanı dışı matematik sorusu",
        "query": "Bir üçgenin alanı nasıl hesaplanır?",
        "expected_scenario": None,
    },
]


def print_case_results(case: dict, raw_results, accepted_results) -> bool:
    print("\n" + "=" * 78)
    print(f"TEST: {case['name']}")
    print(f"SORGU: {case['query']}")

    if raw_results:
        print("HAM İLK 5 SONUÇ:")

        for index, result in enumerate(raw_results, start=1):
            print(
                f"  {index}. {result.similarity:.4f} | "
                f"{result.scenario} | {result.source_path} | {result.heading}"
            )

    if case["expected_scenario"] is None:
        passed = not accepted_results
        decision = "ÇEKİMSER" if passed else "EŞİĞİ GEÇTİ"
        print(
            f"KARAR: {decision} | eşik={DEFAULT_MIN_SIMILARITY:.2f} | "
            f"durum={'OK' if passed else 'KALİBRASYON GEREKİYOR'}"
        )
        return passed

    if not accepted_results:
        print(
            f"KARAR: SONUÇ YOK | eşik={DEFAULT_MIN_SIMILARITY:.2f} | "
            "durum=KALİBRASYON GEREKİYOR"
        )
        return False

    top_scenario = accepted_results[0].scenario
    top_result_is_allowed = top_scenario in {
        case["expected_scenario"],
        "general",
    }
    expected_in_top_three = any(
        result.scenario == case["expected_scenario"]
        for result in accepted_results[:3]
    )
    passed = top_result_is_allowed and expected_in_top_three
    print(
        f"KARAR: top_scenario={top_scenario} | "
        f"beklenen={case['expected_scenario']} | "
        f"ilk_3_eslesmesi={'EVET' if expected_in_top_three else 'HAYIR'} | "
        f"durum={'OK' if passed else 'KONTROL'}"
    )
    return passed


def main() -> None:
    connection = get_connection()
    initialize_database(connection)

    document_count = connection.execute(
        "SELECT COUNT(*) FROM documents"
    ).fetchone()[0]
    chunk_count = connection.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]

    if document_count == 0 or chunk_count == 0:
        connection.close()
        raise RuntimeError(
            "Embedding veritabanı boş. Önce "
            "python src\\ingest_knowledge_base.py çalıştırın."
        )

    print(f"Veritabanı hazır: documents={document_count}, chunks={chunk_count}")

    config = Configuration(app_name="CyberSOC-Retrieval-Test")
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
        passed_count = 0

        for case in TEST_CASES:
            raw_results = retriever.search(
                case["query"],
                top_k=5,
                min_similarity=None,
            )
            accepted_results = [
                result
                for result in raw_results
                if result.similarity >= DEFAULT_MIN_SIMILARITY
            ]

            if print_case_results(case, raw_results, accepted_results):
                passed_count += 1

        print("\n" + "=" * 78)
        print(f"ÖZET: {passed_count}/{len(TEST_CASES)} kontrol başarılı")

        if passed_count == len(TEST_CASES):
            print("VECTOR RETRIEVAL TESTLERİ BAŞARILI.")
        else:
            print(
                "Motor çalışıyor; skor eşiği veya sorgu talimatı sonuçlara "
                "göre kalibre edilmeli."
            )
            raise SystemExit(1)
    finally:
        if model_loaded:
            model.unload()

        connection.close()


if __name__ == "__main__":
    main()

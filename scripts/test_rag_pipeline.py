from __future__ import annotations

import re
import sys
from pathlib import Path

from foundry_local_sdk import Configuration, FoundryLocalManager


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from database import get_connection, initialize_database  # noqa: E402
from rag_service import (  # noqa: E402
    FALLBACK_CHAT_MODEL_ALIAS,
    PRIMARY_CHAT_MODEL_ALIAS,
    find_missing_sections,
    format_rag_response,
    generate_grounded_answer,
)
from vector_retriever import (  # noqa: E402
    EMBEDDING_MODEL_ALIAS,
    VectorRetriever,
)


SOC_QUERY = (
    "Endpoint üzerinde powershell.exe -EncodedCommand ile başlayan bir komut "
    "çalıştı. Aynı süreç kısa süre sonra dış bir IP adresine bağlantı kurdu. "
    "Henüz kullanıcının bu işlemi başlatıp başlatmadığı bilinmiyor. Bu alarmı "
    "triaj et ve analistin toplaması gereken kanıtları belirt."
)
OUT_OF_SCOPE_QUERY = "İstanbul'da hafta sonu hava nasıl olacak?"


def prepare_chat_model(manager, alias: str):
    print(f"Chat modeli hazırlanıyor: {alias}")
    model = manager.catalog.get_model(alias)
    model.download()
    model.load()

    client = model.get_chat_client()
    client.settings.temperature = 0.0
    client.settings.max_tokens = 450
    return model, client


def main() -> None:
    connection = get_connection()
    initialize_database(connection)

    config = Configuration(app_name="CyberSOC-RAG-Pipeline-Test")
    FoundryLocalManager.initialize(config)
    manager = FoundryLocalManager.instance

    embedding_model = manager.catalog.get_model(EMBEDDING_MODEL_ALIAS)
    embedding_loaded = False
    active_chat_model = None
    active_chat_alias = None

    try:
        print(f"Embedding modeli hazırlanıyor: {EMBEDDING_MODEL_ALIAS}")
        embedding_model.download()
        embedding_model.load()
        embedding_loaded = True

        retriever = VectorRetriever(
            connection,
            embedding_model.get_embedding_client(),
        )
        soc_results = retriever.search(SOC_QUERY, top_k=3)
        out_of_scope_results = retriever.search(OUT_OF_SCOPE_QUERY, top_k=3)

        print(f"SOC sorgusu için bulunan kaynak: {len(soc_results)}")
        print(
            "Alan dışı sorgu kararı: "
            + ("ÇEKİMSER" if not out_of_scope_results else "KONTROL")
        )

        embedding_model.unload()
        embedding_loaded = False

        if not soc_results:
            raise RuntimeError("SOC sorgusu için RAG bağlamı bulunamadı.")

        active_chat_model, chat_client = prepare_chat_model(
            manager,
            PRIMARY_CHAT_MODEL_ALIAS,
        )
        active_chat_alias = PRIMARY_CHAT_MODEL_ALIAS

        try:
            rag_response = generate_grounded_answer(
                SOC_QUERY,
                soc_results,
                chat_client,
            )
        except Exception as error:
            if "cancel" not in str(error).lower():
                raise

            print(
                f"{PRIMARY_CHAT_MODEL_ALIAS} isteği iptal edildi; "
                f"fallback modele geçiliyor: {FALLBACK_CHAT_MODEL_ALIAS}"
            )
            active_chat_model.unload()
            active_chat_model = None

            active_chat_model, chat_client = prepare_chat_model(
                manager,
                FALLBACK_CHAT_MODEL_ALIAS,
            )
            active_chat_alias = FALLBACK_CHAT_MODEL_ALIAS
            rag_response = generate_grounded_answer(
                SOC_QUERY,
                soc_results,
                chat_client,
            )
        formatted_answer = format_rag_response(rag_response)

        print("\n" + "=" * 78)
        print("LOCAL RAG CEVABI")
        print("=" * 78)
        print(f"Kullanılan chat modeli: {active_chat_alias}\n")
        print(formatted_answer)

        cited_labels = set(re.findall(r"\[(K\d+)\]", rag_response.answer))
        valid_labels = {source.label for source in rag_response.sources}
        assessment_section = rag_response.answer.split(
            "## Risk ve Gerekçe",
            maxsplit=1,
        )[0]
        unsupported_actor_claim = re.search(
            r"kullanıcı.{0,45}(çalıştırdı|çalıştırıp|gerçekleştirdi|başlattı)",
            assessment_section,
            flags=re.IGNORECASE | re.DOTALL,
        )

        checks = {
            "cevap_uretildi": len(rag_response.answer) >= 100,
            "kaynak_var": bool(rag_response.sources),
            "kaynak_etiketi_kullanildi": any(
                f"[{source.label}]" in rag_response.answer
                for source in rag_response.sources
            ),
            "tum_bolumler_tamam": not find_missing_sections(
                rag_response.answer
            ),
            "citation_etiketleri_gecerli": cited_labels <= valid_labels,
            "dogrulanmamis_aktor_iddiasi_yok": unsupported_actor_claim is None,
            "grounded": rag_response.grounded,
            "alan_disi_cekimser": not out_of_scope_results,
        }

        print("\n" + "=" * 78)
        print("KONTROLLER")

        for name, passed in checks.items():
            print(f"{name}: {'OK' if passed else 'FAIL'}")

        if all(checks.values()):
            print("\nRAG PIPELINE TESTİ BAŞARILI.")
        else:
            raise RuntimeError("RAG pipeline kontrollerinden biri başarısız.")
    finally:
        if embedding_loaded:
            embedding_model.unload()

        if active_chat_model is not None:
            active_chat_model.unload()

        connection.close()


if __name__ == "__main__":
    main()

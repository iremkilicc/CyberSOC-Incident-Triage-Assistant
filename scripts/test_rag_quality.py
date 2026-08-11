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
from vector_retriever import EMBEDDING_MODEL_ALIAS, VectorRetriever  # noqa: E402


CASES = [
    {
        "name": "Brute force",
        "scenario": "brute_force",
        "query": (
            "Harici bir IP adresinden aynı kullanıcıya 10 dakika içinde "
            "250 başarısız VPN girişi ve ardından başarılı giriş görüldü. "
            "MFA sonucu ve başarılı oturumun kullanıcıya ait olup olmadığı "
            "henüz bilinmiyor. Olayı triaj et."
        ),
        "quality_terms": ("ip", "mfa", "kullanıcı", "başarılı", "oturum"),
        "forbidden_assessment": (),
    },
    {
        "name": "Phishing",
        "scenario": "phishing",
        "query": (
            "Kurumsal giriş sayfasını taklit eden bağlantı içeren bir e-posta "
            "kullanıcıya ulaştı ve kullanıcı bağlantıya tıkladı. Kimlik "
            "bilgisi girilip girilmediği bilinmiyor. Olayı triaj et."
        ),
        "quality_terms": (
            "gönderen",
            "header",
            "url",
            "tıkl",
            "kimlik",
            "credential",
        ),
        "forbidden_assessment": (),
    },
    {
        "name": "Suspicious PowerShell",
        "scenario": "suspicious_powershell",
        "query": (
            "Endpoint üzerinde powershell.exe -EncodedCommand çalıştığı ve "
            "aynı sürecin dış IP adresine bağlandığı gözlemlendi. İşlemi "
            "kullanıcının başlatıp başlatmadığı bilinmiyor. Olayı triaj et."
        ),
        "quality_terms": (
            "komut",
            "parent",
            "process",
            "kullanıcı",
            "ağ",
            "ip",
            "edr",
            "amsi",
        ),
        "forbidden_assessment": (
            r"kullanıcı.{0,45}(çalıştırdı|çalıştırıp|gerçekleştirdi|başlattı)",
        ),
    },
]


def prepare_chat_model(manager, alias: str):
    print(f"Chat modeli hazırlanıyor: {alias}")
    model = manager.catalog.get_model(alias)
    model.download()
    model.load()
    client = model.get_chat_client()
    client.settings.temperature = 0.0
    client.settings.max_tokens = 450
    return model, client


def extract_section(answer: str, title: str, next_title: str | None) -> str:
    if title not in answer:
        return ""

    section = answer.split(title, maxsplit=1)[1]

    if next_title and next_title in section:
        section = section.split(next_title, maxsplit=1)[0]

    return section.strip()


def evaluate_case(case: dict, results, response) -> tuple[bool, dict[str, bool]]:
    answer = response.answer
    assessment = extract_section(
        answer,
        "## Ön Değerlendirme",
        "## Risk ve Gerekçe",
    )
    evidence = extract_section(
        answer,
        "## Toplanacak Kanıtlar",
        "## Önerilen Aksiyonlar",
    )
    evidence_items = [
        line
        for line in evidence.splitlines()
        if line.strip().startswith("-")
    ]
    answer_lower = answer.casefold()
    quality_hits = sum(
        term.casefold() in answer_lower
        for term in case["quality_terms"]
    )
    invalid_actor_claim = any(
        re.search(pattern, assessment, flags=re.IGNORECASE | re.DOTALL)
        for pattern in case["forbidden_assessment"]
    )
    cited_labels = set(re.findall(r"\[(K\d+)\]", answer))
    valid_labels = {source.label for source in response.sources}
    retrieved_scenarios = {result.scenario for result in results[:3]}
    unsafe_action = re.search(
        r"(tekrar|yeniden)\s+çalıştır(?!madan)|komutu\s+çalıştır|"
        r"güvenlik\s+kontrolünü\s+kapat|antivirüsü\s+kapat",
        answer,
        flags=re.IGNORECASE,
    )

    checks = {
        "retrieval_scenario": case["scenario"] in retrieved_scenarios,
        "all_sections": not find_missing_sections(answer),
        "valid_citations": cited_labels <= valid_labels and bool(cited_labels),
        "evidence_item_count": 1 <= len(evidence_items) <= 3,
        "quality_terms": quality_hits >= 2,
        "neutral_actor_language": not invalid_actor_claim,
        "unsafe_execution_advice_absent": unsafe_action is None,
    }
    return all(checks.values()), checks


def main() -> None:
    connection = get_connection()
    initialize_database(connection)
    config = Configuration(app_name="CyberSOC-RAG-Quality-Test")
    FoundryLocalManager.initialize(config)
    manager = FoundryLocalManager.instance
    embedding_model = manager.catalog.get_model(EMBEDDING_MODEL_ALIAS)
    embedding_loaded = False
    chat_model = None
    chat_alias = PRIMARY_CHAT_MODEL_ALIAS

    try:
        print(f"Embedding modeli hazırlanıyor: {EMBEDDING_MODEL_ALIAS}")
        embedding_model.download()
        embedding_model.load()
        embedding_loaded = True
        retriever = VectorRetriever(
            connection,
            embedding_model.get_embedding_client(),
        )
        retrieved_by_case = {
            case["name"]: retriever.search(case["query"], top_k=3)
            for case in CASES
        }
        embedding_model.unload()
        embedding_loaded = False

        chat_model, chat_client = prepare_chat_model(manager, chat_alias)
        passed_count = 0

        for case in CASES:
            results = retrieved_by_case[case["name"]]

            try:
                response = generate_grounded_answer(
                    case["query"],
                    results,
                    chat_client,
                )
            except Exception as error:
                if "cancel" not in str(error).lower() or (
                    chat_alias == FALLBACK_CHAT_MODEL_ALIAS
                ):
                    raise

                print(
                    f"{chat_alias} isteği iptal edildi; "
                    f"{FALLBACK_CHAT_MODEL_ALIAS} modeline geçiliyor."
                )
                chat_model.unload()
                chat_alias = FALLBACK_CHAT_MODEL_ALIAS
                chat_model, chat_client = prepare_chat_model(
                    manager,
                    chat_alias,
                )
                response = generate_grounded_answer(
                    case["query"],
                    results,
                    chat_client,
                )

            passed, checks = evaluate_case(case, results, response)
            passed_count += int(passed)

            print("\n" + "=" * 78)
            print(f"RAG QUALITY: {case['name']} | model={chat_alias}")
            print("=" * 78)
            print(format_rag_response(response))
            print("\nKONTROLLER")

            for name, check_passed in checks.items():
                print(f"{name}: {'OK' if check_passed else 'FAIL'}")

        print("\n" + "=" * 78)
        print(f"RAG QUALITY ÖZETİ: {passed_count}/{len(CASES)} başarılı")

        if passed_count != len(CASES):
            raise SystemExit(1)

        print("TÜM RAG QUALITY TESTLERİ BAŞARILI.")
    finally:
        if embedding_loaded:
            embedding_model.unload()

        if chat_model is not None:
            chat_model.unload()

        connection.close()


if __name__ == "__main__":
    main()

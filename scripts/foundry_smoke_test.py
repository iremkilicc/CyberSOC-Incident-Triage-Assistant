from foundry_local_sdk import Configuration, FoundryLocalManager


CHAT_MODEL_ALIAS = "qwen3.5-2b"
EMBEDDING_MODEL_ALIAS = "qwen3-embedding-0.6b"


def main():
    print("Foundry Local smoke test başlıyor...")

    config = Configuration(app_name="CyberSOC")
    FoundryLocalManager.initialize(config)
    manager = FoundryLocalManager.instance

    print("\nExecution Provider bilgileri:")
    for ep in manager.discover_eps():
        print(f"- {ep.name} | registered={ep.is_registered}")

    print(f"\nChat modeli hazırlanıyor: {CHAT_MODEL_ALIAS}")
    chat_model = manager.catalog.get_model(CHAT_MODEL_ALIAS)
    chat_model.download()
    chat_model.load()

    chat_client = chat_model.get_chat_client()
    chat_client.settings.temperature = 0.1
    chat_client.settings.max_tokens = 300

    response = chat_client.complete_chat(
        [
            {
                "role": "user",
                "content": (
                    "Türkçe ve en fazla iki cümleyle cevap ver: "
                    "SOC triage nedir?"
                ),
            }
        ]
    )

    print("\nLOCAL CHAT CEVABI:")
    print(response.choices[0].message.content)

    chat_model.unload()
    print("\nChat modeli kapatıldı.")

    print(f"\nEmbedding modeli hazırlanıyor: {EMBEDDING_MODEL_ALIAS}")
    embedding_model = manager.catalog.get_model(EMBEDDING_MODEL_ALIAS)
    embedding_model.download()
    embedding_model.load()

    embedding_client = embedding_model.get_embedding_client()
    embedding_response = embedding_client.generate_embedding(
        "Multiple failed login attempts followed by a successful login."
    )

    vector = embedding_response.data[0].embedding

    print("\nEMBEDDING SONUCU:")
    print(f"Vektör boyutu: {len(vector)}")
    print(f"İlk 5 değer: {vector[:5]}")

    embedding_model.unload()
    print("\nEmbedding modeli kapatıldı.")
    print("\nTÜM FOUNDRY LOCAL TESTLERİ BAŞARILI.")


if __name__ == "__main__":
    main()

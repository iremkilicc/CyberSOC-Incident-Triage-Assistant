from foundry_local_sdk import Configuration, FoundryLocalManager


CHAT_MODEL_ALIAS = "qwen3.5-2b"
EMBEDDING_MODEL_ALIAS = "qwen3-embedding-0.6b"


def main() -> None:
    print("Foundry Local smoke test başlıyor...")

    config = Configuration(app_name="CyberSOC")
    FoundryLocalManager.initialize(config)
    manager = FoundryLocalManager.instance
    chat_model = manager.catalog.get_model(CHAT_MODEL_ALIAS)
    embedding_model = manager.catalog.get_model(EMBEDDING_MODEL_ALIAS)
    chat_loaded = False
    embedding_loaded = False

    try:
        print("\nExecution Provider bilgileri:")

        for ep in manager.discover_eps():
            print(f"- {ep.name} | registered={ep.is_registered}")

        print(f"\nChat modeli hazırlanıyor: {CHAT_MODEL_ALIAS}")
        chat_model.download()
        chat_model.load()
        chat_loaded = True

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
        chat_loaded = False
        print("\nChat modeli kapatıldı.")

        print(f"\nEmbedding modeli hazırlanıyor: {EMBEDDING_MODEL_ALIAS}")
        embedding_model.download()
        embedding_model.load()
        embedding_loaded = True

        embedding_client = embedding_model.get_embedding_client()
        embedding_response = embedding_client.generate_embedding(
            "Multiple failed login attempts followed by a successful login."
        )
        vector = embedding_response.data[0].embedding

        print("\nEMBEDDING SONUCU:")
        print(f"Vektör boyutu: {len(vector)}")
        print(f"İlk 5 değer: {vector[:5]}")

        if len(vector) != 1024:
            raise RuntimeError(
                f"Beklenen embedding boyutu 1024, alınan {len(vector)}."
            )

        print("\nTÜM FOUNDRY LOCAL TESTLERİ BAŞARILI.")
    finally:
        if chat_loaded:
            chat_model.unload()

        if embedding_loaded:
            embedding_model.unload()


if __name__ == "__main__":
    main()

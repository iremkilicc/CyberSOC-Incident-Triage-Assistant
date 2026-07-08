from load_knowledge_base import load_markdown_files


def score_document(query: str, document_content: str) -> int:
    """
    Query içindeki kelimeler dokümanda geçiyorsa puan verir.
    Bu çok basit bir arama sistemidir.
    """

    query_words = query.lower().replace("_", " ").split()
    document_text = document_content.lower()

    score = 0

    for word in query_words:
        if word in document_text:
            score += 1

    return score


def retrieve_relevant_documents(
    query: str,
    knowledge_base_path: str = "knowledge_base",
    top_k: int = 4
):
    """
    Query'ye en alakalı knowledge base dokümanlarını bulur.
    """

    documents = load_markdown_files(knowledge_base_path)
    scored_documents = []

    for doc in documents:
        score = score_document(query, doc["content"])

        scored_documents.append(
            {
                "path": doc["path"],
                "content": doc["content"],
                "score": score
            }
        )

    scored_documents.sort(key=lambda x: x["score"], reverse=True)

    return scored_documents[:top_k]


if __name__ == "__main__":
    test_query = "Multiple failed login attempts admin vpn successful login"

    results = retrieve_relevant_documents(test_query)

    print("Sorgu:", test_query)
    print("\nBulunan ilgili dokümanlar:")

    for result in results:
        print(f"- Skor: {result['score']} | {result['path']}")
from pathlib import Path
import re


KNOWLEDGE_BASE_DIR = Path("knowledge_base")


TOKEN_ALIASES = {
    # Brute force / login
    "login": [
        "authentication",
        "auth",
        "signin",
        "sign-in",
        "giriş",
        "giris",
    ],
    "failed": [
        "failure",
        "fail",
        "başarısız",
        "basarisiz",
        "deneme",
    ],
    "success": [
        "successful",
        "başarılı",
        "basarili",
    ],
    "vpn": [
        "remote access",
        "gateway",
    ],
    "brute": [
        "password guessing",
        "password spraying",
        "credential stuffing",
        "T1110",
    ],

    # Phishing / email
    "email": [
        "mail",
        "e-posta",
        "eposta",
        "message",
    ],
    "phishing": [
        "suspicious email",
        "şüpheli mail",
        "supheli mail",
        "şüpheli e-posta",
        "supheli e-posta",
        "credential phishing",
        "T1566",
    ],
    "link": [
        "url",
        "unknown link",
        "bilinmeyen link",
        "domain",
    ],
    "credential": [
        "credentials",
        "password",
        "parola",
        "şifre",
        "sifre",
        "credentials_entered",
    ],

    # PowerShell / endpoint
    "powershell": [
        "pwsh",
        "encodedcommand",
        "encoded command",
        "encoded",
        "script",
        "T1059",
    ],
    "command": [
        "command_line",
        "command line",
        "komut",
        "script execution",
    ],
    "process": [
        "parent_process",
        "parent process",
        "child_process",
        "endpoint",
    ],
    "network": [
        "network_connection",
        "network connection",
        "destination_ip",
        "destination_domain",
    ],
}


CATEGORY_KEYWORDS = {
    "brute_force": [
        "brute force",
        "password guessing",
        "password spraying",
        "credential stuffing",
        "failed login",
        "successful login",
        "login attempt",
        "authentication",
        "vpn",
        "admin",
        "başarısız giriş",
        "basarisiz giris",
        "başarılı giriş",
        "basarili giris",
        "giriş denemesi",
        "giris denemesi",
        "failed_attempt_count",
        "success_after_failures",
        "t1110",
    ],
    "phishing": [
        "phishing",
        "suspicious email",
        "email",
        "mail",
        "sender",
        "subject",
        "password reset",
        "unknown link",
        "credentials_entered",
        "user_clicked",
        "attachment",
        "spf",
        "dkim",
        "dmarc",
        "şüpheli mail",
        "supheli mail",
        "şüpheli e-posta",
        "supheli e-posta",
        "t1566",
    ],
    "suspicious_powershell": [
        "powershell",
        "encodedcommand",
        "encoded command",
        "command_line",
        "parent_process",
        "child_process",
        "endpoint",
        "network_connection",
        "scheduled_task",
        "registry",
        "edr",
        "amsi",
        "t1059",
    ],
}


CATEGORY_DOCUMENT_HINTS = {
    "brute_force": [
        "t1110_brute_force.md",
        "brute_force_playbook.md",
        "login_log_fields.md",
    ],
    "phishing": [
        "t1566_phishing.md",
        "phishing_playbook.md",
        "email_investigation_fields.md",
    ],
    "suspicious_powershell": [
        "t1059_command_and_scripting_interpreter.md",
        "suspicious_powershell_playbook.md",
        "endpoint_investigation_fields.md",
    ],
}


GENERAL_DOCUMENT_HINTS = [
    "nist_incident_response_summary.md",
]

def basic_tokenize(text):
    """
    Metni küçük parçalara ayırır.
    Alias genişletmesi yapmaz.
    Bu fonksiyon recursion hatasını önlemek için ayrı tutulur.
    """

    text = text.lower()
    text = text.replace("_", " ")
    text = text.replace("-", " ")

    return re.findall(r"[a-zA-Z0-9çğıöşüÇĞİÖŞÜ]+", text)


def tokenize(text):
    """
    Metni tokenlara ayırır ve alias kelimelerle genişletir.

    Önemli:
    Aliaslar tekrar tokenize() ile değil basic_tokenize() ile parçalanır.
    Böylece sonsuz recursion oluşmaz.
    """

    tokens = basic_tokenize(text)
    expanded_tokens = []

    for token in tokens:
        expanded_tokens.append(token)

        if token in TOKEN_ALIASES:
            for alias in TOKEN_ALIASES[token]:
                alias_tokens = basic_tokenize(alias)
                expanded_tokens.extend(alias_tokens)

    return expanded_tokens



def load_documents():
    """
    knowledge_base klasörü altındaki .md dosyalarını yükler.
    sample_alerts JSON dosyaları retrieval kaynağı olarak yüklenmez.
    """

    documents = []

    for path in KNOWLEDGE_BASE_DIR.rglob("*.md"):
        text = path.read_text(encoding="utf-8", errors="ignore")

        documents.append(
            {
                "path": path,
                "text": text,
                "tokens": tokenize(text),
            }
        )

    return documents


def detect_query_category(query):
    """
    Query'nin hangi SOC senaryosuna daha yakın olduğunu bulur.

    Öncelik sırası:
    1. Eğer query içinde açık category alanı varsa onu kullanır.
    2. Yoksa keyword skorlarına bakar.
    """

    query_lower = query.lower()

    # JSON sample alertlerinden gelen açık kategori bilgisi
    if "category: brute_force" in query_lower:
        return "brute_force"

    if "category: phishing" in query_lower:
        return "phishing"

    if "category: suspicious_powershell" in query_lower:
        return "suspicious_powershell"

    scores = {}

    for category, keywords in CATEGORY_KEYWORDS.items():
        score = 0

        for keyword in keywords:
            if keyword.lower() in query_lower:
                score += 1

        scores[category] = score

    best_category = max(scores, key=scores.get)

    if scores[best_category] == 0:
        return None

    return best_category

def get_document_category_boost(document_path, detected_category):
    """
    Query kategorisine uygun dokümanlara ekstra puan verir.
    Genel incident response dokümanını da destekleyici kaynak olarak öne çıkarır.
    """

    if detected_category is None:
        return 0

    document_name = document_path.name.lower()

    expected_documents = CATEGORY_DOCUMENT_HINTS.get(detected_category, [])

    if document_name in expected_documents:
        return 1000

    if document_name in GENERAL_DOCUMENT_HINTS:
        return 600

    return 0


def calculate_keyword_score(query_tokens, document_tokens):
    """
    Basit keyword eşleşme skorunu hesaplar.
    """

    document_token_set = set(document_tokens)
    score = 0

    for token in query_tokens:
        if token in document_token_set:
            score += 1

    return score


def retrieve(query, top_k=4):
    """
    Query'ye en uygun knowledge base dokümanlarını döndürür.

    Skor iki parçadan oluşur:
    - keyword eşleşme skoru
    - kategori uyum boost'u

    Bu skor saldırı olasılığı değildir.
    Sadece retrieval sıralama skorudur.
    """

    documents = load_documents()
    query_tokens = tokenize(query)
    detected_category = detect_query_category(query)

    results = []

    for document in documents:
        keyword_score = calculate_keyword_score(query_tokens, document["tokens"])
        category_boost = get_document_category_boost(
            document["path"],
            detected_category,
        )

        final_score = keyword_score + category_boost

        if final_score > 0:
            results.append((final_score, document))

    results.sort(key=lambda item: item[0], reverse=True)

    return results[:top_k]


def build_context(results, max_chars_per_doc=2500):
    """
    Retrieval sonuçlarından LLM'e verilecek context metnini oluşturur.
    """

    context_parts = []
    sources = []

    for index, (score, document) in enumerate(results, start=1):
        path = document["path"]
        text = document["text"][:max_chars_per_doc]

        context_parts.append(
            f"[SOURCE {index}]\n"
            f"Path: {path}\n"
            f"Score: {score}\n\n"
            f"Content:\n{text}\n"
        )

        sources.append(
            {
                "path": str(path),
                "score": score,
            }
        )

    context = "\n---\n\n".join(context_parts)

    return context, sources


def main():
    query = """
    Multiple failed login attempts were detected for the admin user on the vpn-gateway.
    There were 35 failed login attempts within 5 minutes.
    After the failed attempts, a successful login was observed.
    """

    results = retrieve(query, top_k=4)
    context, sources = build_context(results)

    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    output_path = output_dir / "retrieved_context.txt"
    output_path.write_text(context, encoding="utf-8")

    print("Retrieved context oluşturuldu:")
    print(output_path)

    print("\nBulunan kaynaklar:")

    for source in sources:
        print(f"- {source['path']} | kaynak eşleşme skoru: {source['score']}")


if __name__ == "__main__":
    main()
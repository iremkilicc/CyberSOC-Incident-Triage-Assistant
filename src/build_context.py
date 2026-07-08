from pathlib import Path
import re


KB_DIR = Path("knowledge_base")

QUERY = "Multiple failed login attempts admin vpn successful login"


def tokenize(text):
    """
    Metni küçük harfe çevirir, _ ve - karakterlerini boşluk yapar,
    sonra kelimelere böler.

    Örnek:
    'T1110_brute_force.md' -> {'t1110', 'brute', 'force', 'md'}
    """
    normalized = text.lower()
    normalized = normalized.replace("_", " ")
    normalized = normalized.replace("-", " ")

    return set(re.findall(r"[a-zA-Z0-9çğıöşü]+", normalized))


TOKEN_ALIASES = {
    "failed": {"failed", "failure", "başarısız", "basarisiz"},
    "success": {"success", "successful", "başarılı", "basarili"},
    "successful": {"success", "successful", "başarılı", "basarili"},
    "login": {"login", "giriş", "giris", "authentication"},
    "admin": {"admin", "privileged", "yetkili"},
    "vpn": {"vpn", "gateway", "vpn-gateway"},

    "brute": {"brute", "force", "t1110", "password", "guessing"},
    "force": {"brute", "force", "t1110", "password", "guessing"},

    "phishing": {
        "phishing",
        "t1566",
        "email",
        "mail",
        "sender",
        "subject",
        "link",
        "domain",
        "attachment",
        "credential",
        "credentials",
        "clicked",
        "user_clicked",
        "credentials_entered",
        "urgent",
        "password",
        "reset",
        "suspicious"
    },

    "email": {
        "phishing",
        "t1566",
        "email",
        "mail",
        "sender",
        "subject",
        "link",
        "domain",
        "attachment",
        "credential",
        "credentials",
        "clicked",
        "user_clicked",
        "credentials_entered",
        "urgent",
        "password",
        "reset",
        "suspicious"
    },

    "mail": {
        "phishing",
        "t1566",
        "email",
        "mail",
        "sender",
        "subject",
        "link",
        "domain",
        "attachment"
    },

    "link": {
        "phishing",
        "t1566",
        "email",
        "mail",
        "url",
        "domain",
        "user_clicked",
        "clicked"
    },

    "credentials": {
        "phishing",
        "credential",
        "credentials",
        "credentials_entered",
        "password",
        "mfa"
    },

    "powershell": {"powershell", "t1059", "command", "script", "encoded"},
    "encoded": {"powershell", "t1059", "command", "script", "encoded"},
    "command": {"powershell", "t1059", "command", "script", "command_line"},
}

def expand_tokens(tokens):
    """
    Sorgudaki bazı İngilizce kelimelerin Türkçe / teknik karşılıklarını ekler.
    Böylece 'failed login' araması 'başarısız giriş' yazan dosyaları da bulabilir.
    """
    expanded = set(tokens)

    for token in tokens:
        if token in TOKEN_ALIASES:
            expanded.update(TOKEN_ALIASES[token])

    return expanded

def read_documents():
    """
    knowledge_base klasörü altındaki tüm .md dosyalarını okur.
    Her dosya için:
    - path
    - text
    - tokens
    bilgilerini döndürür.
    """
    documents = []

    for path in KB_DIR.rglob("*.md"):
        text = path.read_text(encoding="utf-8", errors="ignore")

        document_tokens = tokenize(path.as_posix() + " " + text)

        documents.append(
            {
                "path": path,
                "text": text,
                "tokens": document_tokens,
            }
        )

    return documents


def retrieve(query, top_k=3):
    """
    Sorguya en uygun dokümanları bulur.
    Şimdilik basit kelime eşleşmesi yapıyoruz.
    """
    query_tokens = expand_tokens(tokenize(query))
    documents = read_documents()

    results = []

    for document in documents:
        score = len(query_tokens & document["tokens"])

        if score > 0:
            results.append((score, document))

    results.sort(key=lambda item: item[0], reverse=True)

    return results[:top_k]


def build_context(results, max_chars_per_doc=1200):
    """
    Bulunan dokümanların içeriğinden context oluşturur.
    Context, daha sonra LLM'e verilecek bilgi paketidir.
    """
    context_blocks = []
    sources = []

    for index, (score, document) in enumerate(results, start=1):
        path = document["path"]
        text = document["text"].strip()

        snippet = text[:max_chars_per_doc]

        block = f"""
[SOURCE {index}]
Path: {path}
Score: {score}

Content:
{snippet}
"""

        context_blocks.append(block)
        sources.append(str(path))

    final_context = "\n---\n".join(context_blocks)

    return final_context, sources


def main():
    print(f"Sorgu: {QUERY}\n")

    results = retrieve(QUERY, top_k=4)
    if not results:
        print("İlgili doküman bulunamadı.")
        return

    context, sources = build_context(results)

    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    output_path = output_dir / "retrieved_context.txt"
    output_path.write_text(context, encoding="utf-8")

    print("Seçilen kaynaklar:")

    for source in sources:
        print(f"- {source}")

    print("\nContext dosyası oluşturuldu:")
    print(output_path)


if __name__ == "__main__":
    main()
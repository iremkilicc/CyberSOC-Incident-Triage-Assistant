def build_query_from_alert(alert_text):
    """
    Kullanıcının yazdığı alert metnini daha güçlü bir arama sorgusuna çevirir.

    Amaç:
    - Kullanıcı doğal cümle yazsa bile ilgili knowledge base dosyalarını bulmak
    - Brute force, phishing ve PowerShell gibi senaryoları daha iyi yakalamak
    """

    text = alert_text.lower()
    query_parts = [alert_text]

    # Brute force / login anomaly ipuçları
    brute_force_indicators = [
        "failed login",
        "failed attempt",
        "failed attempts",
        "successful login",
        "login attempt",
        "login attempts",
        "authentication",
        "vpn",
        "admin",
        "başarısız giriş",
        "basarisiz giris",
        "başarılı giriş",
        "basarili giris",
        "giriş denemesi",
        "giris denemesi",
        "şifre denemesi",
        "sifre denemesi",
        "parola denemesi",
    ]

    if any(indicator in text for indicator in brute_force_indicators):
        query_parts.append(
            "brute force password guessing T1110 failed login successful login "
            "authentication vpn admin valid accounts source_ip"
        )

    # Phishing ipuçları
    phishing_indicators = [
        "phishing",
        "suspicious email",
        "email",
        "mail",
        "sender",
        "subject",
        "urgent",
        "password reset",
        "unknown link",
        "link",
        "domain",
        "attachment",
        "credentials",
        "credentials_entered",
        "user_clicked",
        "şüpheli mail",
        "supheli mail",
        "şüpheli e-posta",
        "supheli e-posta",
        "parola sıfırlama",
        "parola sifirlama",
        "bilinmeyen link",
    ]

    if any(indicator in text for indicator in phishing_indicators):
        query_parts.append(
            "phishing T1566 suspicious email sender subject link domain attachment "
            "credentials user_clicked credentials_entered password reset"
        )

    # Suspicious PowerShell ipuçları
    powershell_indicators = [
        "powershell",
        "encodedcommand",
        "encoded command",
        "encoded",
        "command_line",
        "command line",
        "parent_process",
        "parent process",
        "endpoint",
        "win-client",
        "network_connection",
        "network connection",
        "komut",
        "encoded powershell",
    ]

    if any(indicator in text for indicator in powershell_indicators):
        query_parts.append(
            "powershell T1059 command scripting interpreter encoded command "
            "command_line parent_process endpoint network_connection suspicious process"
        )

    return " ".join(query_parts)
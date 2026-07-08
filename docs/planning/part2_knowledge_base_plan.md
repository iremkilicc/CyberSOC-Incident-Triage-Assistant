# Part 2 - Knowledge Base Plan

## Amaç
Bu partın amacı, CyberSOC Incident Triage Assistant’ın cevap üretirken kullanacağı bilgi tabanını tasarlamaktır. Sistem kullanıcının verdiği alert, log parçası veya olay açıklamasını doğrudan kendi bilgisiyle yorumlamayacak; önce MITRE, NIST, SOC playbook ve investigation notes dokümanlarında arama yapacak, sonra cevabını bu kaynaklara dayandıracaktır.


## Klasör Yapısı
knowledge_base/
  mitre/
    T1110_brute_force.md
    T1078_valid_accounts.md
    T1566_phishing.md
    T1059_command_and_scripting_interpreter.md
    T1003_credential_dumping.md

  nist/
    nist_incident_response_summary.md

  playbooks/
    brute_force_playbook.md
    phishing_playbook.md
    suspicious_powershell_playbook.md

  investigation_notes/
    login_log_fields.md
    email_investigation_fields.md
    endpoint_investigation_fields.md

  sample_alerts/
    brute_force_alert_01.json
    phishing_alert_01.json
    powershell_alert_01.json



## Kullanılacak MITRE Teknikleri
İlk sürümde 5 MITRE ATT&CK tekniği kullanılacak:

1. T1110 - Brute Force
   Çok sayıda parola denemesi veya password guessing davranışı.

2. T1078 - Valid Accounts
   Geçerli veya ele geçirilmiş kullanıcı hesabıyla sisteme giriş yapılması.

3. T1566 - Phishing
   Kullanıcının sahte mail, link veya ek dosya ile kandırılmaya çalışılması.

4. T1059 - Command and Scripting Interpreter
   PowerShell, cmd veya benzer komut/script araçlarının kullanılması.

5. T1003 - Credential Dumping
   Sistemdeki parola veya kimlik bilgilerini elde etmeye yönelik davranışlar.



## Yazılacak NIST Özeti
NIST özeti, olay müdahalesinde savunmacının nasıl düşünmesi gerektiğini anlatacak. İlk sürümde NIST dokümanının tamamı yerine sade bir özet kullanılacak.

Dosya:
nist_incident_response_summary.md

İçerik:
- Olayı tanımla
- Etkilenen kullanıcı/sistemleri belirle
- Kanıtları koru
- Olayın ciddiyetini değerlendir
- Kontrol altına alma adımlarını düşün
- Temizleme ve toparlanma adımlarını planla
- Olay sonrası ders çıkar



## Yazılacak SOC Playbooklar
İlk sürümde 3 ana SOC playbook hazırlanacak:

1. Brute Force Playbook
   Çok sayıda başarısız giriş denemesi görüldüğünde hangi kontrollerin yapılacağını anlatır.

2. Phishing Playbook
   Şüpheli mail veya link bildirildiğinde hangi kontrollerin yapılacağını anlatır.

3. Suspicious PowerShell Playbook
   Windows cihazda şüpheli PowerShell komutu çalıştığında hangi kontrollerin yapılacağını anlatır.



## Investigation Notes
Investigation notes dosyaları, olayları analiz ederken hangi alanlara bakılacağını kısa listeler halinde tutar.

login_log_fields.md:
- user
- source_ip
- timestamp
- login_status
- failed_attempt_count
- successful_login_after_failure
- location
- device

email_investigation_fields.md:
- sender
- recipient
- subject
- link
- attachment
- email_header
- domain
- user_clicked
- credentials_entered

endpoint_investigation_fields.md:
- user
- command_line
- parent_process
- process_name
- encoded_command
- endpoint_name
- network_connection
- related_alerts



## Sample Alerts
Sample alerts, sistemi test etmek ve final demosunda kullanmak için hazırlanacak sahte olay örnekleridir. Gerçek şirket logu, gerçek kullanıcı bilgisi veya hassas veri kullanılmayacak.

İlk örnekler:
- brute_force_alert_01.json
{
  "alert_name": "Multiple Failed Login Attempts",
  "user": "admin",
  "source_ip": "192.168.1.25",
  "failed_attempts": 35,
  "time_window": "5 minutes",
  "successful_login_after_failures": true,
  "target_system": "vpn-gateway",
  "severity": "medium"
}

- phishing_alert_01.json
{
  "alert_name": "Suspicious Email Reported",
  "user": "ayse@example.local",
  "sender": "security-update@example-alert.local",
  "subject": "Urgent Password Reset Required",
  "contains_link": true,
  "unknown_domain": true,
  "attachment": false,
  "user_clicked": "unknown",
  "credentials_entered": "unknown"
}

- powershell_alert_01.json
{
  "alert_name": "Encoded PowerShell Command",
  "user": "standard_user",
  "endpoint": "WIN-CLIENT-01",
  "command_type": "encoded",
  "command_line": "powershell.exe -EncodedCommand <redacted>",
  "parent_process": "unknown",
  "network_connection": "unknown",
  "severity": "medium"
}



## İlk Hedef
İlk hedef, 3 ana demo senaryosunu destekleyecek kadar temiz bir bilgi tabanı oluşturmaktır:

1. Brute Force
2. Phishing
3. Suspicious PowerShell

Bu üç senaryo için MITRE notları, playbooklar, investigation notes ve sample alertler hazırlanacaktır.


## Sonraki Genişletme
İlk sürüm çalıştıktan sonra bilgi tabanı şu konularla genişletilebilir:

- Valid Accounts
- Credential Dumping
- Suspicious Network Connection
- Malware / Suspicious File Activity
- VPN login anomalies
- Impossible travel login


## Başarı Kriterleri

- Sistem 3 ana demo senaryosunda doğru olay tipini yorumlayabilmeli.
- Cevapta en az 1 MITRE tekniği önerebilmeli.
- İlk kontrol adımlarını listeleyebilmeli.
- Kullanılan kaynak dosyaları gösterebilmeli.
- Bilgi yetersizse kesin konuşmak yerine “kaynaklarda yeterli bilgi yok” diyebilmeli.
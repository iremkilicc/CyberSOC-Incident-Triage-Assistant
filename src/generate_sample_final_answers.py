from pathlib import Path


OUTPUT_DIR = Path("outputs/sample_final_answers")


FINAL_ANSWERS = {
    "sample_final_answer_bruteforce.md": r"""
# Sample Final Answer - Brute Force / Suspicious Login

## 1. Olayı İnsan Dilinde Açıklama

Bu olayda `admin` hesabı için VPN gateway üzerinde kısa süre içinde çok sayıda başarısız giriş denemesi görülüyor. 5 dakika içinde 35 başarısız deneme yapılmış ve ardından başarılı bir giriş oluşmuş.

Basitçe: Birisi admin hesabına tekrar tekrar girmeyi denemiş ve sonunda giriş başarılı olmuş olabilir.

## 2. İlk İzlenim

Bu olay brute force, password guessing veya geçerli hesap kullanımı ihtimaline benzeyebilir.

Ancak tek başına kesin saldırı demek doğru değildir. Kullanıcı şifresini unutmuş, eski bir cihaz otomatik deneme yapmış veya bir servis yanlış yapılandırılmış olabilir.

## 3. Olası Senaryolar

- Gerçek brute force / password guessing denemesi olabilir.
- Başarısız denemelerden sonra başarılı login olduğu için valid account abuse ihtimali değerlendirilebilir.
- Kullanıcı şifresini birkaç kez yanlış girip sonra doğru girmiş olabilir.
- VPN client veya mobil cihaz eski parola ile otomatik deneme yapıyor olabilir.
- Yanlış yapılandırılmış servis hesabı tekrar tekrar login deniyor olabilir.

## 4. MITRE ATT&CK Eşleşmesi

Olası MITRE ATT&CK eşleşmesi:

- T1110 - Brute Force

Başarılı giriş sonrası aktiviteler şüpheliyse valid account abuse ihtimali de ayrıca değerlendirilmelidir.

## 5. Bu Yorumu Destekleyen Kanıtlar

- Hedef kullanıcı `admin`.
- Hedef sistem `vpn-gateway`.
- 5 dakika içinde 35 başarısız giriş denemesi var.
- Başarısız denemelerden sonra başarılı giriş görülmüş.
- Olay authentication/login davranışıyla ilgili.
- Source IP bilgisi mevcut.
- Alert seviyesi medium olarak belirtilmiş.

## 6. Risk Artıran Durumlar

- Hedef hesabın admin olması.
- VPN gateway gibi dış erişim noktasının hedeflenmesi.
- Kısa sürede çok sayıda başarısız deneme olması.
- Başarısız denemelerden sonra başarılı giriş olması.
- MFA durumunun bilinmemesi.
- Başarılı login sonrası aktivitelerin henüz bilinmemesi.

## 7. Risk Düşüren veya False Positive Olabilecek Durumlar

- Kullanıcı şifresini unutmuş olabilir.
- Kullanıcı sonunda doğru parolayı hatırlamış olabilir.
- VPN istemcisi eski parola ile otomatik deneme yapmış olabilir.
- Mobil cihaz eski credential ile tekrar tekrar authentication deniyor olabilir.
- SSO veya authentication servisinde geçici hata oluşmuş olabilir.
- Kullanıcı normal cihaz ve lokasyondan giriş yapmış olabilir.

## 8. Eksik Bilgiler

- Başarılı giriş sonrası kullanıcı ne yaptı?
- Source IP daha önce görülmüş mü?
- Source IP başka hesapları da denemiş mi?
- Kullanıcı normalde VPN kullanıyor mu?
- Giriş normal saat, cihaz ve lokasyondan mı?
- MFA aktif mi?
- MFA başarılı mı, başarısız mı?
- Kullanıcı bu girişleri kendisinin yaptığını doğruluyor mu?
- Aynı zaman aralığında başka alert var mı?

## 9. SOC Analyst İçin Adım Adım Kontrol Planı

1. Kullanıcının kritik/yetkili hesap olup olmadığını kontrol et.
2. Başarısız deneme sayısını ve zaman aralığını doğrula.
3. Başarılı girişin aynı source IP üzerinden olup olmadığını kontrol et.
4. Source IP geçmişine bak.
5. Aynı IP başka hesapları denemiş mi kontrol et.
6. MFA durumunu incele.
7. Başarılı login sonrası aktiviteleri kontrol et.
8. Kullanıcının normal cihaz, lokasyon ve saat bilgisiyle karşılaştır.
9. Kullanıcı doğrulaması yap.
10. Başka endpoint, email veya network alerti var mı bak.

## 10. Ne Zaman Incident'a Yükseltilir?

- Kullanıcı başarılı girişi reddederse.
- Başarılı giriş sonrası şüpheli aktivite varsa.
- Aynı IP başka hesapları da denemişse.
- MFA bypass veya onaylanmamış MFA kabulü varsa.
- Admin hesabıyla yetki değişikliği veya hassas veri erişimi varsa.
- Aynı olay başka güvenlik alertleriyle ilişkiliyse.

## 11. Önerilen İlk Müdahale

İlk aşamada kanıt toplanmalı ve olay doğrulanmalıdır.

Önerilen güvenli adımlar:

- Başarılı login sonrası aktiviteleri incele.
- Source IP ve MFA durumunu kontrol et.
- Kullanıcı doğrulaması yap.
- Aynı IP’nin başka hesapları deneyip denemediğini araştır.
- Gerekirse insan analiste veya incident response ekibine yükselt.

Otomatik hesap kapatma, IP engelleme veya yıkıcı aksiyon önerilmemelidir.

## 12. Kullanılan Kaynaklar

- T1110_brute_force.md
- brute_force_playbook.md
- login_log_fields.md
- nist_incident_response_summary.md

## 13. Güven Düzeyi

Güven düzeyi: Orta-yüksek

Çünkü brute force davranışını destekleyen güçlü kanıtlar var. Ancak kesin saldırı kararı için source IP geçmişi, MFA durumu, kullanıcı doğrulaması ve başarılı login sonrası aktiviteler eksik.
""",

    "sample_final_answer_phishing.md": r"""
# Sample Final Answer - Phishing / Suspicious Email

## 1. Olayı İnsan Dilinde Açıklama

Bu olayda kullanıcıya şüpheli bir e-posta gelmiş. E-posta acil parola sıfırlama teması taşıyor ve bilinmeyen bir link içeriyor.

Basitçe: Kullanıcı kandırılarak sahte bir sayfaya yönlendirilmeye çalışılmış olabilir.

## 2. İlk İzlenim

Bu olay credential phishing ihtimaline benzeyebilir.

Ancak kesin karar için kullanıcının linke tıklayıp tıklamadığı, credential girip girmediği, URL reputation sonucu ve email authentication bilgileri kontrol edilmelidir.

## 3. Olası Senaryolar

- Credential phishing girişimi olabilir.
- Gerçek bir servis parola sıfırlama maili göndermiş olabilir.
- Mail spam veya pazarlama otomasyonu olabilir.
- Kullanıcı maili şüpheli sanmış ama tıklamamış olabilir.
- Gönderen domain veya mail altyapısı yanlış yapılandırılmış olabilir.

## 4. MITRE ATT&CK Eşleşmesi

Olası MITRE ATT&CK eşleşmesi:

- T1566 - Phishing

Eğer kullanıcı credential girdiyse credential phishing ve account compromise ihtimali ayrıca değerlendirilmelidir.

## 5. Bu Yorumu Destekleyen Kanıtlar

- E-posta password reset / account verification teması taşıyor.
- Bilinmeyen link içeriyor.
- Kullanıcı etkileşimi bilinmiyor.
- Sender ve reply-to bilgileri kontrol gerektiriyor.
- SPF, DKIM veya DMARC sorunları varsa risk artar.
- Mail kullanıcıyı hızlı aksiyon almaya yönlendiriyor olabilir.

## 6. Risk Artıran Durumlar

- Acil parola sıfırlama teması.
- Bilinmeyen link.
- Display name ile sender domain uyumsuzluğu ihtimali.
- Reply-to adresinin farklı olması.
- SPF, DKIM veya DMARC fail sonucu.
- Kullanıcının linke tıklamış olması.
- Kullanıcının credential girmiş olması.
- Aynı mailin başka kullanıcılara da gitmiş olması.

## 7. Risk Düşüren veya False Positive Olabilecek Durumlar

- Mail gerçek bir servis tarafından gönderilmiş olabilir.
- Kullanıcı maili tıklamadan raporlamış olabilir.
- Mail gateway tarafından karantinaya alınmış olabilir.
- Kullanıcı credential girmemiş olabilir.
- Link güvenlik servisi veya kurumsal redirect içeriyor olabilir.
- Üçüncü taraf meşru servis farklı mail altyapısı kullanıyor olabilir.

## 8. Eksik Bilgiler

- Mail kullanıcıya ulaştı mı?
- Kullanıcı linke tıkladı mı?
- Kullanıcı credential girdi mi?
- URL reputation sonucu nedir?
- Landing page sahte login sayfası mı?
- SPF, DKIM ve DMARC sonuçları ne?
- Aynı mail başka kullanıcılara da gitti mi?
- Tıklama sonrası suspicious login oluştu mu?
- Attachment var mıydı?
- Kullanıcı bu e-postayı bekliyor muydu?

## 9. SOC Analyst İçin Adım Adım Kontrol Planı

1. Mailin delivery status bilgisini kontrol et.
2. Sender, display name, reply-to ve return-path bilgilerini incele.
3. SPF, DKIM ve DMARC sonuçlarını kontrol et.
4. Subject ve body içinde sosyal mühendislik göstergesi var mı bak.
5. Linkin gerçek hedefini ve reputation sonucunu kontrol et.
6. Landing page login formu gösteriyor mu incele.
7. Kullanıcının tıklama durumunu kontrol et.
8. Credential girilip girilmediğini doğrula.
9. Aynı mail başka mailboxlarda var mı araştır.
10. Tıklama sonrası login ve MFA loglarını incele.

## 10. Ne Zaman Incident'a Yükseltilir?

- Kullanıcı credential girdiyse.
- Kullanıcı MFA kodu girdiyse veya onayladıysa.
- Tıklama sonrası suspicious successful login varsa.
- Aynı mail çok sayıda kullanıcıya ulaştıysa.
- Birden fazla kullanıcı linke tıkladıysa.
- URL veya attachment malicious çıkarsa.
- Kullanıcı hesabında mailbox rule veya forwarding rule oluştuysa.

## 11. Önerilen İlk Müdahale

İlk aşamada e-posta, link, kullanıcı etkileşimi ve kapsam bilgileri doğrulanmalıdır.

Önerilen güvenli adımlar:

- Mail metadata bilgisini topla.
- URL ve domain reputation kontrolü yap.
- Kullanıcıya linke tıklayıp tıklamadığını sor.
- Tıklama sonrası login loglarını incele.
- Aynı IOC’lerin başka kullanıcı ve sistemlerde görülüp görülmediğini araştır.
- Gerekirse incident response ekibine yükselt.

Kanıt olmadan otomatik hesap kapatma, domain engelleme veya yıkıcı aksiyon önerilmemelidir.

## 12. Kullanılan Kaynaklar

- T1566_phishing.md
- phishing_playbook.md
- email_investigation_fields.md
- nist_incident_response_summary.md

## 13. Güven Düzeyi

Güven düzeyi: Orta

Çünkü phishing göstergeleri var ancak kullanıcı tıklama, credential girişi, URL reputation ve post-click login bilgileri olmadan kesin incident kararı verilemez.
""",

    "sample_final_answer_powershell.md": r"""
# Sample Final Answer - Suspicious PowerShell / Endpoint Execution

## 1. Olayı İnsan Dilinde Açıklama

Bu olayda standart bir kullanıcı cihazında encoded PowerShell komutu çalıştırılmış. Parent process ve network connection bilgisi bilinmiyor.

Basitçe: Cihazda okunması zorlaştırılmış bir PowerShell komutu çalışmış ve bunun meşru mu yoksa şüpheli mi olduğu araştırılmalı.

## 2. İlk İzlenim

Bu olay suspicious PowerShell veya command-line anomaly olarak değerlendirilebilir.

PowerShell tek başına zararlı değildir. Ancak encoded command, standart kullanıcı ve bilinmeyen parent process birleştiğinde risk artar.

## 3. Olası Senaryolar

- Meşru IT veya management aracı encoded PowerShell çalıştırmış olabilir.
- Kullanıcı teknik bir işlem yapmış olabilir.
- Phishing attachment veya link sonrası PowerShell çalışmış olabilir.
- Zararlı script veya payload çalıştırma girişimi olabilir.
- Suspicious login sonrası endpoint üzerinde komut çalıştırılmış olabilir.

## 4. MITRE ATT&CK Eşleşmesi

Olası MITRE ATT&CK eşleşmesi:

- T1059 - Command and Scripting Interpreter

PowerShell özelinde execution davranışı değerlendirilebilir. Ancak kesin malicious execution demek için ek kanıt gerekir.

## 5. Bu Yorumu Destekleyen Kanıtlar

- Process adı `powershell.exe`.
- Komut satırında `EncodedCommand` var.
- Kullanıcı standart kullanıcı.
- Parent process bilinmiyor.
- Network connection durumu bilinmiyor.
- Dosya, registry veya scheduled task etkisi henüz bilinmiyor.

## 6. Risk Artıran Durumlar

- Encoded PowerShell kullanımı.
- Standart kullanıcı bağlamında çalışması.
- Parent process bilgisinin unknown olması.
- Network connection bilgisinin unknown olması.
- Komutun ne yaptığının henüz bilinmemesi.
- Aynı zamanda phishing veya suspicious login alerti varsa risk artar.
- EDR/AV/AMSI detection varsa risk artar.

## 7. Risk Düşüren veya False Positive Olabilecek Durumlar

- IT yönetim aracı PowerShell kullanmış olabilir.
- Software deployment veya monitoring agent çalıştırmış olabilir.
- Kurumsal otomasyon aracı encoded command kullanmış olabilir.
- Parent process güvenilir bir management agent olabilir.
- Network bağlantısı yoksa veya internal/güvenilir hedefe ise risk düşebilir.
- EDR/AV/AMSI malicious detection yoksa risk düşebilir.

## 8. Eksik Bilgiler

- Parent process nedir?
- Encoded command decode edildiğinde ne yapıyor?
- Network bağlantısı var mı?
- Destination IP/domain nedir?
- Dosya oluşturuldu mu?
- Registry değişikliği var mı?
- Scheduled task veya service oluşturuldu mu?
- Child process oluştu mu?
- EDR/AV/AMSI tespiti var mı?
- Kullanıcı veya IT ekibi bu çalıştırmayı doğruluyor mu?
- Aynı komut başka endpointlerde görüldü mü?

## 9. SOC Analyst İçin Adım Adım Kontrol Planı

1. Hostname ve kullanıcı bilgisini doğrula.
2. Kullanıcının rolünü ve normal PowerShell kullanımını kontrol et.
3. Full command line bilgisini incele.
4. Encoded command içeriğini savunma amacıyla okunabilir hale getirip davranışı anlamaya çalış.
5. Parent process bilgisini kontrol et.
6. Child process oluşmuş mu bak.
7. Network connection var mı kontrol et.
8. Destination IP/domain reputation bilgisine bak.
9. Dosya, registry, scheduled task ve service değişikliklerini araştır.
10. EDR/AV/AMSI sonuçlarını kontrol et.
11. Phishing veya suspicious login ile zaman ilişkisi var mı bak.
12. Kullanıcı veya IT ekibiyle meşru kullanım doğrulaması yap.

## 10. Ne Zaman Incident'a Yükseltilir?

- Kullanıcı çalıştırmayı reddederse.
- Parent process Office, browser veya email client ise.
- PowerShell dış şüpheli IP/domain ile bağlantı kurduysa.
- Komut uzak içerik indirip çalıştırdıysa.
- EDR/AV/AMSI malicious tespit verdiyse.
- Persistence göstergesi varsa.
- Scheduled task, service veya registry değişikliği şüpheliyse.
- Olay phishing tıklaması sonrası oluştuysa.
- Aynı IOC birden fazla endpointte görülüyorsa.

## 11. Önerilen İlk Müdahale

İlk aşamada process tree, command line, network bağlantıları ve EDR kanıtları toplanmalıdır.

Önerilen güvenli adımlar:

- Process tree bilgisini çıkar.
- Parent ve child process ilişkisini incele.
- Network hedeflerini kontrol et.
- Dosya ve registry etkilerini araştır.
- EDR/AV/AMSI sonuçlarını değerlendir.
- Kullanıcı veya IT ekibiyle doğrulama yap.
- Gerekirse incident response ekibine yükselt.

Kanıt olmadan process sonlandırma, dosya silme veya hesap kapatma önerilmemelidir.

## 12. Kullanılan Kaynaklar

- T1059_command_and_scripting_interpreter.md
- suspicious_powershell_playbook.md
- endpoint_investigation_fields.md
- nist_incident_response_summary.md

## 13. Güven Düzeyi

Güven düzeyi: Orta

Çünkü encoded PowerShell ve standart kullanıcı bağlamı şüpheli göstergelerdir. Ancak parent process, network bağlantısı, EDR detection ve post-execution etkiler bilinmeden kesin malicious demek doğru değildir.
""",
}


def write_final_answer(file_name, content):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    output_path = OUTPUT_DIR / file_name
    output_path.write_text(content.strip() + "\n", encoding="utf-8")

    print(f"Created: {output_path}")


def main():
    print("Generating CyberSOC sample final answers...")
    print("=" * 70)

    for file_name, content in FINAL_ANSWERS.items():
        write_final_answer(file_name, content)

    print("=" * 70)
    print(f"Done. Total final answers created: {len(FINAL_ANSWERS)}")
    print(f"Output directory: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
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

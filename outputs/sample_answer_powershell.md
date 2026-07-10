# Sample Answer - Suspicious PowerShell Alert

## 1. Olayı İnsan Dilinde Açıklama

Bu alert, `WIN-CLIENT-01` adlı Windows cihazında standart bir kullanıcının encoded yani gizlenmiş/şifrelenmiş görünümlü bir PowerShell komutu çalıştırdığını gösteriyor. Komut satırında `powershell.exe -EncodedCommand` ifadesi var. PowerShell’i hangi process’in başlattığı ve sonrasında ağ bağlantısı olup olmadığı bilinmiyor.

Basitçe: Normal bir kullanıcı hesabı altında gizlenmiş PowerShell komutu çalışmış; bu nedenle olay incelenmelidir.

## 2. İlk İzlenim

Bu olay şüpheli PowerShell kullanımı olabilir. Encoded command kullanılması, standart kullanıcı hesabı ve parent process bilgisinin bilinmemesi nedeniyle dikkat gerektirir.

Ancak PowerShell tek başına zararlı değildir. Sistem yöneticileri, kurumsal araçlar veya yazılım kurulumları da PowerShell kullanabilir.

## 3. Olası Senaryolar

- **Şüpheli komut/script çalıştırma:** Encoded PowerShell komutu kötüye kullanım göstergesi olabilir.
- **Phishing sonrası komut çalışması:** Kullanıcı bir linke veya dosyaya tıkladıktan sonra PowerShell çalışmış olabilir.
- **Kurumsal IT işlemi:** Yönetim aracı, güvenlik aracı veya yazılım kurulumu PowerShell kullanmış olabilir.
- **False Positive:** Kullanıcı veya sistem yasal bir işlem yapmış olabilir.

## 4. MITRE ATT&CK Eşleşmesi

Olası MITRE ATT&CK eşleşmesi:

- T1059 - Command and Scripting Interpreter

Alt bağlam olarak PowerShell kullanımı değerlendirilebilir.

## 5. Bu Yorumu Destekleyen Kanıtlar

- Standart kullanıcı hesabı PowerShell çalıştırmış.
- Komut satırında `powershell.exe -EncodedCommand` var.
- Encoded command kullanılmış.
- Endpoint adı mevcut: `WIN-CLIENT-01`.
- `parent_process` bilinmiyor.
- `network_connection` bilinmiyor.
- Alert seviyesi `medium`.

## 6. Risk Artıran Durumlar

- Encoded command kullanılması.
- Komutu standart kullanıcının çalıştırması.
- Parent process bilgisinin bilinmemesi.
- Network connection durumunun bilinmemesi.
- Komutun gerçek içeriğinin henüz incelenmemiş olması.
- PowerShell’in phishing veya şüpheli dosya sonrası çalışmış olma ihtimali.

## 7. Risk Düşüren veya False Positive Olabilecek Durumlar

- Kurumsal IT aracı PowerShell kullanıyor olabilir.
- Yazılım kurulumu veya güncelleme PowerShell çalıştırmış olabilir.
- Güvenlik aracı otomatik kontrol yapmış olabilir.
- Sistem yöneticisi bakım işlemi yapıyor olabilir.
- Kullanıcı teknik bir işlem için PowerShell kullanmış olabilir.

## 8. Eksik Bilgiler

- Encoded komutun decode edilmiş gerçek içeriği nedir?
- PowerShell’i hangi parent process başlattı?
- PowerShell sonrası dış ağ bağlantısı oluştu mu?
- Komut dosya indirme veya yeni process başlatma davranışı gösterdi mi?
- Kullanıcı normalde PowerShell kullanır mı?
- Aynı cihazda başka alert var mı?
- Kullanıcı yakın zamanda phishing maili açtı mı?
- Endpoint üzerinde process tree bilgisi mevcut mu?

## 9. SOC Analyst İçin Adım Adım Kontrol Planı

1. Komutu çalıştıran kullanıcı hesabını doğrula.
2. Kullanıcının normalde PowerShell kullanıp kullanmadığını kontrol et.
3. `command_line` bilgisini incele.
4. Encoded komutun decode edilmiş içeriğini güvenli ortamda analiz et.
5. Parent process bilgisini bul.
6. Parent process Word, Excel, browser veya bilinmeyen process mi kontrol et.
7. Komut sonrası network connection oluşmuş mu incele.
8. Komut dosya indirme, yeni process başlatma veya persistence davranışı göstermiş mi bak.
9. Aynı endpoint üzerinde başka alert var mı kontrol et.
10. Kullanıcının yakın zamanda phishing maili açıp açmadığını araştır.
11. Bulgular şüpheliyse olayı incident olarak yükseltmeyi değerlendir.

## 10. Ne Zaman Incident'a Yükseltilir?

- Decode edilmiş komut zararlı veya şüpheli davranış içeriyorsa.
- Parent process Word, Excel, browser veya bilinmeyen bir process ise.
- PowerShell sonrası dış IP veya bilinmeyen domaine bağlantı oluşmuşsa.
- Komut dosya indirme veya başka process başlatma davranışı göstermişse.
- Aynı cihazda malware, phishing veya credential alertleri varsa.
- Kullanıcı bu işlemi kendisinin yapmadığını söylüyorsa.

## 11. Önerilen İlk Müdahale

Öncelikle komutun içeriği, parent process, endpoint geçmişi ve network bağlantıları incelenmelidir. Kanıtlar güçlenmeden otomatik izolasyon, process sonlandırma veya dosya silme önerilmemelidir.

Olay orta öncelikle incelenmeli; komut içeriği ve davranış zinciri şüpheli çıkarsa incident olarak yükseltilmelidir.

## 12. Kullanılan Kaynaklar

- knowledge_base/mitre/T1059_command_and_scripting_interpreter.md
- knowledge_base/investigation_notes/endpoint_investigation_fields.md
- knowledge_base/playbooks/suspicious_powershell_playbook.md
- knowledge_base/nist/nist_incident_response_summary.md

## 13. Güven Düzeyi

**Orta.**

Encoded PowerShell kullanımı ve standart kullanıcı hesabı olayın incelenmesini gerektirir. Ancak parent process, network connection, decode edilmiş komut içeriği ve endpoint üzerindeki diğer aktiviteler bilinmediği için kesin kötü niyetli demek doğru değildir.

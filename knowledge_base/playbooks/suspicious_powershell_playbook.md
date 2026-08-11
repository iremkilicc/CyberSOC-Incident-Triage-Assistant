# Suspicious PowerShell SOC Playbook

## Amaç

Bu playbook, endpoint üzerinde görülen suspicious PowerShell, encoded command, command-line anomaly, suspicious script execution ve endpoint process alertlerinde SOC analyst'in nasıl düşünmesi gerektiğini açıklar.

PowerShell tek başına zararlı değildir. Windows ortamında yönetim, otomasyon, yazılım dağıtımı, güvenlik araçları ve sistem bakımı için sıkça kullanılır.

Ancak bazı PowerShell kullanım şekilleri saldırı davranışına benzeyebilir:

- Encoded veya obfuscated komut
- Office, browser veya email client üzerinden PowerShell başlaması
- Dış IP/domain bağlantısı
- Uzak script indirme
- Persistence davranışı
- EDR/AV/AMSI tespiti
- Phishing veya suspicious login sonrası PowerShell çalışması

Amaç, otomatik olarak “malware” demek değil, kanıtları toplayarak olayın meşru yönetim aktivitesi mi yoksa şüpheli davranış mı olduğunu belirlemektir.

---

## Kapsam

Bu playbook şu olaylarda kullanılabilir:

- Encoded PowerShell command alerti
- Suspicious process execution
- PowerShell command line anomaly
- PowerShell network connection
- Office dosyası sonrası PowerShell çalışması
- Browser download sonrası script execution
- Email attachment açılması sonrası PowerShell
- EDR tarafından suspicious script alerti
- PowerShell ile dosya indirme veya çalıştırma şüphesi
- PowerShell sonrası scheduled task, registry veya service değişikliği
- PowerShell'in phishing, brute force veya suspicious login olaylarıyla ilişkili olması

---

## Temel Kavramlar

### PowerShell

PowerShell, Windows sistemlerde yönetim ve otomasyon için kullanılan güçlü bir komut satırı ve scripting aracıdır.

Meşru kullanım örnekleri:

- Sistem yönetimi
- Kullanıcı veya servis kontrolü
- Yazılım kurulum/güncelleme
- Log toplama
- Monitoring
- Güvenlik ekibi scriptleri
- IT otomasyon araçları

Şüpheli kullanım örnekleri:

- Encoded command
- Obfuscated komut
- Dış URL'den script çekme
- Hidden window kullanımı
- Execution policy bypass davranışı
- Office dosyasından PowerShell başlatılması
- PowerShell sonrası unknown network connection

---

### Encoded Command

Encoded command, PowerShell komutunun okunması zor hale getirilmiş biçimde çalıştırılmasıdır.

Bu tek başına kesin zararlı değildir. Bazı yönetim araçları da encoded komut kullanabilir.

Risk şu durumlarda artar:

- Standart kullanıcı çalıştırdıysa
- Parent process Office, browser veya email client ise
- Komut dış URL/IP ile bağlantı kuruyorsa
- Komut dosya indiriyor veya çalıştırıyorsa
- Komut obfuscated ve açıklanamıyorsa
- EDR/AV/AMSI aynı süreçte alert üretmişse

---

### Parent Process

Parent process, PowerShell'i başlatan üst process'tir.

Bu alan çok kritiktir çünkü PowerShell'in neden çalıştığını anlamaya yardım eder.

Daha normal görülebilecek parent örnekleri:

- explorer.exe
- cmd.exe
- Windows Terminal
- management agent
- software deployment tool
- monitoring agent
- admin automation tool

Daha şüpheli olabilecek parent örnekleri:

- winword.exe
- excel.exe
- outlook.exe
- chrome.exe
- msedge.exe
- firefox.exe
- 7z.exe
- winrar.exe
- wscript.exe
- mshta.exe
- rundll32.exe

Özellikle Office veya email client üzerinden PowerShell başlaması phishing attachment veya macro davranışıyla ilişkili olabilir.

---

### Network Connection

PowerShell'in network bağlantısı kurması tek başına kesin kötü değildir. Meşru scriptler de update veya internal service için bağlantı kurabilir.

Ancak şu durumlarda risk artar:

- Dış IP veya bilinmeyen domaine bağlantı
- Yeni veya düşük reputation domain
- PowerShell komutunda URL geçmesi
- URL'den script veya dosya indirme
- Bağlantı sonrası yeni dosya oluşması
- Aynı domain/IP başka endpointlerde de görülmesi
- Network bağlantısı phishing veya suspicious login sonrası oluşması

---

## Alert İlk Geldiğinde Sorulacak Ana Sorular

Bir SOC analyst suspicious PowerShell alerti gördüğünde önce şu soruları sormalıdır:

1. Hangi cihazda çalıştı?
2. Hangi kullanıcı çalıştırdı?
3. Kullanıcı standart kullanıcı mı, admin mi?
4. Kullanıcı normalde PowerShell kullanır mı?
5. Process adı nedir?
6. Command line tam olarak ne içeriyor?
7. Encoded veya obfuscated komut var mı?
8. Parent process nedir?
9. Child process oluşmuş mu?
10. Network bağlantısı var mı?
11. Dosya oluşturma veya değiştirme var mı?
12. Registry değişikliği var mı?
13. Scheduled task veya service oluşturulmuş mu?
14. EDR/AV/AMSI tespiti var mı?
15. Aynı zamanda phishing, suspicious login veya brute force alerti var mı?
16. Bu davranış meşru IT aracıyla açıklanabiliyor mu?
17. Aynı komut başka cihazlarda da görülmüş mü?

---

## Toplanması Gereken Kanıtlar

### Endpoint Bilgisi

Toplanacak bilgiler:

- hostname
- device type
- operating system
- domain membership
- endpoint criticality
- EDR status
- last seen time

Risk artıran durumlar:

- Kritik sunucu üzerinde suspicious PowerShell
- Domain controller, file server, database server veya admin workstation üzerinde olay
- Endpoint güvenlik aracının devre dışı olması
- Aynı cihazda başka alertlerin de olması

---

### Kullanıcı Bilgisi

Toplanacak bilgiler:

- user
- account type
- privilege level
- department
- normal PowerShell usage
- login history
- related phishing or login alerts

Risk artıran durumlar:

- Standart kullanıcının encoded PowerShell çalıştırması
- Kullanıcının IT/admin rolünde olmaması
- Kullanıcı hesabında aynı zamanda suspicious login olması
- Kullanıcının çalıştırmayı reddetmesi
- Kullanıcının phishing mailine tıklamış olması

---

### Process Bilgisi

Toplanacak bilgiler:

- process_name
- process_id
- command_line
- parent_process
- child_process
- process_start_time
- process_hash
- signed or unsigned status

Risk artıran durumlar:

- powershell.exe veya pwsh.exe encoded command ile çalışmışsa
- Parent process Office/browser/email client ise
- PowerShell başka suspicious process başlatmışsa
- Komut satırı uzun, anlamsız veya obfuscated ise
- Process imzasız veya beklenmeyen dizinden çalışıyorsa

---

### Command Line Bilgisi

Kontrol edilecekler:

- EncodedCommand var mı?
- Hidden window davranışı var mı?
- Execution policy bypass benzeri davranış var mı?
- No profile kullanımı var mı?
- Uzak URL veya IP var mı?
- Dosya indirme veya çalıştırma davranışı var mı?
- Registry, scheduled task veya service komutları var mı?
- Credential, token, discovery veya persistence davranışı var mı?

Risk artıran durumlar:

- Encoded/obfuscated komut
- Uzak kaynaktan script çekme
- Komutun dış network hedefi içermesi
- Güvenlik kontrollerini atlatmaya çalışan parametreler
- Komutun parent process ile mantıksız görünmesi

---

### Parent ve Child Process Bilgisi

Parent process için sorular:

- PowerShell'i kim başlatmış?
- Parent process kullanıcı etkileşimiyle mi başladı?
- Parent process güvenilir yönetim aracı mı?
- Parent process Office, browser veya email client mı?

Child process için sorular:

- PowerShell başka process başlatmış mı?
- cmd, wscript, mshta, rundll32, regsvr32 gibi processler var mı?
- Child process network bağlantısı kurmuş mu?
- Child process dosya veya registry değişikliği yapmış mı?

Risk artıran durumlar:

- Office dosyası → PowerShell
- Browser → PowerShell
- Email client → PowerShell
- PowerShell → cmd/script interpreter
- PowerShell → unknown executable
- PowerShell → persistence aracı

---

### Network Kanıtları

Toplanacak bilgiler:

- network_connection
- destination_ip
- destination_domain
- url
- port
- protocol
- proxy logs
- DNS logs
- firewall logs

Risk artıran durumlar:

- Bilinmeyen dış IP/domain
- Yeni veya düşük reputation domain
- URL üzerinden script veya executable indirme
- PowerShell sonrası dış bağlantı
- Aynı hedefin başka endpointlerde de görülmesi
- Bağlantı sonrası dosya oluşturma veya process başlatma

---

### Dosya ve Sistem Değişikliği Kanıtları

Toplanacak bilgiler:

- file_created
- file_modified
- file_path
- file_hash
- registry_change
- scheduled_task_created
- service_created
- startup folder changes

Risk artıran durumlar:

- Temp klasöründe EXE/script oluşturulması
- Startup klasörüne dosya yazılması
- Registry Run/RunOnce değişikliği
- Yeni scheduled task oluşturulması
- Yeni service oluşturulması
- Dosyanın kısa süre içinde çalıştırılması
- Hash'in malicious veya suspicious çıkması

---

### Detection Kanıtları

Toplanacak bilgiler:

- EDR alert
- antivirus detection
- AMSI detection
- script block logging
- module logging
- SIEM correlation
- severity
- detection name

Risk artıran durumlar:

- EDR'nin high severity alert üretmesi
- AMSI malicious script tespiti
- Antivirus malicious detection
- Aynı process tree içinde birden fazla suspicious davranış
- Detection'ın credential access, persistence veya defense evasion belirtmesi

---

## PowerShell ve False Positive Ayrımı

### Gerçek Şüpheli Davranışa Benzeyen Durumlar

Aşağıdaki bulgular varsa olay daha şüpheli değerlendirilir:

- Standart kullanıcı encoded PowerShell çalıştırmış
- Parent process Office, browser veya email client
- Command line obfuscated veya açıklanamıyor
- PowerShell dış domain/IP ile bağlantı kurmuş
- Komut uzak içerik indirmiş
- PowerShell sonrası suspicious child process oluşmuş
- Yeni scheduled task, service veya registry persistence var
- EDR/AV/AMSI malicious tespit üretmiş
- Aynı zamanda phishing veya suspicious login alerti var
- Kullanıcı çalıştırmayı reddediyor

---

### False Positive Olabilecek Durumlar

Aşağıdaki durumlar saldırı dışı açıklama olabilir:

- IT ekibi yönetim scripti çalıştırmış olabilir
- Software deployment tool PowerShell kullanmış olabilir
- Monitoring veya backup agent script çalıştırmış olabilir
- Güvenlik ürünü kendi kontrol scriptini çalıştırmış olabilir
- Windows update veya kurulum süreci PowerShell kullanmış olabilir
- Parent process güvenilir management agent olabilir
- Network bağlantısı kurum içi servis veya update adresi olabilir
- Encoded command kurumsal otomasyon aracından gelebilir
- Kullanıcı teknik rol gereği PowerShell kullanıyor olabilir

Bu ihtimaller riski düşürebilir ama command_line, parent_process, user, hostname, network ve detection kanıtları yine kontrol edilmelidir.

---

## Severity Değerlendirme Mantığı

Severity sadece alertin verdiği seviyeye göre değil, kanıtlara göre değerlendirilmelidir.

### Düşük Risk

Şu durumlarda düşük risk düşünülebilir:

- PowerShell güvenilir IT aracı tarafından çalıştırılmış
- Parent process normal
- Network bağlantısı yok veya güvenilir internal kaynak
- EDR/AV/AMSI malicious tespit yok
- Kullanıcı teknik rol gereği PowerShell kullanıyor
- Suspicious child process yok

---

### Orta Risk

Şu durumlarda orta risk düşünülebilir:

- Encoded command var
- Parent process bilinmiyor
- Kullanıcı standart kullanıcı
- Network connection bilgisi eksik
- Komutun amacı tam anlaşılamıyor
- Ek kanıt gerekiyor

---

### Orta-Yüksek Risk

Şu durumlarda orta-yüksek risk düşünülebilir:

- Standart kullanıcı encoded PowerShell çalıştırmış
- Parent process suspicious veya unknown
- Network connection unknown veya dış hedef var
- Komut obfuscated görünüyor
- Dosya oluşturma veya child process bilgisi eksik
- Aynı zamanda phishing veya suspicious login olabilir

---

### Yüksek Risk

Şu durumlarda yüksek risk düşünülebilir:

- PowerShell dış şüpheli IP/domain ile bağlantı kurmuş
- Uzak içerik indirip çalıştırmış
- EDR/AV/AMSI malicious tespit var
- Persistence göstergesi var
- Credential access veya discovery davranışı görülmüş
- Attachment açıldıktan sonra PowerShell başlamış
- Kullanıcı çalıştırmayı reddetmiş
- Aynı IOC birden fazla endpointte görülmüş

---

## SOC Analyst İçin Adım Adım Triage Planı

### Adım 1: Alert Bilgisini Doğrula

Kontrol et:

- Alert hangi güvenlik aracından geldi?
- Hangi hostname üzerinde oluştu?
- Hangi kullanıcı ile çalıştı?
- Process adı ve command line nedir?
- Alert zamanı nedir?

Amaç:

Olayın gerçekten endpoint process alerti olduğunu doğrulamak.

---

### Adım 2: Kullanıcı ve Cihaz Bağlamını İncele

Kontrol et:

- Kullanıcı standart kullanıcı mı, admin mi?
- Kullanıcı IT/admin ekibinden mi?
- Cihaz kullanıcı laptopu mu, sunucu mu?
- Kullanıcı normalde bu cihazı kullanıyor mu?
- Cihaz kritik sistem mi?

Amaç:

Davranışın beklenen kullanıcı/cihaz bağlamına uyup uymadığını anlamak.

---

### Adım 3: Command Line'ı İncele

Kontrol et:

- Komut ne yapmaya çalışıyor?
- Encoded veya obfuscated mı?
- Uzak URL/IP içeriyor mu?
- Dosya indirme veya çalıştırma var mı?
- Security bypass veya hidden execution izlenimi var mı?

Amaç:

PowerShell'in amacını anlamak.

---

### Adım 4: Parent Process'i İncele

Kontrol et:

- PowerShell'i kim başlatmış?
- Parent process normal mi?
- Office, browser veya email client mı?
- Management agent veya admin tool mu?

Amaç:

PowerShell'in nasıl tetiklendiğini anlamak.

---

### Adım 5: Child Process ve Process Tree'yi İncele

Kontrol et:

- PowerShell başka process başlatmış mı?
- cmd, wscript, mshta, rundll32 gibi processler var mı?
- Process tree saldırı zinciri gibi mi görünüyor?
- EDR process tree hangi sırayı gösteriyor?

Amaç:

PowerShell sonrası ne olduğunu anlamak.

---

### Adım 6: Network Bağlantılarını Kontrol Et

Kontrol et:

- PowerShell network bağlantısı kurmuş mu?
- Hedef IP/domain nedir?
- Hedef kurum içi mi dış kaynak mı?
- Proxy/DNS/firewall loglarında aynı hedef var mı?
- Aynı hedefe başka endpointler bağlanmış mı?

Amaç:

Komutun dış sistemlerle iletişim kurup kurmadığını anlamak.

---

### Adım 7: Dosya, Registry ve Persistence İzlerini Kontrol Et

Kontrol et:

- Yeni dosya oluşturulmuş mu?
- Temp, AppData veya startup dizinleri kullanılmış mı?
- Registry değişikliği var mı?
- Scheduled task veya service oluşturulmuş mu?
- Oluşan dosyanın hash değeri nedir?

Amaç:

Kalıcı olma veya payload bırakma ihtimalini değerlendirmek.

---

### Adım 8: Detection Sonuçlarını İncele

Kontrol et:

- EDR ne tespit etmiş?
- AV malicious detection verdi mi?
- AMSI script tespiti var mı?
- Script block logging mevcut mu?
- SIEM başka alertlerle ilişkilendirmiş mi?

Amaç:

Güvenlik araçlarının kanıtlarını değerlendirmek.

---

### Adım 9: Zaman Çizelgesi Kur

Kontrol et:

- Olaydan önce phishing maili var mı?
- Olaydan önce suspicious login var mı?
- Kullanıcı aynı saatlerde cihaz başında mı?
- PowerShell sonrası network, dosya veya process olayları ne zaman oluşmuş?
- Aynı zaman aralığında başka endpointlerde benzer olay var mı?

Amaç:

Olayın saldırı zincirinin parçası olup olmadığını anlamak.

---

### Adım 10: Kapsamı Araştır

Kontrol et:

- Aynı command line başka cihazlarda var mı?
- Aynı hash başka endpointlerde var mı?
- Aynı destination domain/IP başka cihazlarda görülmüş mü?
- Aynı kullanıcı başka cihazlarda benzer işlem yapmış mı?

Amaç:

Olay tek cihaz mı, yoksa yaygın kampanya mı anlamak.

---

### Adım 11: Olayı Sınıflandır

Olası sınıflandırmalar:

- Benign admin activity
- Software deployment activity
- Suspicious PowerShell
- Suspicious script execution
- Phishing-related execution
- Malware execution suspicion
- Persistence suspicion
- Confirmed malicious execution

Amaç:

Olayı kanıta dayalı kategoriye koymak.

---

## Ne Zaman Incident'a Yükseltilir?

Aşağıdaki durumlarda olay incident olarak yükseltilmelidir:

- Kullanıcı çalıştırmayı reddediyorsa
- Parent process Office, browser veya email client ise ve davranış açıklanamıyorsa
- PowerShell dış şüpheli IP/domain ile bağlantı kurduysa
- Komut uzak içerik indirip çalıştırdıysa
- EDR/AV/AMSI malicious tespit verdiyse
- Suspicious child process oluştuysa
- Registry, scheduled task veya service ile persistence göstergesi varsa
- Credential access, discovery veya lateral movement davranışı varsa
- Olay phishing tıklaması sonrası oluştuysa
- Aynı kullanıcıda suspicious login veya account compromise şüphesi varsa
- Aynı komut, hash veya network IOC birden fazla endpointte görülüyorsa
- Endpointte veri erişimi, veri sıkıştırma veya dışarı gönderme şüphesi varsa

---

## Önerilen İlk Müdahale Yaklaşımı

Bu playbook otomatik aksiyon önermek için değil, insan analiste güvenli triage rehberi vermek için kullanılır.

Temkinli ilk müdahale önerileri:

- Process tree bilgisini topla
- Command line ve parent process'i incele
- Network bağlantılarını kontrol et
- Dosya, registry, scheduled task ve service değişikliklerini ara
- EDR/AV/AMSI sonuçlarını değerlendir
- Aynı IOC'leri diğer endpointlerde ara
- Kullanıcı ve IT ekibiyle meşru kullanım doğrulaması yap
- Eksik kanıtları not et
- Gerekirse incident response ekibine yükselt

Önerilmemesi gereken otomatik aksiyonlar:

- Kanıt olmadan process sonlandırma
- Kanıt olmadan dosya silme
- Kanıt olmadan hesap kapatma
- Kanıt olmadan IP/domain engelleme
- Sistemde yıkıcı değişiklik yapma
- Komutu kesin zararlı ilan etme

---

## Kullanıcıya veya IT Ekibine Sorulabilecek Güvenli Sorular

Kullanıcıya sorulabilecekler:

- Bu saatlerde cihazda bir işlem yaptınız mı?
- Bir e-posta eki açtınız mı?
- Bir linke tıkladınız mı?
- PowerShell veya terminal açtınız mı?
- Bir kurulum veya güncelleme yaptınız mı?

IT ekibine sorulabilecekler:

- Bu komut kurumsal yönetim scriptlerinden biri mi?
- Software deployment veya monitoring aracı bu komutu çalıştırıyor mu?
- Bu hostname üzerinde planlı bakım var mıydı?
- Aynı komut başka cihazlarda da beklenen şekilde çalışıyor mu?

Amaç kullanıcıyı suçlamak değil, teknik kanıtları tamamlamaktır.

---

## Raporlama İçin Örnek Analist Notu

Örnek not:

Bu olayda standart kullanıcı bağlamında encoded PowerShell komutu çalıştığı görülmektedir. PowerShell tek başına zararlı değildir ancak encoded komut, parent process bilgisinin belirsiz olması ve network connection durumunun bilinmemesi nedeniyle olay dikkatli incelenmelidir. Kesin karar için command line içeriği, parent process, child process, network bağlantıları, dosya/registry değişiklikleri ve EDR/AV/AMSI sonuçları kontrol edilmelidir. Şüpheli network bağlantısı, persistence veya malicious detection görülürse olay incident olarak yükseltilmelidir.

---

## Kullanılan MITRE ATT&CK Eşleşmesi

Bu playbook için ana MITRE eşleşmesi:

- T1059 - Command and Scripting Interpreter

PowerShell özelinde değerlendirilebilecek alt davranış:

- PowerShell kullanımı

İlgili olabilecek ek davranışlar:

- Defense evasion şüphesi
- Execution şüphesi
- Persistence şüphesi
- Credential access şüphesi
- Discovery şüphesi

Bu ek davranışlar kesin olarak söylenmemeli, sadece kanıt varsa değerlendirilmelidir.

---

## Kısa Özet

Suspicious PowerShell alertinde en kritik nokta şudur:

PowerShell'in çalışması tek başına zararlı değildir. Ancak encoded command, suspicious parent process, dış network bağlantısı, dosya/registry değişikliği, EDR/AV/AMSI tespiti veya phishing/suspicious login ile ilişki varsa risk ciddi şekilde artar.

SOC analyst önce bağlamı anlamalı, process tree'yi incelemeli, network ve dosya etkilerini kontrol etmeli, olayın meşru yönetim aktivitesiyle açıklanıp açıklanamayacağını doğrulamalıdır.
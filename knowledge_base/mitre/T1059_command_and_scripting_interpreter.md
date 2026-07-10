# T1059 - Command and Scripting Interpreter

## Kısa Açıklama

T1059 - Command and Scripting Interpreter, saldırganların sistem üzerinde komut veya script çalıştırmak için yerleşik yorumlayıcıları kullanmasını ifade eder.

Bu teknik Windows, Linux ve macOS sistemlerde görülebilir. Windows ortamında en yaygın örneklerden biri PowerShell kullanımıdır.

PowerShell, cmd, bash, sh, Python, JavaScript, VBScript, WMI, mshta, wscript ve cscript gibi araçlar hem meşru yönetim amaçlı hem de saldırgan davranışlarında kullanılabilir.

SOC açısından önemli nokta şudur:

Komut veya script yorumlayıcısının çalışması tek başına zararlı değildir. Risk, çalıştırılan komutun içeriği, parent process, kullanıcı, network bağlantısı, dosya/registry etkileri ve diğer alertlerle ilişkisine göre değerlendirilmelidir.

---

## SOC Açısından Neden Önemlidir?

Command and scripting interpreter kullanımı saldırı zincirinin birçok aşamasında görülebilir:

- İlk erişim sonrası komut çalıştırma
- Phishing attachment sonrası script execution
- Zararlı dosya indirme
- Keşif komutları çalıştırma
- Yetki kontrolü
- Persistence oluşturma
- Güvenlik araçlarından kaçınma
- Credential access denemeleri
- İç ağda hareket hazırlığı
- Veri toplama veya dışarı aktarma hazırlığı

SOC analyst için amaç, sadece `powershell.exe çalıştı` demek değildir. Asıl amaç şunu anlamaktır:

- Bu komutu kim çalıştırdı?
- Hangi cihazda çalıştı?
- Hangi parent process başlattı?
- Komut ne yapmaya çalışıyor?
- Encoded veya obfuscated mı?
- Network bağlantısı kurdu mu?
- Dosya, registry, scheduled task veya service değişikliği yaptı mı?
- EDR/AV/AMSI tespiti var mı?
- Olay phishing, suspicious login veya başka alertlerle ilişkili mi?

---

## Bu Teknik Ne Zaman Düşünülür?

Aşağıdaki durumlarda T1059 düşünülebilir:

- PowerShell, cmd veya başka script interpreter olağan dışı şekilde çalıştıysa
- Encoded veya obfuscated komut görülüyorsa
- Komut satırı uzun, karışık veya açıklanamıyorsa
- Parent process Office, browser veya email client ise
- Komut dış IP/domain ile bağlantı kuruyorsa
- Komut uzak içerik indiriyor gibi görünüyorsa
- PowerShell sonrası suspicious child process oluşuyorsa
- Endpoint üzerinde yeni dosya, registry değişikliği, scheduled task veya service oluşuyorsa
- Script execution sonrası EDR/AV/AMSI alerti varsa
- Olay phishing tıklaması veya attachment açılması sonrası oluştuysa
- Kullanıcı normalde böyle komutlar çalıştırmıyorsa
- Aynı command line veya IOC başka endpointlerde de görülüyorsa

---

## Yaygın Interpreter Örnekleri

### PowerShell

Windows yönetim ve otomasyon aracıdır. Saldırganlar tarafından da execution, download, discovery, persistence ve defense evasion amacıyla kullanılabilir.

Şüpheli olabilecek göstergeler:

- EncodedCommand
- Obfuscated command line
- Hidden window davranışı
- Uzak URL'den içerik alma
- Script block içinde karmaşık veya okunması zor ifadeler
- Standart kullanıcı tarafından çalıştırılması
- Office veya browser parent process'i
- PowerShell sonrası dış network bağlantısı

---

### cmd.exe

Windows komut satırıdır. Meşru yönetim işlemlerinde kullanılır ancak saldırganlar tarafından da komut çalıştırma, dosya çalıştırma veya sistem bilgisi toplama için kullanılabilir.

Şüpheli olabilecek göstergeler:

- Beklenmeyen parent process
- Script veya batch dosyası çalıştırma
- PowerShell veya başka interpreter başlatma
- Sistem veya kullanıcı bilgisi toplayan komutlar
- Network veya dosya işlemleriyle birleşmesi

---

### wscript.exe ve cscript.exe

Windows Script Host araçlarıdır. JavaScript veya VBScript dosyalarını çalıştırabilir.

Şüpheli olabilecek göstergeler:

- Email attachment sonrası çalışması
- Temp veya AppData içinden script çalıştırması
- PowerShell veya cmd başlatması
- Dış network bağlantısı
- Obfuscated script içeriği

---

### mshta.exe

HTML Application dosyalarını çalıştırabilir. Saldırganlar tarafından script execution için kötüye kullanılabilir.

Şüpheli olabilecek göstergeler:

- Uzak URL ile çalışması
- Office veya browser parent process'i
- PowerShell/cmd child process oluşturması
- Bilinmeyen domain ile bağlantı

---

### bash, sh, Python veya Diğer Script Interpreterlar

Linux/macOS veya geliştirici sistemlerinde meşru olabilir. Ancak saldırı sırasında da komut çalıştırmak, dosya indirmek veya sistem keşfi yapmak için kullanılabilir.

Şüpheli olabilecek göstergeler:

- Beklenmeyen kullanıcı bağlamı
- Dış URL'den script çalıştırma
- Persistence veya credential erişimi
- Beklenmeyen network bağlantısı
- Aynı komutun birden fazla sistemde görülmesi

---

## PowerShell Özelinde Riskli Davranışlar

PowerShell kullanımı özellikle şu göstergelerle birlikte riskli hale gelir:

- Encoded command
- Obfuscated script
- Hidden execution
- No profile kullanımı
- Execution policy bypass davranışı
- Uzak URL veya IP içeren komut
- Script veya dosya indirme
- Dosya indirip çalıştırma zinciri
- Office, browser veya email client parent process'i
- Standart kullanıcı tarafından çalıştırılması
- Dış network bağlantısı
- EDR/AV/AMSI alerti
- Script block logging içinde suspicious davranış
- Scheduled task veya registry persistence
- Phishing veya suspicious login ile zaman ilişkisi

Not:

Bu göstergeler tek tek kesin zararlı anlamına gelmez. Ancak birkaçının birlikte görülmesi risk seviyesini artırır.

---

## Tipik Kanıtlar

T1059 şüphesinde aranabilecek kanıtlar:

- process_name
- command_line
- parent_process
- child_process
- process_start_time
- hostname
- user
- encoded_command_present
- script_block_logging
- module_logging
- network_connection
- destination_ip
- destination_domain
- url
- file_created
- file_modified
- file_hash
- registry_change
- scheduled_task_created
- service_created
- EDR alert
- antivirus detection
- AMSI detection
- related phishing alert
- related suspicious login alert
- same command seen on other endpoints

---

## Risk Artıran Göstergeler

Aşağıdaki bulgular olayın riskini artırır:

- Standart kullanıcının PowerShell veya script interpreter çalıştırması
- Kullanıcının teknik rolü olmaması
- Parent process'in Office, browser veya email client olması
- Parent process'in unknown olması
- Command line'ın encoded veya obfuscated olması
- Komutun dış URL/IP/domain içermesi
- Komutun uzak içerik indiriyor gibi görünmesi
- Komut sonrası yeni dosya oluşturulması
- Komut sonrası suspicious child process oluşması
- Registry, scheduled task veya service değişikliği
- EDR/AV/AMSI malicious veya suspicious tespiti
- Komutun phishing mailinden veya attachment açılmasından sonra çalışması
- Aynı kullanıcıda suspicious login veya brute force alerti olması
- Aynı command line'ın başka endpointlerde de görülmesi
- Komut sonrası network bağlantısı ve dosya oluşturmanın birlikte görülmesi
- Kullanıcının komutu çalıştırdığını reddetmesi

---

## Risk Düşüren veya False Positive Olabilecek Durumlar

Aşağıdaki durumlar saldırı dışı açıklama olabilir:

- IT ekibi yönetim scripti çalıştırmış olabilir
- Software deployment tool PowerShell kullanmış olabilir
- Monitoring agent script çalıştırmış olabilir
- Backup, EDR veya güvenlik ürünü kendi kontrol scriptini çalıştırmış olabilir
- Windows update veya uygulama kurulum süreci komut çalıştırmış olabilir
- Kullanıcı geliştirici veya sistem yöneticisi olabilir
- Parent process güvenilir management agent olabilir
- Network bağlantısı kurum içi servis veya güvenilir update adresi olabilir
- Encoded command kurumsal otomasyon aracı tarafından üretilmiş olabilir
- Script block logging içeriği meşru yönetim komutu olabilir

Bu ihtimaller riski düşürür ama yine de command line, parent process, user, hostname, network ve detection kanıtları kontrol edilmelidir.

---

## SOC Analyst İlk Neye Bakar?

SOC analyst ilk aşamada şu sorulara cevap aramalıdır:

1. Hangi cihazda çalıştı?
2. Hangi kullanıcı ile çalıştı?
3. Kullanıcı standart kullanıcı mı, admin mi?
4. Kullanıcı normalde script veya PowerShell kullanır mı?
5. Process adı nedir?
6. Command line tam olarak ne içeriyor?
7. Encoded veya obfuscated içerik var mı?
8. Parent process nedir?
9. Parent process normal mi, suspicious mı?
10. Child process oluşmuş mu?
11. Network bağlantısı var mı?
12. Dış IP veya domain ile iletişim var mı?
13. Yeni dosya, registry, scheduled task veya service oluşmuş mu?
14. EDR/AV/AMSI tespiti var mı?
15. Olay phishing veya suspicious login ile ilişkili mi?
16. Aynı komut başka endpointlerde de görülmüş mü?
17. Davranış meşru IT aracıyla açıklanabiliyor mu?

---

## İncelenecek Log Kaynakları

T1059 triage sırasında şu log kaynakları faydalı olabilir:

- Endpoint process logs
- EDR telemetry
- Windows Event Logs
- PowerShell script block logs
- PowerShell module logs
- AMSI logs
- Antivirus logs
- Sysmon logs
- Command line logging
- Parent-child process tree
- File creation logs
- Registry modification logs
- Scheduled task logs
- Service creation logs
- Network connection logs
- DNS logs
- Proxy logs
- Firewall logs
- Email security logs
- Identity provider logs
- SIEM correlation logs

---

## Önemli Endpoint Alanları

Aşağıdaki alanlar özellikle önemlidir:

- hostname
- user
- process_name
- command_line
- parent_process
- child_process
- process_start_time
- powershell_version
- encoded_command_present
- script_block_logging
- module_logging
- network_connection
- destination_ip
- destination_domain
- url
- file_created
- file_modified
- file_hash
- registry_change
- scheduled_task_created
- service_created
- edr_alert
- antivirus_detection
- amsi_detection

Bu alanlar olmadan olay hakkında kesin yorum yapmak zordur.

---

## Parent Process Değerlendirme Mantığı

Parent process, komutun nasıl tetiklendiğini anlamak için kritiktir.

### Daha Normal Görünebilecek Parent Processler

- explorer.exe
- cmd.exe
- Windows Terminal
- management agent
- software deployment tool
- monitoring agent
- admin automation tool

Bu parent processler olayın meşru olma ihtimalini artırabilir ama tek başına güvenli olduğunu kanıtlamaz.

### Daha Şüpheli Görünebilecek Parent Processler

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

Bu parent processler özellikle phishing, attachment execution veya browser-based execution ile ilişkili olabilir.

---

## Command Line Değerlendirme Mantığı

Command line incelenirken şu sorular sorulmalıdır:

- Komut ne yapmaya çalışıyor?
- Komut okunabilir mi?
- Encoded veya obfuscated mı?
- Uzak URL/IP/domain içeriyor mu?
- Dosya indiriyor mu?
- Dosya çalıştırıyor mu?
- Güvenlik kontrollerini aşmaya çalışıyor mu?
- Registry, service veya scheduled task değiştiriyor mu?
- Kullanıcı veya sistem bilgisi topluyor mu?
- Meşru IT scriptine benziyor mu?

Riskli kombinasyon örnekleri:

- Standart kullanıcı + encoded command + unknown parent process
- Office parent process + PowerShell + network connection
- PowerShell + dış URL + file created
- PowerShell + scheduled task created
- Suspicious login sonrası PowerShell execution
- Phishing attachment sonrası script interpreter execution

---

## Network Bağlantısı Varsa Özellikle Kontrol Edilecekler

Script interpreter network bağlantısı kurduysa şu kontroller yapılmalıdır:

- Hedef IP/domain nedir?
- İç ağ mı dış kaynak mı?
- Domain daha önce kurumda görülmüş mü?
- Reputation sonucu nedir?
- DNS/proxy/firewall loglarında aynı hedef var mı?
- Aynı hedefe başka endpointler bağlanmış mı?
- Bağlantıdan sonra dosya indirme veya yeni process oluşmuş mu?
- Hedef phishing veya malware kampanyalarıyla ilişkili mi?
- Bağlantı kullanıcı aksiyonu ile açıklanabiliyor mu?

---

## Dosya veya Persistence Göstergesi Varsa Kontrol Edilecekler

Komut sonrası dosya veya kalıcılık izi varsa şu kontroller yapılmalıdır:

- Hangi dosya oluşturuldu?
- Dosya hangi dizinde?
- Dosya hash değeri nedir?
- Dosya çalıştırılmış mı?
- Registry Run/RunOnce değişikliği var mı?
- Yeni scheduled task oluşturulmuş mu?
- Yeni service oluşturulmuş mu?
- Startup klasörü kullanılmış mı?
- Bu değişiklik IT aracıyla açıklanabiliyor mu?

Risk artar:

- Temp veya AppData altında executable/script oluşması
- Scheduled task ile tekrar çalışacak komut yazılması
- Service oluşturulması
- Güvenlik ayarlarının değiştirilmesi
- Hash'in malicious çıkması

---

## Olay Sınıflandırma Yaklaşımı

Bu teknikle ilişkili olaylar şu şekilde sınıflandırılabilir:

### Benign Admin Activity

Meşru IT veya admin işlemi. Parent process, kullanıcı rolü, command line ve yönetim aracı bağlamı normaldir.

### Software Deployment Activity

Yazılım dağıtım, update veya monitoring aracı tarafından çalıştırılan meşru script olabilir.

### Suspicious Script Execution

Command line veya parent process şüphelidir ancak malicious olduğuna dair yeterli kanıt yoktur.

### Phishing-Related Execution

Script interpreter phishing maili, attachment veya link tıklaması sonrası çalışmıştır.

### Malware Execution Suspicion

Komut suspicious network, file creation, child process veya detection ile ilişkilidir.

### Persistence Suspicion

Registry, scheduled task, service veya startup değişiklikleri görülmüştür.

### Confirmed Malicious Execution

EDR/AV/AMSI malicious detection, suspicious network, persistence veya kullanıcı reddi gibi güçlü kanıtlar vardır.

---

## Incident'a Yükseltme Koşulları

Aşağıdaki bulgular varsa olay incident olarak yükseltilebilir:

- Kullanıcı komutu çalıştırmadığını söylüyorsa
- Parent process Office, browser veya email client ise ve davranış açıklanamıyorsa
- Encoded/obfuscated komut dış IP/domain ile bağlantı kuruyorsa
- Komut uzak içerik indirip çalıştırmışsa
- EDR/AV/AMSI malicious tespiti varsa
- Suspicious child process oluşmuşsa
- Persistence göstergesi varsa
- Registry, scheduled task veya service değişikliği şüpheliyse
- Credential access veya discovery davranışı görülüyorsa
- Olay phishing tıklaması sonrası oluştuysa
- Aynı kullanıcıda suspicious login veya account compromise şüphesi varsa
- Aynı komut, hash veya network IOC birden fazla endpointte görülüyorsa
- Endpointte veri erişimi, veri sıkıştırma veya veri dışarı gönderme şüphesi varsa

---

## Güven Düzeyi Değerlendirme Mantığı

### Düşük Güven

Şu durumlarda analiz güveni düşük olur:

- Sadece process adı biliniyordur
- Command line eksiktir
- Parent process bilinmiyordur
- Network bağlantısı hakkında bilgi yoktur
- EDR/AV/AMSI sonucu yoktur
- Dosya veya registry etkisi bilinmiyordur

### Orta Güven

Şu durumlarda analiz güveni orta olabilir:

- Command line vardır ama amacı belirsizdir
- Encoded command vardır
- Kullanıcı standart kullanıcıdır
- Parent process unknown olabilir
- Network veya dosya etkisi henüz bilinmiyordur
- Ek kanıt gerekir

### Orta-Yüksek Güven

Şu durumlarda analiz güveni orta-yüksek olabilir:

- Encoded command vardır
- Parent process suspicious veya unknown'dur
- Standart kullanıcı bağlamında çalışmıştır
- Network connection suspicious veya unknown'dur
- Aynı zamanda phishing veya suspicious login ilişkisi olabilir
- Ancak malicious detection veya post-execution kanıtı henüz yoktur

### Yüksek Güven

Şu durumlarda analiz güveni yüksek olabilir:

- EDR/AV/AMSI malicious tespit vardır
- Komut dış suspicious IP/domain ile bağlantı kurmuştur
- Uzak içerik indirip çalıştırmıştır
- Persistence göstergesi vardır
- Kullanıcı çalıştırmayı reddetmiştir
- Attachment açıldıktan sonra PowerShell başlamıştır
- Aynı IOC birden fazla endpointte görülmüştür

---

## SOC Analyst İçin Güvenli Triage Notu

Bu teknik incelenirken otomatik yıkıcı aksiyon önerilmemelidir.

Önerilebilecek güvenli triage adımları:

- Process tree bilgisini topla
- Command line ve parent process'i incele
- Kullanıcı ve cihaz bağlamını değerlendir
- Network bağlantılarını kontrol et
- Dosya, registry, scheduled task ve service değişikliklerini ara
- EDR/AV/AMSI sonuçlarını değerlendir
- Script block logging varsa içeriğini savunma amacıyla incele
- Aynı IOC'leri diğer endpointlerde ara
- Phishing veya login alertleriyle zaman ilişkisini kontrol et
- IT ekibi veya kullanıcıyla meşru kullanım doğrulaması yap
- Eksik kanıtları not et
- Olayı insan analiste veya incident response ekibine yükseltmeyi değerlendir

Önerilmemesi gerekenler:

- Kanıt olmadan process sonlandırma
- Kanıt olmadan dosya silme
- Kanıt olmadan hesap kapatma
- Kanıt olmadan IP/domain engelleme
- Sistemde yıkıcı değişiklik yapma
- Komutu kesin zararlı ilan etme

---

## Kısa Özet

T1059 - Command and Scripting Interpreter, sistem üzerinde komut veya script çalıştırma davranışını ifade eder.

Bu teknik özellikle şu kombinasyonlarda ciddi risk oluşturur:

- Encoded veya obfuscated command
- Suspicious parent process
- Standart kullanıcı bağlamı
- Dış network bağlantısı
- Uzak içerik indirme
- Dosya veya registry değişikliği
- Scheduled task veya service oluşturma
- EDR/AV/AMSI detection
- Phishing veya suspicious login ile ilişki

Kesin saldırı kararı için command line, parent process, network bağlantısı, dosya/registry etkileri, detection sonuçları ve kullanıcı/IT doğrulaması incelenmelidir.
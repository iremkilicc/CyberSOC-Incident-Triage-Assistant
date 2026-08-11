# Endpoint Investigation Fields

## Amaç

Bu dosya, endpoint üzerinde görülen suspicious PowerShell, encoded command, suspicious process execution, script activity, command line anomaly ve endpoint-based alertlerde hangi alanlara bakılması gerektiğini açıklar.

PowerShell tek başına zararlı değildir. Windows ortamında sistem yöneticileri, güvenlik ekipleri, otomasyon araçları ve yazılımlar PowerShell kullanabilir. Ancak bazı kullanım şekilleri saldırı davranışına benzeyebilir.

Bu yüzden SOC analyst'in amacı doğrudan "zararlı" demek değil, çalıştırılan komutun bağlamını, kullanıcıyı, parent process bilgisini, network bağlantılarını, dosya/registry etkilerini ve olay sonrası aktiviteleri incelemektir.

---

## Temel Endpoint Alanları

### hostname

Olayın gerçekleştiği cihaz adıdır.

Kontrol soruları:
- Cihaz kullanıcı bilgisayarı mı, sunucu mu?
- Cihaz kritik sistem mi?
- Cihaz kurum domainine bağlı mı?
- Cihaz daha önce benzer alert üretmiş mi?
- Aynı cihazda aynı zaman aralığında başka güvenlik alertleri var mı?

Risk artıran durumlar:
- Kritik sunucu üzerinde suspicious PowerShell
- Domain controller, file server, database server veya admin workstation üzerinde olay
- Aynı cihazda birden fazla suspicious process görülmesi
- Endpoint güvenlik aracının aynı cihazda başka alert üretmesi

---

### user

Komutu veya process'i çalıştıran kullanıcıdır.

Kontrol soruları:
- Kullanıcı standart kullanıcı mı, admin mi?
- Kullanıcı normalde PowerShell kullanır mı?
- Kullanıcı IT/admin ekibinden mi?
- Kullanıcı bu cihazda normalde oturum açar mı?
- Kullanıcı hesabında aynı zamanda suspicious login alerti var mı?

Risk artıran durumlar:
- Standart kullanıcının encoded PowerShell çalıştırması
- Admin hesabının olağan dışı saatlerde script çalıştırması
- Kullanıcının aynı zamanda phishing veya brute force olayında geçmesi
- Kullanıcının bu çalıştırmayı reddetmesi

---

### process_name

Çalışan process adıdır.

Örnekler:
- powershell.exe
- pwsh.exe
- cmd.exe
- wscript.exe
- cscript.exe
- mshta.exe
- rundll32.exe
- regsvr32.exe
- certutil.exe
- bitsadmin.exe
- schtasks.exe

Kontrol soruları:
- Process beklenen bir araç mı?
- Kullanıcı bu aracı normalde kullanır mı?
- Process güvenlik ürünü tarafından şüpheli olarak işaretlenmiş mi?
- Process başka child process başlatmış mı?

Risk artıran durumlar:
- Standart kullanıcıdan powershell.exe
- Office uygulamasından powershell.exe başlaması
- Browser veya mail client üzerinden script process başlaması
- PowerShell'in encoded veya gizli şekilde çalışması

---

### command_line

Process'in çalıştırıldığı tam komut satırıdır.

Kontrol soruları:
- Komut satırı ne yapmaya çalışıyor?
- Encoded command var mı?
- Download, execute, bypass, hidden, no profile gibi riskli parametreler var mı?
- Komut uzak bir URL, IP veya domain ile iletişim kuruyor mu?
- Komut dosya indiriyor, çalıştırıyor veya sistem ayarı değiştiriyor mu?
- Komut obfuscated veya okunması zor mu?

Risk artıran durumlar:
- EncodedCommand kullanımı
- ExecutionPolicy bypass benzeri davranışlar
- Hidden window veya no profile kullanımı
- Download cradle davranışı
- Uzak kaynaktan script çekme
- Base64 veya obfuscation benzeri uzun/anlamsız stringler
- Komutun audit veya güvenlik kontrollerinden kaçmaya çalışması

Not:

Encoded veya uzun komut satırı tek başına kesin zararlı değildir. Bazı yönetim araçları da encoded komut kullanabilir. Ancak standart kullanıcı, bilinmeyen parent process ve network connection ile birleşirse risk artar.

---

### parent_process

Şüpheli process'i başlatan üst process bilgisidir.

Kontrol soruları:
- PowerShell'i kim başlatmış?
- Parent process normal mi?
- Parent process Office, browser, email client veya archive tool mu?
- Parent process kullanıcı etkileşimiyle mi başlamış?
- Parent process güvenilir yönetim aracı mı?

Normal olabilecek parent process örnekleri:
- explorer.exe
- cmd.exe
- Windows Terminal
- management agent
- software deployment tool
- admin automation tool

Riskli olabilecek parent process örnekleri:
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

Risk artıran durumlar:
- Office uygulamasından PowerShell başlaması
- Browser'dan script process başlaması
- Email client sonrası PowerShell çalışması
- Archive tool sonrası executable/script çalışması
- Parent process'in bilinmiyor olması

---

### child_process

Şüpheli process'in başlattığı alt processlerdir.

Kontrol soruları:
- PowerShell başka process başlatmış mı?
- cmd, wscript, mshta, rundll32, regsvr32 gibi processler başlamış mı?
- Network veya dosya işlemleri yapan processler var mı?
- Güvenlik aracının child process için alerti var mı?

Risk artıran durumlar:
- PowerShell sonrası cmd veya script interpreter başlaması
- PowerShell sonrası credential, discovery veya persistence davranışına benzeyen processler
- PowerShell sonrası dış bağlantı kuran process
- PowerShell sonrası dosya indirme veya çalıştırma

---

## PowerShell'e Özel Alanlar

### powershell_version

Çalışan PowerShell sürümüdür.

Kontrol soruları:
- Eski PowerShell sürümü mü kullanılmış?
- PowerShell Core mu Windows PowerShell mi?
- Kurumda beklenen sürüm bu mu?

Risk artıran durumlar:
- Eski sürüm kullanımı
- Standart kullanıcı tarafından beklenmeyen PowerShell kullanımı
- Güvenlik logging özelliklerinin olmadığı veya zayıf olduğu ortamlar

---

### script_block_logging

PowerShell script block logging kaydıdır.

Kontrol soruları:
- Çalıştırılan script içeriği loglanmış mı?
- Script içinde download, execute, credential, discovery veya persistence davranışı var mı?
- Script okunabilir mi yoksa obfuscated mı?
- Script güvenilir bir yönetim scripti mi?

Risk artıran durumlar:
- Obfuscated script
- Uzak URL'den içerik çekme
- Credential veya token erişimi
- Security tool bypass denemesi
- Registry, scheduled task veya startup değişikliği

---

### module_logging

PowerShell module logging bilgisidir.

Kontrol soruları:
- Hangi PowerShell modülleri kullanılmış?
- Kullanılan modül yönetim amaçlı mı?
- Modül credential, domain, process, service veya registry işlemleri yapıyor mu?

Risk artıran durumlar:
- Beklenmeyen modül kullanımı
- Yetki, credential veya discovery amaçlı modül davranışı
- Kullanıcının normalde kullanmadığı modüller

---

### encoded_command_present

Komut satırında encoded command olup olmadığını gösterir.

Kontrol soruları:
- EncodedCommand var mı?
- Encoded içerik okunabilir hale getirildiğinde ne yapıyor?
- Encoded komut güvenilir yönetim aracı tarafından mı üretilmiş?
- Encoded komut network bağlantısı, dosya indirme veya execution yapıyor mu?

Risk artıran durumlar:
- Encoded komutun standart kullanıcı tarafından çalıştırılması
- Encoded komutun parent process'inin Office/browser/email client olması
- Encoded komutun dış domain/IP ile iletişim kurması
- Encoded komutun güvenlik ayarı değiştirmesi

Not:

Encoded içeriği analiz ederken sadece savunma ve triage amacıyla incelenmelidir. Amaç zararlı davranışı anlamak ve kanıt toplamaktır.

---

### execution_policy_change

PowerShell execution policy veya benzer çalıştırma kısıtlarının değiştirilmeye çalışılıp çalışılmadığını gösterir.

Kontrol soruları:
- Komut execution restriction bypass etmeye çalışıyor mu?
- Bu davranış kurumda beklenen yönetim scriptlerinden mi geliyor?
- Kullanıcı normalde böyle bir işlem yapar mı?

Risk artıran durumlar:
- Bypass davranışı
- Hidden execution ile birlikte görülmesi
- Uzak kaynaktan indirilen script ile birlikte görülmesi

---

## Network Alanları

### network_connection

Process'in dış veya iç network bağlantısı kurup kurmadığını gösterir.

Kontrol soruları:
- PowerShell network bağlantısı kurmuş mu?
- Bağlantı iç IP'ye mi dış IP'ye mi?
- Hedef domain veya IP daha önce görülmüş mü?
- Bağlantı dosya indirme, C2 veya veri gönderme davranışına benziyor mu?
- Proxy/DNS/firewall loglarında aynı hedef var mı?

Risk artıran durumlar:
- PowerShell'in dış IP veya bilinmeyen domaine bağlanması
- Yeni veya düşük reputation domain
- Komutun URL'den içerik çekmesi
- Aynı hedefe başka endpointlerin de bağlanması
- Bağlantı sonrası yeni dosya oluşması veya process başlaması

---

### destination_ip

Network bağlantısının hedef IP adresidir.

Kontrol soruları:
- IP iç ağ mı dış ağ mı?
- IP hangi ülke, ASN veya hosting sağlayıcısına ait?
- IP daha önce kurumda görülmüş mü?
- IP tehdit istihbaratında zararlı mı?

Risk artıran durumlar:
- Bilinmeyen dış IP
- Hosting/VPS/TOR/proxy izlenimi
- Aynı IP'ye birden fazla endpoint bağlantısı
- IP'nin malicious veya suspicious olarak işaretlenmesi

---

### destination_domain

Network bağlantısının hedef domainidir.

Kontrol soruları:
- Domain güvenilir mi?
- Domain yeni mi?
- Domain marka taklidi veya rastgele görünüyor mu?
- Domain daha önce kurumda görülmüş mü?
- DNS loglarında başka endpointler de çözümlemiş mi?

Risk artıran durumlar:
- Yeni kayıtlı domain
- Rastgele karakterli domain
- Düşük reputation
- Phishing veya malware kampanyalarıyla ilişkili domain
- PowerShell komutu içinde doğrudan domain geçmesi

---

### url

Komut veya process tarafından kullanılan URL bilgisidir.

Kontrol soruları:
- URL dosya indiriyor mu?
- URL script veya executable içeriyor mu?
- URL kısa link veya redirect kullanıyor mu?
- URL güvenilir kaynak mı?

Risk artıran durumlar:
- Uzak script indirme
- IP tabanlı URL
- Şüpheli dosya uzantıları
- URL'den indirilen dosyanın çalıştırılması

---

## Dosya ve Sistem Değişikliği Alanları

### file_created

Process çalıştıktan sonra oluşturulan dosyalardır.

Kontrol soruları:
- Yeni dosya nerede oluşturulmuş?
- Dosya geçici klasörde mi?
- Dosya kullanıcı profilinde mi?
- Dosya çalıştırılabilir veya script mi?
- Dosya hash'i bilinen mi?

Risk artıran durumlar:
- Temp dizininde executable/script oluşturulması
- Startup klasörüne dosya yazılması
- Beklenmeyen DLL, EXE veya script oluşturulması
- Dosyanın kısa süre sonra çalıştırılması

---

### file_modified

Process çalıştıktan sonra değiştirilen dosyalardır.

Kontrol soruları:
- Hangi dosyalar değişti?
- Sistem veya güvenlik dosyaları etkilenmiş mi?
- Kullanıcı dokümanları şifrelenmiş veya toplu değişmiş mi?

Risk artıran durumlar:
- Güvenlik ayar dosyalarının değişmesi
- Çok sayıda dosyanın kısa sürede değişmesi
- Hassas dosyalara erişim veya değişiklik

---

### file_hash

Oluşturulan veya çalıştırılan dosyanın hash bilgisidir.

Kontrol soruları:
- Hash güvenlik araçlarında görülmüş mü?
- Hash kurum içinde daha önce var mı?
- Hash malicious veya suspicious olarak işaretlenmiş mi?

Risk artıran durumlar:
- Hash'in malicious çıkması
- Hash'in başka endpointlerde de görülmesi
- Hash'in yeni ve bilinmeyen olması

---

### registry_change

Registry üzerinde değişiklik yapılıp yapılmadığını gösterir.

Kontrol soruları:
- Registry persistence amacıyla mı değiştirilmiş?
- Run/RunOnce gibi başlangıç noktaları etkilenmiş mi?
- Güvenlik veya logging ayarları değiştirilmiş mi?
- Değişiklik kullanıcı tarafından beklenen bir kurulumdan mı kaynaklanıyor?

Risk artıran durumlar:
- Startup persistence
- Güvenlik aracı ayarlarıyla oynama
- Script veya executable'ın otomatik başlatılması
- Olağan dışı registry key değişiklikleri

---

### scheduled_task_created

Yeni scheduled task oluşturulup oluşturulmadığını gösterir.

Kontrol soruları:
- Yeni task ne zaman oluşturulmuş?
- Task hangi komutu çalıştırıyor?
- Task hangi kullanıcıyla çalışıyor?
- Task adı normal mi yoksa rastgele mi?
- Task persistence amacı taşıyor olabilir mi?

Risk artıran durumlar:
- PowerShell tarafından scheduled task oluşturulması
- Task'ın gizli veya rastgele isimli olması
- Task'ın dış URL'den script çalıştırması
- Task'ın yüksek yetkiyle çalışması

---

### service_created

Yeni servis oluşturulup oluşturulmadığını gösterir.

Kontrol soruları:
- Yeni servis ne zaman oluşturulmuş?
- Servisin binary path'i nedir?
- Servis adı normal mi?
- Servis yüksek yetkiyle mi çalışıyor?

Risk artıran durumlar:
- Beklenmeyen servis oluşturulması
- Servisin suspicious path'ten çalışması
- PowerShell sonrası servis oluşturulması
- Servisin persistence amacı taşıması

---

## Security Tool ve Detection Alanları

### edr_alert

Endpoint güvenlik aracının ürettiği alerttir.

Kontrol soruları:
- EDR hangi davranışı şüpheli bulmuş?
- Alert severity nedir?
- EDR process tree gösteriyor mu?
- EDR dosya, network veya registry kanıtı sunuyor mu?

Risk artıran durumlar:
- EDR'nin malicious veya high severity alert üretmesi
- Aynı process tree içinde birden fazla şüpheli davranış
- EDR'nin credential access, defense evasion veya persistence davranışı belirtmesi

---

### antivirus_detection

Antivirus tespit bilgisidir.

Kontrol soruları:
- Dosya veya process malicious olarak işaretlenmiş mi?
- Detection adı ne?
- Quarantine olmuş mu?
- Aynı detection başka endpointlerde var mı?

Risk artıran durumlar:
- Malicious detection
- Aynı hash'in birçok endpointte görülmesi
- Quarantine sonrası tekrar oluşma

---

### amsi_detection

AMSI veya script scanning tespitidir.

Kontrol soruları:
- Script içeriği şüpheli olarak yakalanmış mı?
- Hangi satır veya davranış tespit edilmiş?
- Tespit blocked mı yoksa allowed mı?

Risk artıran durumlar:
- AMSI malicious script tespiti
- Script'in çalışmaya devam etmiş olması
- Aynı script'in başka cihazlarda da görülmesi

---

## Zaman Çizelgesi Alanları

### event_time

Olayın gerçekleştiği zamandır.

Kontrol soruları:
- Olay mesai içinde mi dışında mı?
- Kullanıcı o sırada cihazı kullanıyor muydu?
- Aynı zamanda phishing, login veya network alerti var mı?
- Olaydan önce hangi process başladı?

Risk artıran durumlar:
- Mesai dışı suspicious execution
- Phishing mailinden hemen sonra PowerShell
- Suspicious login sonrası endpointte komut çalışması
- Aynı zaman aralığında başka güvenlik alertleri

---

### process_start_time

Process'in başladığı zamandır.

Kontrol soruları:
- Process hangi olaydan sonra başladı?
- Parent process ile zaman ilişkisi nedir?
- Kullanıcı etkileşimiyle mi başladı?

Risk artıran durumlar:
- Attachment açıldıktan hemen sonra PowerShell
- Browser download sonrası script execution
- Suspicious login sonrası command execution

---

## False Positive İhtimalleri

Suspicious PowerShell alertleri şu nedenlerle saldırı olmadan da oluşabilir:

- IT ekibi yönetim scripti çalıştırmış olabilir
- Yazılım dağıtım aracı PowerShell kullanmış olabilir
- EDR, backup, monitoring veya management agent script çalıştırmış olabilir
- Kurulum veya güncelleme süreci PowerShell kullanmış olabilir
- Kullanıcı meşru bir teknik işlem yapmış olabilir
- Kurumsal otomasyon aracı encoded command kullanmış olabilir
- Parent process güvenilir bir yönetim aracı olabilir
- Network bağlantısı meşru update veya internal service olabilir

Bu ihtimaller riski düşürebilir ama yine de command_line, parent_process, user, hostname ve network davranışı kontrol edilmelidir.

---

## Risk Artıran Göstergeler

Aşağıdaki bulgular olayın riskini artırır:

- Standart kullanıcı tarafından encoded PowerShell çalıştırılması
- Parent process'in Office, browser veya email client olması
- Parent process bilgisinin unknown olması
- PowerShell'in dış IP veya bilinmeyen domaine bağlanması
- Komutun uzak içerik indirmesi
- Obfuscated veya okunması zor command_line
- Execution policy bypass benzeri davranış
- Hidden execution davranışı
- PowerShell sonrası yeni dosya oluşturulması
- Registry persistence değişikliği
- Scheduled task veya servis oluşturulması
- EDR/AV/AMSI tespiti
- Aynı zaman aralığında phishing veya suspicious login alerti
- Kullanıcının bu çalıştırmayı reddetmesi

---

## SOC Analyst İçin Temel Kontrol Mantığı

Bir suspicious PowerShell alerti incelenirken şu sırayla düşünülmelidir:

1. Hangi cihazda çalıştı?
2. Hangi kullanıcı çalıştırdı?
3. Kullanıcı normalde PowerShell kullanır mı?
4. Process adı ve command_line nedir?
5. Encoded veya obfuscated komut var mı?
6. Parent process nedir?
7. Child process oluşmuş mu?
8. Network bağlantısı var mı?
9. Dosya oluşturulmuş veya değiştirilmiş mi?
10. Registry, scheduled task veya servis değişikliği var mı?
11. EDR/AV/AMSI tespiti var mı?
12. Aynı zamanda phishing, login veya başka endpoint alerti var mı?
13. Bu davranış meşru yönetim aracıyla açıklanabiliyor mu?
14. Olay tek cihazla mı sınırlı, yoksa başka cihazlarda da var mı?

---

## Incident'a Yükseltme Göstergeleri

Aşağıdaki bulgular görülürse olay incident olarak yükseltilebilir:

- Kullanıcı çalıştırmayı reddediyorsa
- PowerShell dış IP veya şüpheli domaine bağlandıysa
- Komut uzak içerik indirip çalıştırdıysa
- EDR/AV/AMSI malicious tespit verdiyse
- PowerShell sonrası suspicious child process oluştuysa
- Persistence göstergesi varsa
- Registry, scheduled task veya servis değişikliği şüpheliyse
- Credential access veya discovery davranışı görülüyorsa
- Aynı olay phishing tıklaması sonrası oluştuysa
- Aynı kullanıcıda suspicious login veya account compromise şüphesi varsa
- Aynı komut veya IOC birden fazla endpointte görülüyorsa

---

## Kısa Özet

Suspicious PowerShell incelemesinde en kritik sorular şunlardır:

- PowerShell'i kim çalıştırdı?
- Hangi cihazda çalıştı?
- Komut satırı ne içeriyor?
- Encoded veya obfuscated mı?
- Parent process nedir?
- Network bağlantısı var mı?
- Dosya, registry, scheduled task veya servis değişikliği var mı?
- EDR/AV/AMSI tespiti var mı?
- Davranış meşru yönetim aracıyla açıklanabiliyor mu?

PowerShell tek başına zararlı değildir. Risk, bağlam ve destekleyici kanıtlarla değerlendirilmelidir.
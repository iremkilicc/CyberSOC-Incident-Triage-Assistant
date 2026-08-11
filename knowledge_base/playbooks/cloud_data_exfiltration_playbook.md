# Cloud Data Exfiltration ve Toplu İndirme Playbook

## Amaç

SharePoint veya OneDrive üzerinde olağandışı toplu indirme, endpoint üzerinde
arşiv oluşturma ve kurum dışı bulut hedefine yükleme sinyallerini tek olay
zaman çizelgesinde değerlendirmek için SOC triaj rehberi.

## Aşama 1 — Anormal Toplu İndirme

Kısa sürede çok sayıda `FileDownloaded` olayı tek başına veri sızdırmayı
doğrulamaz. Kullanıcının geçmiş davranışı, iş görevi, kaynak IP, UserAgent,
cihaz yönetim durumu, SharePoint/OneDrive sitesi ve indirilen nesneler birlikte
doğrulanmalıdır. Meşru senkronizasyon, proje devri veya yedekleme olasılığı
ayrıştırılmadan kesin saldırgan atfı yapılmamalıdır.

## Aşama 2 — Hassas Veri Toplama ve Arşivleme

Toplu indirme sonrasında hassasiyet etiketli dosyaların endpoint üzerinde ZIP
arşivinde birleştirilmesi, olası veri toplama ve sızdırma hazırlığı göstergesidir.
Arşivin tam yolu, adı, boyutu, hash değeri, oluşturma zamanı ve oluşturan süreç
ağacı korunmalıdır. Dosyalar yeniden açılmadan bulut audit, endpoint ve DLP
telemetrisiyle ilişkilendirilmelidir.

## Aşama 3 — Kurum Dışı Hedefe Aktarım

Proxy, tarayıcı, DLP veya endpoint ağ kayıtlarında arşivin kurum dışı bulut
hedefine başarıyla yüklendiği doğrulanırsa olay veri sızdırma olarak ele
alınmalıdır. Hedef alan adı ve URL, kaynak cihaz, kullanıcı, oturum, zaman,
aktarılan bayt miktarı, arşiv hash değeri ve yüklemeyi başlatan süreç tek zaman
çizelgesinde korunmalıdır.

## Aşama 4 — Çoklu Kullanıcı veya Cihaz Kapsamı

Aynı dış hedef, arşivleme davranışı, dosya hashleri veya yükleme süreci başka
kullanıcı ve cihazlarda da görülürse olay tek kullanıcıyla sınırlı sayılmamalıdır.
Kurum genelinde avcılık yapılarak toplam kullanıcı, cihaz, veri hacmi, kaynak
siteler, hassas veri kümeleri ve ilk-son etkinlik zamanları belirlenmelidir.

## Öncelikli SOC Aksiyonları

1. Purview, Entra, endpoint, proxy, DNS, tarayıcı ve DLP kanıtlarını değişmeden koruyun.
2. İndirme, arşivleme ve yükleme olaylarını kullanıcı, cihaz, IP, oturum ve zaman üzerinden korele edin.
3. Dış aktarım doğrulanırsa veri güvenliği, hukuk, gizlilik ve olay müdahale ekiplerine eskale edin.
4. Aktif aktarım, oturum, hesap veya cihaz sınırlandırmasını yalnızca kanıt koruma sonrasında kurum prosedürü ve yetkili onayla uygulayın.

## Kaynaklar

- Microsoft Learn, Audit log activities: https://learn.microsoft.com/en-us/purview/audit-log-activities
- Microsoft Learn, Detailed activity properties in the audit log: https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties
- Microsoft Learn, Investigate activities in Defender for Cloud Apps: https://learn.microsoft.com/en-us/defender-cloud-apps/activity-filters
- MITRE ATT&CK T1530, Data from Cloud Storage: https://attack.mitre.org/techniques/T1530/
- MITRE ATT&CK T1560, Archive Collected Data: https://attack.mitre.org/techniques/T1560/
- MITRE ATT&CK T1567.002, Exfiltration to Cloud Storage: https://attack.mitre.org/techniques/T1567/002/


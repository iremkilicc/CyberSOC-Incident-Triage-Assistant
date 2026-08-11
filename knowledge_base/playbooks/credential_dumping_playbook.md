# Credential Dumping / LSASS Bellek Erişimi SOC Playbook

## Amaç ve Kapsam

Bu playbook, Windows endpointlerinde LSASS sürecine olağandışı erişim, bellek dump dosyası oluşturma ve ardından ayrıcalıklı hesap kullanımı görülen alarmların savunma amaçlı SOC triajını kapsar. Tek bir ProcessAccess olayı doğrudan ihlal kanıtı değildir; güvenlik, yedekleme ve tanılama yazılımları da LSASS erişimi üretebilir.

## Aşama 1 — Şüpheli LSASS Süreç Erişimi

Sysmon Event ID 10 veya eşdeğer EDR telemetrisinde SourceImage, TargetImage, GrantedAccess, ProcessGuid, User ve CallTrace alanlarını koruyun. Kaynak dosyanın yolu, hash'i, dijital imzası, parent process'i ve kurumsal allowlist durumu doğrulanmadan LSASS belleğinin gerçekten döküldüğünü varsaymayın.

Risk başlangıçta Orta olabilir. Beklenmeyen bir sistem aracı, kullanıcı yazılabilir dizinden çalışan imzasız süreç, olağandışı erişim hakları veya şüpheli parent process riski yükseltir.

## Aşama 2 — Dump Oluşturmanın Doğrulanması

LSASS erişimini Sysmon Event ID 11, EDR FileCreate ve Windows 4688 süreç oluşturma kayıtlarıyla zaman çizelgesinde birleştirin. Dump dosyasının tam yolu, oluşturma zamanı, boyutu, hash'i ve oluşturan ProcessGuid değerini belirleyin. comsvcs.dll MiniDump gibi yerleşik bileşen kullanımı tek başına meşruluk kanıtı değildir; süreç zinciri ve iş amacı incelenmelidir.

LSASS dump dosyası oluşturulduğunda credential dumping olasılığı güçlenir ve risk Yüksek seviyeye çıkar. Dosyayı yeniden açmayın veya saldırı komutunu yeniden çalıştırmayın; kanıtı hash, yol ve zaman bilgisiyle güvenli biçimde koruyun.

## Aşama 3 — Kimlik Etkisinin Doğrulanması

Dump zamanından sonraki Windows 4624, etki alanı denetleyicisi kimlik doğrulama, VPN, Entra ve kritik sistem oturumlarını araştırın. TargetUserName, LogonType, WorkstationName, SourceNetworkAddress, LogonId ve zaman alanlarını endpoint olaylarıyla korele edin.

Ayrıcalıklı hesabın etkilenen endpointten olağandışı başarılı oturum açması ve hesap sahibinin işlemi reddetmesi, çalınan kimlik materyalinin kötüye kullanıldığı hipotezini yüksek güvenle destekler. Bu durumda olay Kritik öncelikte ele alınmalıdır.

## Aşama 4 — Kampanya Kapsamı

Aynı SourceImage, hash, LSASS TargetImage, GrantedAccess, dump yolu veya yöntemi ve ilişkili hesap kullanımını tüm EDR filosunda araştırın. Etkilenen endpoint ve ayrıcalıklı hesap sayılarını tahmin etmek yerine kayıtlarla doğrulayın; her varlık için ilk ve son etkinlik zamanını çıkarın.

Birden fazla endpointte aynı davranış görüldüğünde olayı kurum geneli credential dumping kampanyası olarak kapsamlandırın. Kanıt koruma sonrasında endpoint sınırlandırma, oturum sonlandırma ve parola, servis sırrı veya bilet döndürme işlemlerini kurum prosedürü ve yetkili onayla koordine edin.

## Öncelikli SOC Aksiyonları

- ProcessAccess, ProcessCreate, FileCreate ve kimlik doğrulama kayıtlarını değişmeden koruyun.
- LSASS erişimi, dump dosyası ve sonraki hesap kullanımını tek zaman çizelgesinde birleştirin.
- Etkilenen endpointleri, dump sırasında bellekte bulunabilecek hesapları ve erişilen kaynakları belirleyin.
- Aynı hash, süreç zinciri, dump göstergesi ve hesap kullanımını kurum genelinde araştırın.
- Kimlik ve endpoint müdahalesini kanıt koruma sonrasında yetkili ekiplerle uygulayın.

## Kaynaklar

- MITRE ATT&CK T1003 — OS Credential Dumping: https://attack.mitre.org/techniques/T1003/
- MITRE ATT&CK T1003.001 — LSASS Memory: https://attack.mitre.org/techniques/T1003/001/
- Microsoft Sysmon olayları: https://learn.microsoft.com/sysinternals/downloads/sysmon
- Microsoft Windows 4688: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688
- Microsoft Windows 4624: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624

# Credential Dumping İnceleme Alanları

## Sysmon Event ID 10 — ProcessAccess

- UtcTime ve RuleName
- SourceProcessGuid, SourceProcessId ve SourceImage
- TargetProcessGuid, TargetProcessId ve TargetImage
- GrantedAccess, CallTrace ve User
- Kaynak dosyanın SHA256 değeri, imza ve signer bilgisi

TargetImage değeri LSASS olduğunda SourceImage ve GrantedAccess tek başına yeterli değildir. Süreç yolu, imza, parent process, allowlist ve aynı zaman aralığındaki dosya oluşturma olaylarıyla birlikte değerlendirin.

## Süreç Oluşturma Alanları

- Windows 4688 NewProcessId, NewProcessName ve ProcessCommandLine
- CreatorProcessId ve CreatorProcessName
- SubjectUserName, SubjectDomainName ve MandatoryLabel
- EDR process tree, parent-child ilişkisi ve bütünlük seviyesi

ProcessCommandLine alanının Windows denetim ilkesine bağlı olarak boş olabileceğini dikkate alın. Eksikse EDR süreç telemetrisi ve Sysmon ProcessCreate kayıtlarıyla tamamlayın.

## Dump Dosyası Alanları

- Tam dosya yolu ve dosya adı
- Oluşturma, değiştirme ve silme zamanları
- Dosya boyutu ve SHA256 değeri
- Oluşturan ProcessGuid ve kullanıcı
- Sysmon Event ID 11 veya eşdeğer EDR FileCreate kaydı
- Dosyanın taşınma, arşivlenme veya ağ üzerinden aktarılma izleri

## Kimlik Doğrulama Alanları

- Windows 4624 TargetUserName ve TargetDomainName
- LogonType, LogonProcessName ve AuthenticationPackageName
- WorkstationName ve SourceNetworkAddress
- LogonId, ProcessName ve ElevatedToken
- Hedef sistem, erişilen kaynak ve ilk-son etkinlik zamanı

## Kapsam Alanları

- Etkilenen endpoint adı, varlık sahibi ve kritikliği
- Dump sırasında oturum açmış kullanıcı ve servis hesapları
- Etkilenen ayrıcalıklı hesap sayısı
- Aynı SourceImage, hash, GrantedAccess, dump yolu ve yönteminin diğer endpointlerde görülmesi
- Her endpoint ve hesap için ilk ve son kötü amaçlı etkinlik zamanı

## Kritik Seviyeye Yükseltme Göstergeleri

- LSASS dump dosyası sonrası yetkisiz ayrıcalıklı hesap oturumu
- Hesap sahibinin ilgili oturumu veya işlemi reddetmesi
- Etki alanı denetleyicisi veya kritik sunucu erişimi
- Aynı credential dumping davranışının birden fazla endpointte görülmesi
- Birden fazla ayrıcalıklı veya servis hesabının etkilenmesi

## Kaynaklar

- Microsoft Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon
- Microsoft Windows 4688: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688
- Microsoft Windows 4624: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624

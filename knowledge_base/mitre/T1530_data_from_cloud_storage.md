# MITRE ATT&CK T1530 — Data from Cloud Storage

## Teknik Özet

Saldırganlar, geçerli kimlik bilgileri veya uygulama erişimleriyle bulut
depolama hizmetlerindeki verileri toplayabilir. SharePoint ve OneDrive gibi
kurumsal bulut depolarında kısa sürede yüksek hacimli indirme, kullanıcının
normal davranışı ve iş göreviyle karşılaştırılmalıdır.

## SOC İçin Ana Bulgular

- Bulut audit kayıtlarında kullanıcı, kaynak IP, UserAgent, cihaz ve dosya yolu.
- Kısa zaman penceresinde olağandışı dosya sayısı veya veri hacmi.
- Hassasiyet etiketli ya da iş açısından kritik klasörlerin hedeflenmesi.
- Yönetilmeyen cihaz, olağandışı oturum veya kullanıcının etkinliği reddetmesi.
- İndirme sonrasında endpoint üzerinde arşivleme ve dış bağlantı etkinliği.

## Korelasyon

`FileDownloaded` kayıtları Entra sign-in, cihaz yönetim durumu, endpoint dosya
olayları ve ağ telemetrisiyle birleştirilmelidir. Bulut verisinin indirilmesi
toplama aşamasını gösterebilir; kurum dışına aktarım ayrı kanıtla doğrulanmalıdır.

## Kaynak

MITRE ATT&CK: https://attack.mitre.org/techniques/T1530/


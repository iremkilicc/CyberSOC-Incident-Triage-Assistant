# Data Exfiltration İnceleme Alanları

## Microsoft 365 Audit Alanları

- `Operation`: Özellikle `FileDownloaded`; gerekirse erişim, paylaşım ve silme olayları.
- `CreationTime`: Olayın UTC zamanı.
- `UserId` ve `UserKey`: Etkinliği gerçekleştiren kimlik.
- `ClientIP`: Kaynak IP ve bilinen kurumsal ağ/VPN karşılaştırması.
- `UserAgent`: Tarayıcı, OneDrive istemcisi, API veya otomasyon ayrımı.
- `ObjectId`: Erişilen dosya ya da klasörün tam URL yolu.
- `SiteUrl` ve `SourceFileName`: Kaynak site ve dosya kapsamı.
- `Workload`: SharePoint veya OneDrive bağlamı.

## Kimlik ve Cihaz Alanları

- Entra sign-in zamanı, kaynak IP, konum, cihaz kimliği, MFA ve Conditional Access sonucu.
- Cihazın kurumsal yönetim, uyumluluk, sahiplik ve EDR durumu.
- Aynı kullanıcı, IP, cihaz ve oturumun önceki 30 günlük davranış çizgisi.

## Hassas Veri ve Arşiv Alanları

- Hassasiyet etiketi, DLP eşleşmesi, veri sahibi ve kaynak site.
- Arşiv adı, tam yol, boyut, SHA-256 hash, oluşturma ve son değiştirme zamanı.
- Arşivi oluşturan süreç, komut satırı, parent süreç ve kullanıcı oturumu.
- Arşiv içeriğine yeniden erişmeden kaynak dosya listesi ve audit korelasyonu.

## Ağ ve Yükleme Alanları

- Hedef alan adı, URL, kategori, DNS çözümlemesi ve sertifika bilgisi.
- Kaynak cihaz, kullanıcı, süreç, tarayıcı profili ve oturum kimliği.
- İstek başlangıç/bitiş zamanı, HTTP yöntemi, durum kodu ve aktarılan bayt miktarı.
- Proxy, CASB, DLP, tarayıcı ve endpoint ağ olaylarının correlation/session değerleri.

## Incident'a Yükseltme Göstergeleri

- Yönetilmeyen cihazdan kısa sürede yüksek hacimli `FileDownloaded` etkinliği.
- Hassasiyet etiketli dosyaların toplu indirilmesi ve arşivlenmesi.
- Arşivin kullanıcı tarafından tanınmayan kurum dışı bulut hedefine yüklenmesi.
- Başarılı aktarım ve kullanıcı tarafından etkinliğin reddedilmesi.
- Aynı hedef veya davranışın başka kullanıcı ve cihazlarda görülmesi.

## Bilinen Bilgiyi Yeniden Sormama

Kullanıcı bir indirme sayısını, zaman penceresini, hassas dosya sayısını, arşiv
adını, dış hedefi, aktarım sonucunu veya toplam etki sayısını açıkça doğruladıysa
bu bilgi takip sorusu olarak yeniden sorulmamalıdır. Sorular yalnızca henüz
bilinmeyen dosya kimlikleri, veri sahipleri, ilk-son zamanlar ve ek kapsam gibi
kararı değiştirecek alanlara yönelmelidir.

## Kaynaklar

- https://learn.microsoft.com/en-us/purview/audit-log-activities
- https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties
- https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema


# Endpoint Investigation Fields

## Amaç

Bu dosya, endpoint yani kullanıcı cihazı veya sunucu üzerinde oluşan şüpheli olayları incelerken hangi alanlara bakılması gerektiğini açıklar.

Suspicious PowerShell, malware activity, suspicious process veya command execution olaylarında bu alanlar SOC analyst için önemlidir.

## Önemli Alanlar

### user

Komutu veya process’i çalıştıran kullanıcı hesabıdır.

Kontrol soruları:
- Kullanıcı normalde bu işlemi yapar mı?
- Kullanıcı teknik veya admin yetkili biri mi?
- Kullanıcı yakın zamanda phishing olayı yaşamış mı?

### command_line

Çalıştırılan komutun tam satır bilgisidir.

Kontrol soruları:
- Komut açık ve anlaşılır mı?
- Komut gizlenmiş veya encoded görünüyor mu?
- Komut dosya indirme, script çalıştırma veya dış bağlantı içeriyor mu?

### parent_process

Şüpheli process’i hangi process’in başlattığını gösterir.

Kontrol soruları:
- PowerShell normal terminalden mi başlatılmış?
- Word, Excel, browser veya bilinmeyen process PowerShell başlatmış mı?
- Parent process beklenen bir uygulama mı?

### process_name

Çalışan process’in adıdır.

Kontrol soruları:
- Process adı beklenen bir sistem aracı mı?
- Process adı sahte veya yanıltıcı görünüyor mu?
- Process olağan dışı bir klasörden mi çalışmış?

### encoded_command

Komutun encoded/gizlenmiş şekilde çalıştırılıp çalıştırılmadığını gösterir.

Bu alan önemlidir çünkü saldırganlar komut içeriğini gizlemek için encoded komutlar kullanabilir. Ancak encoded command tek başına kesin saldırı değildir.

### endpoint_name

Olayın gerçekleştiği cihaz adıdır.

Kontrol soruları:
- Cihaz kritik sistem mi?
- Kullanıcı cihazı mı, sunucu mu?
- Aynı cihazda başka alert var mı?

### network_connection

Komut veya process sonrası ağ bağlantısı oluşup oluşmadığını gösterir.

Kontrol soruları:
- Dış IP veya bilinmeyen domaine bağlantı var mı?
- Bağlantı komuttan hemen sonra mı oluşmuş?
- Bağlantı beklenen bir servisle mi ilişkili?

### related_alerts

Aynı cihaz veya kullanıcıyla ilişkili diğer güvenlik uyarılarıdır.

Kontrol soruları:
- Aynı zamanda phishing alerti var mı?
- Malware veya suspicious file alerti var mı?
- Login anomaly veya credential alerti var mı?

## Asistanın Kullanacağı Not

Endpoint olaylarında tek bir alanla kesin karar verilmemelidir. Kullanıcı, command_line, parent_process, endpoint geçmişi, network bağlantısı ve related_alerts birlikte değerlendirilmelidir.
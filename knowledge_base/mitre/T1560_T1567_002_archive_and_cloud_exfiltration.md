# MITRE ATT&CK T1560 ve T1567.002 — Arşivleme ve Bulut Depolamaya Sızdırma

## T1560 — Archive Collected Data

Saldırganlar toplanan veriyi sızdırmadan önce sıkıştırabilir veya arşivleyebilir.
Toplu indirme sonrasında ZIP arşivi oluşturulması; arşiv adı, yolu, boyutu, hash
değeri ve süreç ağacıyla incelenmelidir. Arşivleme tek başına dış aktarımı
doğrulamaz ancak hassas veri toplama bağlamında güçlü bir yükseltme sinyalidir.

## T1567.002 — Exfiltration to Cloud Storage

Saldırganlar veriyi kurum dışına çıkarmak için bulut depolama hizmetlerini
kullanabilir. Proxy, CASB, DLP, tarayıcı veya endpoint kayıtlarında arşivin
harici bulut hedefine başarılı biçimde yüklenmesi doğrulanırsa sızdırma etkisi
teknik olarak doğrulanmış kabul edilmelidir.

## SOC İçin Ana Bulgular

- Arşiv dosyasının SHA-256 değeri, tam yolu ve oluşturan süreç.
- Hedef alan adı/URL, yükleme zamanı, HTTP sonucu ve aktarılan bayt miktarı.
- Kaynak kullanıcı, cihaz, IP, oturum ve tarayıcı profili.
- Aynı hedef, hash, süreç veya davranışın başka kullanıcı ve cihazlarda görülmesi.
- Dışarı aktarılan veri kümelerinin hassasiyeti, sahipleri ve toplam hacmi.

## Güvenli Müdahale

Kanıtlar korunmadan arşiv silinmemeli veya şüpheli süreç yeniden çalıştırılmamalıdır.
Aktif aktarım, hesap, oturum, cihaz ve dış hedef kontrolleri kurum prosedürü ve
yetkili onay altında uygulanmalıdır.

## Kaynaklar

- MITRE ATT&CK T1560: https://attack.mitre.org/techniques/T1560/
- MITRE ATT&CK T1567.002: https://attack.mitre.org/techniques/T1567/002/


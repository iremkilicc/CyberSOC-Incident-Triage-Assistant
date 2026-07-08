# T1059 - Command and Scripting Interpreter

## Kısa Açıklama

Command and Scripting Interpreter, saldırganların sistemde komut veya script çalıştırmak için işletim sistemindeki yorumlayıcıları kullanmasıdır.

Windows tarafında PowerShell, cmd gibi araçlar; Linux tarafında shell veya bash gibi araçlar bu kategoriye örnek olabilir. Bu araçlar sistem yöneticileri tarafından normal amaçlarla da kullanılır, bu yüzden tek başına komut çalıştırılması kesin saldırı anlamına gelmez.

## Bu Teknik Ne Zaman Düşünülür?

Aşağıdaki durumlarda T1059 düşünülebilir:

- PowerShell, cmd veya benzer komut araçları beklenmeyen şekilde çalıştırılmışsa
- Encoded veya gizlenmiş komut kullanılmışsa
- Komut normal kullanıcı hesabı tarafından çalıştırılmışsa
- Komut beklenmeyen bir parent process tarafından başlatılmışsa
- Komut çalıştıktan sonra ağ bağlantısı veya dosya indirme davranışı görülmüşse
- Komut bir phishing maili, şüpheli ek dosya veya bilinmeyen process sonrası çalışmışsa
- Aynı endpoint üzerinde başka güvenlik alertleri oluşmuşsa

## Tipik Kanıtlar

- command_line bilgisi
- process_name
- parent_process
- encoded_command kullanımı
- user bilgisi
- endpoint_name
- timestamp
- network_connection bilgisi
- related_alerts
- process tree veya child process bilgisi

## SOC Analyst İlk Neye Bakar?

- Komutu hangi kullanıcı çalıştırdı?
- Kullanıcı normalde bu aracı kullanır mı?
- Komut satırında ne yazıyor?
- Encoded command varsa gerçek içerik nedir?
- PowerShell’i hangi parent process başlatmış?
- Komut sonrası dış bağlantı oluşmuş mu?
- Komut dosya indirme veya yeni process başlatma davranışı göstermiş mi?
- Aynı cihazda başka alert var mı?
- Kullanıcı yakın zamanda phishing maili açmış olabilir mi?

## False Positive İhtimali

T1059 benzeri alertler bazen saldırı dışı nedenlerle oluşabilir:

- Sistem yöneticisi bakım işlemi yapıyor olabilir.
- Kurumsal yönetim aracı script çalıştırıyor olabilir.
- Yazılım kurulumu veya güncelleme PowerShell kullanıyor olabilir.
- Güvenlik aracı otomatik kontrol yapıyor olabilir.
- Kullanıcı teknik bir işlem için komut çalıştırmış olabilir.

## İlişkili Teknikler

- T1566 - Phishing
- T1078 - Valid Accounts
- T1003 - Credential Dumping

## Kaynak Notu

Bu dosya MITRE ATT&CK T1059 Command and Scripting Interpreter tekniğinin eğitim amaçlı sadeleştirilmiş özetidir. Projede kaynaklı cevap üretimi için kullanılacaktır.
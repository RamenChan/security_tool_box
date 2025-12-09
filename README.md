# Security Tool Box

Siber güvenlik uzmanları için Python ile yazılmış 25 farklı güvenlik aracı koleksiyonu.

## İçindekiler

1. [Network Security](#network-security)
2. [Web Security](#web-security)
3. [Cryptography](#cryptography)
4. [System Security](#system-security)
5. [Forensics & Analysis](#forensics--analysis)
6. [Kurulum](#kurulum)
7. [Uyarılar](#uyarılar)

---

## Network Security

### 1. port_scanner.py
**Açıklama:** Hedef sistemdeki açık portları tespit etmek için kullanılan port tarama aracı.

**Kullanım:**
```bash
python network_security/port_scanner.py <hedef> [başlangıç_port] [bitiş_port]
```

**Örnekler:**
```bash
python network_security/port_scanner.py example.com
python network_security/port_scanner.py 192.168.1.1 1 1024
python network_security/port_scanner.py scanme.nmap.org 80 443
```

**Özellikler:**
- Belirtilen port aralığını tarar
- Açık portları tespit eder
- Bağlantı zaman aşımı kontrolü
- Hızlı tarama modu

---

### 2. packet_sniffer.py
**Açıklama:** Ağ trafiğini yakalayan ve analiz eden paket dinleme aracı. Ethernet, IP ve TCP katmanlarındaki bilgileri görüntüler.

**Kullanım:**
```bash
python network_security/packet_sniffer.py
```

**Özellikler:**
- Ethernet frame analizi
- IPv4 paket analizi
- TCP segment analizi
- ICMP, UDP ve diğer protokol desteği
- Gerçek zamanlı paket yakalama

**Not:** Bu araç root/administrator yetkisi gerektirir.

---

### 3. network_scanner.py
**Açıklama:** Ağdaki aktif hostları tespit etmek için ping sweep yapan ağ tarama aracı.

**Kullanım:**
```bash
python network_security/network_scanner.py <ağ> [zaman_aşımı]
```

**Örnekler:**
```bash
python network_security/network_scanner.py 192.168.1.0/24
python network_security/network_scanner.py 10.0.0.0/24 2
```

**Özellikler:**
- CIDR notasyonu desteği
- Ping sweep ile host keşfi
- Özelleştirilebilir zaman aşımı
- Aktif host listesi

---

### 4. banner_grabber.py
**Açıklama:** Hedef sistemdeki servislerin banner bilgilerini toplar ve versiyon tespiti yapar.

**Kullanım:**
```bash
python network_security/banner_grabber.py <hedef> <port>
```

**Örnekler:**
```bash
python network_security/banner_grabber.py example.com 80
python network_security/banner_grabber.py 192.168.1.1 22
python network_security/banner_grabber.py scanme.nmap.org 21
```

**Özellikler:**
- Servis banner bilgisi toplama
- Versiyon tespiti
- HTTP, FTP, SSH gibi servisleri destekler
- Zaman aşımı kontrolü

---

### 5. syn_scanner.py
**Açıklama:** SYN paketleri göndererek gizli port taraması yapan araç. Tam TCP bağlantısı kurmadan port durumunu tespit eder.

**Kullanım:**
```bash
python network_security/syn_scanner.py <hedef> [başlangıç_port] [bitiş_port]
```

**Örnekler:**
```bash
python network_security/syn_scanner.py example.com
python network_security/syn_scanner.py 192.168.1.1 1 1000
```

**Özellikler:**
- Stealth (gizli) tarama
- SYN-ACK yanıtlarını analiz eder
- Hızlı tarama
- Düşük iz bırakma

**Not:** Bu araç root/administrator yetkisi gerektirir.

---

## Web Security

### 6. sql_injection_scanner.py
**Açıklama:** Web uygulamalarında SQL injection zafiyetlerini tespit eden otomatik tarayıcı.

**Kullanım:**
```bash
python web_security/sql_injection_scanner.py <url> <parametre>
```

**Örnekler:**
```bash
python web_security/sql_injection_scanner.py http://example.com/page.php id
python web_security/sql_injection_scanner.py http://testsite.com/product.php product_id
```

**Özellikler:**
- Çoklu SQL injection payload testi
- Error-based SQL injection tespiti
- GET parametresi testi
- Zafiyet raporlama

---

### 7. xss_scanner.py
**Açıklama:** Cross-Site Scripting (XSS) zafiyetlerini tespit eden tarayıcı. Hem parametreleri hem de formları test eder.

**Kullanım:**
```bash
python web_security/xss_scanner.py param <url> <parametre>
python web_security/xss_scanner.py form <url>
```

**Örnekler:**
```bash
python web_security/xss_scanner.py param http://example.com/search.php q
python web_security/xss_scanner.py form http://example.com/contact.php
```

**Özellikler:**
- Reflected XSS tespiti
- Form tabanlı XSS testi
- Çoklu XSS payload desteği
- Otomatik form keşfi

---

### 8. web_crawler.py
**Açıklama:** Web sitelerini tarayarak linkleri, e-posta adreslerini ve subdomain'leri toplayan crawler.

**Kullanım:**
```bash
python web_security/web_crawler.py <url> [derinlik]
```

**Örnekler:**
```bash
python web_security/web_crawler.py https://example.com
python web_security/web_crawler.py https://example.com 3
```

**Özellikler:**
- Recursive link takibi
- E-posta adresi toplama
- Subdomain keşfi
- Özelleştirilebilir tarama derinliği
- Ziyaret edilen URL takibi

---

### 9. directory_bruteforce.py
**Açıklama:** Web sunucularında gizli dizin ve dosyaları keşfetmek için brute force saldırısı yapan araç.

**Kullanım:**
```bash
python web_security/directory_bruteforce.py <url> <wordlist>
```

**Örnekler:**
```bash
python web_security/directory_bruteforce.py http://example.com wordlist.txt
python web_security/directory_bruteforce.py https://testsite.com/admin common_dirs.txt
```

**Özellikler:**
- Wordlist tabanlı tarama
- HTTP durum kodu kontrolü
- Bulunan dizinleri raporlama
- Özelleştirilebilir wordlist

---

### 10. http_header_analyzer.py
**Açıklama:** Web sitelerinin HTTP güvenlik başlıklarını analiz eden ve eksik güvenlik önlemlerini raporlayan araç.

**Kullanım:**
```bash
python web_security/http_header_analyzer.py <url>
```

**Örnekler:**
```bash
python web_security/http_header_analyzer.py https://example.com
python web_security/http_header_analyzer.py http://testsite.com
```

**Özellikler:**
- X-Frame-Options kontrolü
- X-XSS-Protection kontrolü
- X-Content-Type-Options kontrolü
- Strict-Transport-Security kontrolü
- Content-Security-Policy kontrolü
- Güvenlik önerileri

---

## Cryptography

### 11. hash_generator.py
**Açıklama:** Metin ve dosyalar için çeşitli hash algoritmaları ile hash değeri üreten ve doğrulayan araç.

**Kullanım:**
```bash
python cryptography/hash_generator.py text <metin> [algoritma]
python cryptography/hash_generator.py file <dosya> [algoritma]
python cryptography/hash_generator.py verify <dosya> <hash>
```

**Örnekler:**
```bash
python cryptography/hash_generator.py text "Merhaba Dünya"
python cryptography/hash_generator.py text "Secret" sha256
python cryptography/hash_generator.py file document.pdf
python cryptography/hash_generator.py verify file.zip abc123def456...
```

**Desteklenen Algoritmalar:**
- MD5
- SHA1
- SHA256
- SHA512

---

### 12. symmetric_encryption.py
**Açıklama:** Simetrik şifreleme algoritmaları (AES, DES3) kullanarak veri şifreleme ve şifre çözme aracı.

**Kullanım:**
```bash
python cryptography/symmetric_encryption.py encrypt <metin> <algoritma>
python cryptography/symmetric_encryption.py decrypt <şifreli_metin> <anahtar> <algoritma>
```

**Örnekler:**
```bash
python cryptography/symmetric_encryption.py encrypt "Gizli Mesaj" AES
python cryptography/symmetric_encryption.py decrypt "encrypted_data" "key123" AES
python cryptography/symmetric_encryption.py encrypt "Secret" DES3
```

**Desteklenen Algoritmalar:**
- AES (Advanced Encryption Standard)
- DES3 (Triple DES)

---

### 13. rsa_encryption.py
**Açıklama:** RSA asimetrik şifreleme ile anahtar üretimi, şifreleme, şifre çözme ve dijital imzalama aracı.

**Kullanım:**
```bash
python cryptography/rsa_encryption.py generate <anahtar_boyutu>
python cryptography/rsa_encryption.py encrypt <metin> <public_key_file>
python cryptography/rsa_encryption.py decrypt <şifreli_metin> <private_key_file>
python cryptography/rsa_encryption.py sign <metin> <private_key_file>
python cryptography/rsa_encryption.py verify <metin> <imza> <public_key_file>
```

**Örnekler:**
```bash
python cryptography/rsa_encryption.py generate 2048
python cryptography/rsa_encryption.py encrypt "Secret Message" public.pem
python cryptography/rsa_encryption.py decrypt encrypted.txt private.pem
```

**Özellikler:**
- RSA anahtar çifti üretimi
- Public key şifreleme
- Private key şifre çözme
- Dijital imza oluşturma
- İmza doğrulama

---

### 14. classical_ciphers.py
**Açıklama:** Klasik şifreleme yöntemlerini (Caesar, Vigenere, Substitution, Atbash) uygulayan araç.

**Kullanım:**
```bash
python cryptography/classical_ciphers.py caesar <metin> <kaydırma>
python cryptography/classical_ciphers.py vigenere <metin> <anahtar>
python cryptography/classical_ciphers.py substitution <metin> <anahtar>
python cryptography/classical_ciphers.py atbash <metin>
```

**Örnekler:**
```bash
python cryptography/classical_ciphers.py caesar "HELLO WORLD" 3
python cryptography/classical_ciphers.py vigenere "SECRET" "KEY"
python cryptography/classical_ciphers.py atbash "ABCXYZ"
```

**Desteklenen Şifreler:**
- Caesar Cipher (Kaydırma şifresi)
- Vigenere Cipher (Anahtar kelime şifresi)
- Substitution Cipher (Yerine koyma şifresi)
- Atbash Cipher (Ters alfabe şifresi)

---

### 15. password_generator.py
**Açıklama:** Güçlü ve rastgele şifreler üreten, şifre gücünü kontrol eden araç.

**Kullanım:**
```bash
python cryptography/password_generator.py generate [uzunluk]
python cryptography/password_generator.py check <şifre>
```

**Örnekler:**
```bash
python cryptography/password_generator.py generate
python cryptography/password_generator.py generate 20
python cryptography/password_generator.py check "MyP@ssw0rd123"
```

**Özellikler:**
- Rastgele şifre üretimi
- Büyük/küçük harf, rakam ve özel karakter desteği
- Şifre gücü analizi
- Özelleştirilebilir uzunluk

---

## System Security

### 16. file_integrity_checker.py
**Açıklama:** Dosya ve dizinlerin bütünlüğünü kontrol eden, değişiklikleri tespit eden araç.

**Kullanım:**
```bash
python system_security/file_integrity_checker.py create <dizin> <baseline_dosya>
python system_security/file_integrity_checker.py check <dizin> <baseline_dosya>
```

**Örnekler:**
```bash
python system_security/file_integrity_checker.py create /var/www baseline.txt
python system_security/file_integrity_checker.py check /var/www baseline.txt
```

**Özellikler:**
- SHA256 hash tabanlı kontrol
- Baseline oluşturma
- Değişiklik tespiti
- Yeni/silinmiş dosya tespiti
- Recursive dizin tarama

---

### 17. process_monitor.py
**Açıklama:** Sistem süreçlerini izleyen, şüpheli süreçleri tespit eden ve kaynak kullanımını analiz eden araç.

**Kullanım:**
```bash
python system_security/process_monitor.py list
python system_security/process_monitor.py suspicious
python system_security/process_monitor.py monitor <pid>
python system_security/process_monitor.py kill <pid>
```

**Örnekler:**
```bash
python system_security/process_monitor.py list
python system_security/process_monitor.py suspicious
python system_security/process_monitor.py monitor 1234
python system_security/process_monitor.py kill 5678
```

**Özellikler:**
- Tüm süreçleri listeleme
- Şüpheli süreç tespiti
- CPU ve bellek kullanımı izleme
- Süreç sonlandırma
- Gerçek zamanlı izleme

---

### 18. permission_auditor.py
**Açıklama:** Dosya ve dizin izinlerini denetleyen, güvenlik risklerini tespit eden araç.

**Kullanım:**
```bash
python system_security/permission_auditor.py audit <dizin>
python system_security/permission_auditor.py suid <dizin>
python system_security/permission_auditor.py writable <dizin>
```

**Örnekler:**
```bash
python system_security/permission_auditor.py audit /home/user
python system_security/permission_auditor.py suid /usr/bin
python system_security/permission_auditor.py writable /tmp
```

**Özellikler:**
- İzin denetimi
- SUID/SGID bit tespiti
- World-writable dosya tespiti
- Güvenlik önerileri
- Recursive tarama

---

### 19. log_analyzer.py
**Açıklama:** Sistem loglarını analiz eden, güvenlik olaylarını tespit eden ve raporlayan araç.

**Kullanım:**
```bash
python system_security/log_analyzer.py analyze <log_dosya>
python system_security/log_analyzer.py failed <log_dosya>
python system_security/log_analyzer.py suspicious <log_dosya>
python system_security/log_analyzer.py ips <log_dosya>
```

**Örnekler:**
```bash
python system_security/log_analyzer.py analyze /var/log/auth.log
python system_security/log_analyzer.py failed /var/log/auth.log
python system_security/log_analyzer.py suspicious /var/log/syslog
python system_security/log_analyzer.py ips /var/log/apache2/access.log
```

**Özellikler:**
- Log dosyası analizi
- Başarısız login tespiti
- Şüpheli aktivite tespiti
- IP adresi çıkarma
- Pattern matching

---

### 20. network_monitor.py
**Açıklama:** Ağ bağlantılarını izleyen, şüpheli bağlantıları tespit eden ve ağ istatistiklerini raporlayan araç.

**Kullanım:**
```bash
python system_security/network_monitor.py connections
python system_security/network_monitor.py listening
python system_security/network_monitor.py suspicious
python system_security/network_monitor.py stats
python system_security/network_monitor.py monitor [süre]
```

**Örnekler:**
```bash
python system_security/network_monitor.py connections
python system_security/network_monitor.py listening
python system_security/network_monitor.py suspicious
python system_security/network_monitor.py stats
python system_security/network_monitor.py monitor 120
```

**Özellikler:**
- Aktif bağlantı listesi
- Dinlenen port tespiti
- Şüpheli port kontrolü
- Ağ istatistikleri
- Gerçek zamanlı izleme

---

## Forensics & Analysis

### 21. file_forensics.py
**Açıklama:** Dosya metadata analizi, içerik analizi ve adli bilişim araştırması yapan araç.

**Kullanım:**
```bash
python forensics_analysis/file_forensics.py analyze <dosya>
python forensics_analysis/file_forensics.py search <dizin> <uzantı>
python forensics_analysis/file_forensics.py recent <dizin> [gün]
```

**Örnekler:**
```bash
python forensics_analysis/file_forensics.py analyze suspicious.exe
python forensics_analysis/file_forensics.py search /home/user .pdf
python forensics_analysis/file_forensics.py recent /var/www 7
```

**Özellikler:**
- Dosya metadata analizi
- Hash hesaplama (MD5, SHA1, SHA256)
- Dosya türü tespiti
- Zaman damgası analizi
- Son değişiklik takibi

---

### 22. string_extractor.py
**Açıklama:** Binary dosyalardan okunabilir string'leri, URL'leri, IP adreslerini ve diğer bilgileri çıkaran araç.

**Kullanım:**
```bash
python forensics_analysis/string_extractor.py strings <dosya> [min_uzunluk]
python forensics_analysis/string_extractor.py urls <dosya>
python forensics_analysis/string_extractor.py emails <dosya>
python forensics_analysis/string_extractor.py ips <dosya>
python forensics_analysis/string_extractor.py registry <dosya>
python forensics_analysis/string_extractor.py paths <dosya>
python forensics_analysis/string_extractor.py analyze <dosya>
```

**Örnekler:**
```bash
python forensics_analysis/string_extractor.py strings malware.exe 6
python forensics_analysis/string_extractor.py urls suspicious.dll
python forensics_analysis/string_extractor.py emails document.pdf
python forensics_analysis/string_extractor.py analyze malware.exe
```

**Özellikler:**
- ASCII ve Unicode string çıkarma
- URL tespiti
- E-posta adresi tespiti
- IP adresi tespiti
- Windows Registry anahtarı tespiti
- Dosya yolu tespiti

---

### 23. memory_analyzer.py
**Açıklama:** Bellek dump'larını ve binary dosyaları analiz eden, hex dump oluşturan araç.

**Kullanım:**
```bash
python forensics_analysis/memory_analyzer.py hexdump <dosya> [offset] [uzunluk]
python forensics_analysis/memory_analyzer.py compare <dosya1> <dosya2>
python forensics_analysis/memory_analyzer.py pe <dosya>
python forensics_analysis/memory_analyzer.py search <dosya> <hex_pattern>
```

**Örnekler:**
```bash
python forensics_analysis/memory_analyzer.py hexdump malware.exe 0 256
python forensics_analysis/memory_analyzer.py compare file1.bin file2.bin
python forensics_analysis/memory_analyzer.py pe program.exe
python forensics_analysis/memory_analyzer.py search malware.exe "FF D0 90 90"
```

**Özellikler:**
- Hex dump görüntüleme
- Dosya karşılaştırma
- PE header analizi
- Byte pattern arama
- Binary diff

---

### 24. timeline_analyzer.py
**Açıklama:** Birden fazla log dosyasından olay zaman çizelgesi oluşturan ve olayları korelasyon yapan araç.

**Kullanım:**
```bash
python forensics_analysis/timeline_analyzer.py create <log1> <log2> ...
python forensics_analysis/timeline_analyzer.py frequency <log1> <log2> ...
python forensics_analysis/timeline_analyzer.py correlate <log1> <log2> ... --keyword <anahtar>
python forensics_analysis/timeline_analyzer.py export <log1> <log2> ... --output <dosya>
```

**Örnekler:**
```bash
python forensics_analysis/timeline_analyzer.py create /var/log/auth.log /var/log/syslog
python forensics_analysis/timeline_analyzer.py frequency access.log error.log
python forensics_analysis/timeline_analyzer.py correlate auth.log --keyword "failed"
python forensics_analysis/timeline_analyzer.py export auth.log syslog --output timeline.csv
```

**Özellikler:**
- Çoklu log dosyası desteği
- Zaman damgası parsing
- Olay korelasyonu
- Frekans analizi
- CSV export

---

### 25. malware_detector.py
**Açıklama:** Dosyaları malware açısından analiz eden, şüpheli içerikleri tespit eden araç.

**Kullanım:**
```bash
python forensics_analysis/malware_detector.py analyze <dosya>
python forensics_analysis/malware_detector.py batch <dizin>
```

**Örnekler:**
```bash
python forensics_analysis/malware_detector.py analyze suspicious.exe
python forensics_analysis/malware_detector.py batch /tmp/downloads
```

**Özellikler:**
- Dosya türü tespiti
- Hash hesaplama ve VirusTotal linki
- Şüpheli string tespiti
- API çağrısı analizi
- IP ve URL çıkarma
- Entropy analizi
- Toplu dosya tarama

---

## Kurulum

### Gereksinimler

Python 3.6 veya üzeri gereklidir.

### Bağımlılıkları Yükleme

```bash
pip install psutil requests beautifulsoup4 pycryptodome
```

### Bağımlılık Listesi

- **psutil**: Sistem ve süreç izleme
- **requests**: HTTP istekleri
- **beautifulsoup4**: HTML parsing
- **pycryptodome**: Kriptografik işlemler

---

## Uyarılar

**ÖNEMLİ NOTLAR:**

1. Bu araçlar yalnızca **eğitim ve yasal penetrasyon testi** amaçlı kullanılmalıdır.

2. İzinsiz sistemlere karşı kullanımı **yasadışıdır** ve ciddi yasal sonuçlar doğurabilir.

3. Bazı araçlar **yönetici/root yetkisi** gerektirir (packet_sniffer, syn_scanner vb.).

4. Ağ tarama araçları **güvenlik duvarları ve IDS/IPS sistemleri** tarafından engellenebilir veya alarm üretebilir.

5. Kullanmadan önce **yerel yasaları ve düzenlemeleri** kontrol edin.

6. Araçları kullanırken **hedef sistemin sahibinden izin** alınmalıdır.

7. Test ortamlarında kullanmadan önce **yedekleme** yapılması önerilir.

8. Bazı araçlar **yüksek ağ trafiği** oluşturabilir ve sistemleri etkileyebilir.

9. Üretim ortamlarında kullanmadan önce **test ortamında deneme** yapılmalıdır.

10. Araçların kullanımından doğacak **tüm sorumluluk kullanıcıya aittir**.

---

## Lisans

Bu araçlar eğitim amaçlı geliştirilmiştir. Kullanımdan doğacak sorumluluk kullanıcıya aittir.

---

## Katkıda Bulunma

Hata bildirimleri ve geliştirme önerileri için issue açabilirsiniz.

---

## İletişim

Sorularınız için GitHub üzerinden iletişime geçebilirsiniz.

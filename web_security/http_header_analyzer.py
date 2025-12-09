import requests
import sys
from bs4 import BeautifulSoup
import re

def check_security_headers(url):
    print(f"[*] Güvenlik başlıkları kontrol ediliyor: {url}\n")
    
    security_headers = {
        'Strict-Transport-Security': 'HSTS - HTTPS zorunluluğu',
        'X-Frame-Options': 'Clickjacking koruması',
        'X-Content-Type-Options': 'MIME type sniffing koruması',
        'X-XSS-Protection': 'XSS filtresi',
        'Content-Security-Policy': 'İçerik güvenlik politikası',
        'Referrer-Policy': 'Referrer bilgisi kontrolü',
        'Permissions-Policy': 'Tarayıcı özellik izinleri',
        'X-Permitted-Cross-Domain-Policies': 'Cross-domain politikası'
    }
    
    try:
        response = requests.get(url, timeout=5)
        
        print("[*] Güvenlik Başlıkları:")
        print("-" * 60)
        
        missing_headers = []
        
        for header, description in security_headers.items():
            if header in response.headers:
                print(f"[+] {header}: {response.headers[header]}")
                print(f"    Açıklama: {description}\n")
            else:
                print(f"[-] {header}: BULUNAMADI")
                print(f"    Açıklama: {description}\n")
                missing_headers.append(header)
        
        print("-" * 60)
        
        if missing_headers:
            print(f"\n[!] UYARI: {len(missing_headers)} güvenlik başlığı eksik!")
            print("[*] Eksik başlıklar:")
            for h in missing_headers:
                print(f"    - {h}")
        else:
            print("\n[+] Tüm önemli güvenlik başlıkları mevcut.")
        
        print("\n[*] Diğer Başlıklar:")
        print("-" * 60)
        for header, value in response.headers.items():
            if header not in security_headers:
                print(f"{header}: {value}")
        
    except requests.exceptions.RequestException as e:
        print(f"[!] Bağlantı hatası: {e}")

def check_ssl_tls(url):
    print(f"\n\n[*] SSL/TLS kontrolü yapılıyor: {url}\n")
    
    if not url.startswith('https://'):
        print("[!] UYARI: Site HTTPS kullanmıyor!")
        return
    
    try:
        response = requests.get(url, timeout=5)
        
        if response.url.startswith('https://'):
            print("[+] Site HTTPS kullanıyor.")
        else:
            print("[!] UYARI: HTTP'ye yönlendirme yapılıyor!")
        
    except requests.exceptions.SSLError as e:
        print(f"[!] SSL/TLS HATASI: {e}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Bağlantı hatası: {e}")

def check_cookies(url):
    print(f"\n\n[*] Cookie güvenliği kontrol ediliyor: {url}\n")
    
    try:
        response = requests.get(url, timeout=5)
        
        if response.cookies:
            print(f"[*] {len(response.cookies)} cookie bulundu:\n")
            
            for cookie in response.cookies:
                print(f"Cookie: {cookie.name}")
                print(f"  Değer: {cookie.value[:50]}..." if len(cookie.value) > 50 else f"  Değer: {cookie.value}")
                print(f"  Secure: {'✓' if cookie.secure else '✗ (UYARI: Güvenli değil!)'}")
                print(f"  HttpOnly: {'✓' if cookie.has_nonstandard_attr('HttpOnly') else '✗ (UYARI: XSS riski!)'}")
                print(f"  Domain: {cookie.domain}")
                print(f"  Path: {cookie.path}")
                print()
        else:
            print("[-] Cookie bulunamadı.")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Bağlantı hatası: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python http_header_analyzer.py <url>")
        print("Örnek: python http_header_analyzer.py https://example.com")
        sys.exit()
    
    url = sys.argv[1]
    
    check_security_headers(url)
    check_ssl_tls(url)
    check_cookies(url)

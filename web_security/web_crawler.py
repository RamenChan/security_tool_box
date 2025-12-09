import requests
import sys
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re

def crawl_website(url, max_depth=2):
    visited = set()
    to_visit = [(url, 0)]
    found_urls = []
    
    print(f"[*] Web sitesi taranıyor: {url}")
    print(f"[*] Maksimum derinlik: {max_depth}\n")
    
    while to_visit:
        current_url, depth = to_visit.pop(0)
        
        if current_url in visited or depth > max_depth:
            continue
        
        visited.add(current_url)
        
        try:
            response = requests.get(current_url, timeout=5, allow_redirects=True)
            
            if response.status_code == 200:
                print(f"[+] Bulundu: {current_url} (Derinlik: {depth})")
                found_urls.append(current_url)
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    absolute_url = urljoin(current_url, href)
                    
                    parsed_base = urlparse(url)
                    parsed_url = urlparse(absolute_url)
                    
                    if parsed_base.netloc == parsed_url.netloc:
                        if absolute_url not in visited:
                            to_visit.append((absolute_url, depth + 1))
            else:
                print(f"[-] Erişilemedi: {current_url} (Status: {response.status_code})")
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Hata: {current_url} - {e}")
    
    return found_urls

def extract_emails(url):
    print(f"\n[*] E-posta adresleri aranıyor: {url}\n")
    
    emails = set()
    
    try:
        response = requests.get(url, timeout=5)
        
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        found_emails = re.findall(email_pattern, response.text)
        
        emails.update(found_emails)
        
        if emails:
            print(f"[+] {len(emails)} e-posta adresi bulundu:")
            for email in emails:
                print(f"    - {email}")
        else:
            print("[-] E-posta adresi bulunamadı.")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Hata: {e}")
    
    return list(emails)

def extract_subdomains(url):
    print(f"\n[*] Alt domain'ler aranıyor: {url}\n")
    
    subdomains = set()
    
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        parsed_base = urlparse(url)
        base_domain = '.'.join(parsed_base.netloc.split('.')[-2:])
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            absolute_url = urljoin(url, href)
            parsed_url = urlparse(absolute_url)
            
            if base_domain in parsed_url.netloc and parsed_url.netloc != parsed_base.netloc:
                subdomains.add(parsed_url.netloc)
        
        if subdomains:
            print(f"[+] {len(subdomains)} alt domain bulundu:")
            for subdomain in subdomains:
                print(f"    - {subdomain}")
        else:
            print("[-] Alt domain bulunamadı.")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Hata: {e}")
    
    return list(subdomains)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python web_crawler.py <url> [derinlik]")
        print("Örnek: python web_crawler.py https://example.com 2")
        sys.exit()
    
    url = sys.argv[1]
    depth = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    
    found_urls = crawl_website(url, depth)
    
    print(f"\n[*] Toplam {len(found_urls)} URL bulundu.")
    
    extract_emails(url)
    extract_subdomains(url)

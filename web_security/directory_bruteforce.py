import requests
import sys
from urllib.parse import urljoin

def directory_bruteforce(url, wordlist_file):
    print(f"[*] Dizin taraması başlatılıyor: {url}")
    print(f"[*] Wordlist: {wordlist_file}\n")
    
    found_dirs = []
    
    try:
        with open(wordlist_file, 'r') as f:
            wordlist = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"[!] Wordlist dosyası bulunamadı: {wordlist_file}")
        sys.exit()
    
    print(f"[*] {len(wordlist)} dizin test edilecek...\n")
    
    for directory in wordlist:
        test_url = urljoin(url, directory)
        
        try:
            response = requests.get(test_url, timeout=3, allow_redirects=False)
            
            if response.status_code == 200:
                print(f"[+] BULUNDU: {test_url} (Status: {response.status_code}, Size: {len(response.content)} bytes)")
                found_dirs.append((test_url, response.status_code))
            elif response.status_code == 301 or response.status_code == 302:
                print(f"[~] YÖNLENDİRME: {test_url} (Status: {response.status_code})")
                found_dirs.append((test_url, response.status_code))
            elif response.status_code == 403:
                print(f"[!] YASAK: {test_url} (Status: 403 - Erişim engellendi)")
                found_dirs.append((test_url, response.status_code))
                
        except requests.exceptions.RequestException:
            pass
    
    print("\n" + "-" * 60)
    print(f"[*] Tarama tamamlandı. {len(found_dirs)} dizin/dosya bulundu.")
    
    if found_dirs:
        print("\n[*] Bulunan dizinler:")
        for url, status in found_dirs:
            print(f"    [{status}] {url}")

def create_default_wordlist():
    default_dirs = [
        "admin/",
        "administrator/",
        "login/",
        "wp-admin/",
        "wp-login.php",
        "dashboard/",
        "cpanel/",
        "phpmyadmin/",
        "backup/",
        "backups/",
        "old/",
        "test/",
        "temp/",
        "tmp/",
        "uploads/",
        "images/",
        "files/",
        "download/",
        "downloads/",
        "config/",
        "conf/",
        "api/",
        "private/",
        "secret/",
        "hidden/",
        ".git/",
        ".env",
        "robots.txt",
        "sitemap.xml",
        ".htaccess",
        "web.config",
        "config.php",
        "database.sql",
        "db.sql",
        "backup.zip",
        "backup.tar.gz"
    ]
    
    with open('default_wordlist.txt', 'w') as f:
        for d in default_dirs:
            f.write(d + '\n')
    
    print("[+] Varsayılan wordlist oluşturuldu: default_wordlist.txt")
    return 'default_wordlist.txt'

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python directory_bruteforce.py <url> [wordlist]")
        print("Örnek: python directory_bruteforce.py https://example.com wordlist.txt")
        print("\nWordlist belirtilmezse varsayılan wordlist kullanılır.")
        sys.exit()
    
    url = sys.argv[1]
    
    if not url.endswith('/'):
        url += '/'
    
    if len(sys.argv) > 2:
        wordlist = sys.argv[2]
    else:
        wordlist = create_default_wordlist()
    
    directory_bruteforce(url, wordlist)

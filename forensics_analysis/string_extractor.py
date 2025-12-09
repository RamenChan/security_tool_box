imdiimport sys
import re
from collections import Counter
from datetime import datetime

def extract_strings(filepath, min_length=4):
    print(f"[*] String'ler çıkarılıyor: {filepath}\n")
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        ascii_strings = re.findall(b'[\x20-\x7E]{' + str(min_length).encode() + b',}', data)
        unicode_strings = re.findall(b'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + b',}', data)
        
        all_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings]
        all_strings += [s.decode('utf-16le', errors='ignore') for s in unicode_strings]
        
        print(f"[+] {len(all_strings)} string bulundu.\n")
        
        if all_strings:
            print("İlk 50 String:")
            print("-" * 60)
            for i, string in enumerate(all_strings[:50], 1):
                print(f"{i:3d}. {string[:80]}")
        
        return all_strings
        
    except Exception as e:
        print(f"[!] Hata: {e}")
        return []

def find_urls(filepath):
    print(f"\n[*] URL'ler aranıyor: {filepath}\n")
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read().decode('utf-8', errors='ignore')
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, data)
        
        if urls:
            print(f"[+] {len(urls)} URL bulundu:\n")
            for url in set(urls):
                print(f"  - {url}")
        else:
            print("[-] URL bulunamadı.")
        
        return urls
        
    except Exception as e:
        print(f"[!] Hata: {e}")
        return []

def find_emails(filepath):
    print(f"\n[*] E-posta adresleri aranıyor: {filepath}\n")
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read().decode('utf-8', errors='ignore')
        
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, data)
        
        if emails:
            print(f"[+] {len(emails)} e-posta adresi bulundu:\n")
            for email in set(emails):
                print(f"  - {email}")
        else:
            print("[-] E-posta adresi bulunamadı.")
        
        return emails
        
    except Exception as e:
        print(f"[!] Hata: {e}")
        return []

def find_ip_addresses(filepath):
    print(f"\n[*] IP adresleri aranıyor: {filepath}\n")
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read().decode('utf-8', errors='ignore')
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, data)
        
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
        
        if valid_ips:
            print(f"[+] {len(valid_ips)} IP adresi bulundu:\n")
            
            ip_counts = Counter(valid_ips)
            for ip, count in ip_counts.most_common():
                print(f"  - {ip} ({count} kez)")
        else:
            print("[-] IP adresi bulunamadı.")
        
        return valid_ips
        
    except Exception as e:
        print(f"[!] Hata: {e}")
        return []

def find_registry_keys(filepath):
    print(f"\n[*] Windows Registry anahtarları aranıyor: {filepath}\n")
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read().decode('utf-8', errors='ignore')
        
        registry_pattern = r'HKEY_[A-Z_]+\\[^\s<>"{}|\\^`\[\]]+'
        keys = re.findall(registry_pattern, data)
        
        if keys:
            print(f"[+] {len(keys)} registry anahtarı bulundu:\n")
            for key in set(keys):
                print(f"  - {key}")
        else:
            print("[-] Registry anahtarı bulunamadı.")
        
        return keys
        
    except Exception as e:
        print(f"[!] Hata: {e}")
        return []

def find_file_paths(filepath):
    print(f"\n[*] Dosya yolları aranıyor: {filepath}\n")
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read().decode('utf-8', errors='ignore')
        
        windows_path_pattern = r'[A-Za-z]:\\(?:[^\s<>"{}|\\^`\[\]]+\\)*[^\s<>"{}|\\^`\[\]]+'
        linux_path_pattern = r'/(?:[^\s<>"{}|\\^`\[\]]+/)*[^\s<>"{}|\\^`\[\]]+'
        
        windows_paths = re.findall(windows_path_pattern, data)
        linux_paths = re.findall(linux_path_pattern, data)
        
        all_paths = windows_paths + linux_paths
        
        if all_paths:
            print(f"[+] {len(all_paths)} dosya yolu bulundu:\n")
            for path in set(all_paths[:30]):
                print(f"  - {path}")
        else:
            print("[-] Dosya yolu bulunamadı.")
        
        return all_paths
        
    except Exception as e:
        print(f"[!] Hata: {e}")
        return []

def comprehensive_analysis(filepath):
    print("="*60)
    print("KAPSAMLI STRING ANALİZİ")
    print("="*60 + "\n")
    
    extract_strings(filepath)
    find_urls(filepath)
    find_emails(filepath)
    find_ip_addresses(filepath)
    find_registry_keys(filepath)
    find_file_paths(filepath)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  String çıkarma  : python string_extractor.py strings <dosya> [min_uzunluk]")
        print("  URL arama       : python string_extractor.py urls <dosya>")
        print("  E-posta arama   : python string_extractor.py emails <dosya>")
        print("  IP arama        : python string_extractor.py ips <dosya>")
        print("  Registry arama  : python string_extractor.py registry <dosya>")
        print("  Dosya yolu arama: python string_extractor.py paths <dosya>")
        print("  Kapsamlı analiz : python string_extractor.py analyze <dosya>")
        print("\nÖrnekler:")
        print("  python string_extractor.py strings malware.exe 6")
        print("  python string_extractor.py urls suspicious.dll")
        print("  python string_extractor.py analyze malware.exe")
        sys.exit()
    
    command = sys.argv[1]
    
    if command == 'strings' and len(sys.argv) >= 3:
        filepath = sys.argv[2]
        min_length = int(sys.argv[3]) if len(sys.argv) > 3 else 4
        extract_strings(filepath, min_length)
    elif command == 'urls' and len(sys.argv) >= 3:
        filepath = sys.argv[2]
        find_urls(filepath)
    elif command == 'emails' and len(sys.argv) >= 3:
        filepath = sys.argv[2]
        find_emails(filepath)
    elif command == 'ips' and len(sys.argv) >= 3:
        filepath = sys.argv[2]
        find_ip_addresses(filepath)
    elif command == 'registry' and len(sys.argv) >= 3:
        filepath = sys.argv[2]
        find_registry_keys(filepath)
    elif command == 'paths' and len(sys.argv) >= 3:
        filepath = sys.argv[2]
        find_file_paths(filepath)
    elif command == 'analyze' and len(sys.argv) >= 3:
        filepath = sys.argv[2]
        comprehensive_analysis(filepath)
    else:
        print("[!] Geçersiz kullanım!")

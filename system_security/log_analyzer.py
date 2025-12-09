import sys
import re
from datetime import datetime

def analyze_log_file(log_file, pattern=None):
    print(f"[*] Log dosyası analiz ediliyor: {log_file}\n")
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        print(f"[*] Toplam {len(lines)} satır bulundu.\n")
        
        if pattern:
            print(f"[*] Desen aranıyor: {pattern}\n")
            matches = []
            
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    matches.append((i, line.strip()))
            
            if matches:
                print(f"[+] {len(matches)} eşleşme bulundu:\n")
                for line_num, line in matches[:50]:
                    print(f"Satır {line_num}: {line}")
            else:
                print("[-] Eşleşme bulunamadı.")
        
        return lines
        
    except FileNotFoundError:
        print(f"[!] Log dosyası bulunamadı: {log_file}")
        return None
    except Exception as e:
        print(f"[!] Hata: {e}")
        return None

def find_failed_logins(log_file):
    print(f"[*] Başarısız giriş denemeleri aranıyor: {log_file}\n")
    
    patterns = [
        r'failed password',
        r'authentication failure',
        r'invalid user',
        r'failed login',
        r'login incorrect',
        r'authentication failed'
    ]
    
    failed_attempts = {}
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                        if ip_match:
                            ip = ip_match.group()
                            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
                        
                        print(f"[!] {line.strip()}")
        
        if failed_attempts:
            print("\n" + "="*60)
            print("BAŞARISIZ GİRİŞ İSTATİSTİKLERİ")
            print("="*60)
            
            sorted_attempts = sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)
            
            for ip, count in sorted_attempts[:10]:
                print(f"{ip:<20} : {count} deneme")
        else:
            print("\n[-] Başarısız giriş denemesi bulunamadı.")
            
    except FileNotFoundError:
        print(f"[!] Log dosyası bulunamadı: {log_file}")
    except Exception as e:
        print(f"[!] Hata: {e}")

def find_suspicious_activities(log_file):
    print(f"[*] Şüpheli aktiviteler aranıyor: {log_file}\n")
    
    suspicious_patterns = {
        'SQL Injection': [r'union.*select', r'or.*1=1', r'drop.*table'],
        'XSS': [r'<script>', r'javascript:', r'onerror='],
        'Path Traversal': [r'\.\./', r'\.\.\\'],
        'Command Injection': [r';.*cat', r'\|.*ls', r'&&.*rm'],
        'Brute Force': [r'failed.*password.*\d{3,}', r'authentication.*failure.*\d{3,}']
    }
    
    findings = {}
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        for attack_type, patterns in suspicious_patterns.items():
            findings[attack_type] = []
            
            for line in lines:
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings[attack_type].append(line.strip())
                        break
        
        print("="*60)
        print("ŞÜPHELİ AKTİVİTE RAPORU")
        print("="*60 + "\n")
        
        for attack_type, matches in findings.items():
            if matches:
                print(f"[!] {attack_type}: {len(matches)} olay")
                for match in matches[:5]:
                    print(f"    {match[:100]}...")
                print()
        
    except FileNotFoundError:
        print(f"[!] Log dosyası bulunamadı: {log_file}")
    except Exception as e:
        print(f"[!] Hata: {e}")

def extract_ips(log_file):
    print(f"[*] IP adresleri çıkarılıyor: {log_file}\n")
    
    ip_counts = {}
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                for ip in ips:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        if ip_counts:
            print(f"[+] {len(ip_counts)} benzersiz IP adresi bulundu.\n")
            
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
            
            print("En Aktif IP Adresleri:")
            print("-" * 60)
            for ip, count in sorted_ips[:20]:
                print(f"{ip:<20} : {count} istek")
        else:
            print("[-] IP adresi bulunamadı.")
            
    except FileNotFoundError:
        print(f"[!] Log dosyası bulunamadı: {log_file}")
    except Exception as e:
        print(f"[!] Hata: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Genel analiz    : python log_analyzer.py analyze <log_dosya> [desen]")
        print("  Başarısız giriş : python log_analyzer.py failed <log_dosya>")
        print("  Şüpheli aktivite: python log_analyzer.py suspicious <log_dosya>")
        print("  IP çıkarma      : python log_analyzer.py ips <log_dosya>")
        print("\nÖrnekler:")
        print("  python log_analyzer.py analyze /var/log/auth.log 'error'")
        print("  python log_analyzer.py failed /var/log/auth.log")
        print("  python log_analyzer.py suspicious /var/log/apache2/access.log")
        sys.exit()
    
    command = sys.argv[1]
    
    if command == 'analyze' and len(sys.argv) >= 3:
        log_file = sys.argv[2]
        pattern = sys.argv[3] if len(sys.argv) > 3 else None
        analyze_log_file(log_file, pattern)
    elif command == 'failed' and len(sys.argv) >= 3:
        log_file = sys.argv[2]
        find_failed_logins(log_file)
    elif command == 'suspicious' and len(sys.argv) >= 3:
        log_file = sys.argv[2]
        find_suspicious_activities(log_file)
    elif command == 'ips' and len(sys.argv) >= 3:
        log_file = sys.argv[2]
        extract_ips(log_file)
    else:
        print("[!] Geçersiz kullanım!")

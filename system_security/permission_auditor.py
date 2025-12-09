import os
import sys
import re
from datetime import datetime

def check_permissions(filepath):
    print(f"[*] Dosya izinleri kontrol ediliyor: {filepath}\n")
    
    try:
        stat_info = os.stat(filepath)
        mode = stat_info.st_mode
        
        permissions = {
            'owner_read': bool(mode & 0o400),
            'owner_write': bool(mode & 0o200),
            'owner_execute': bool(mode & 0o100),
            'group_read': bool(mode & 0o040),
            'group_write': bool(mode & 0o020),
            'group_execute': bool(mode & 0o010),
            'other_read': bool(mode & 0o004),
            'other_write': bool(mode & 0o002),
            'other_execute': bool(mode & 0o001)
        }
        
        print(f"Dosya: {filepath}")
        print(f"Oktal: {oct(mode)[-3:]}")
        print(f"\nSahip İzinleri:")
        print(f"  Okuma   : {'✓' if permissions['owner_read'] else '✗'}")
        print(f"  Yazma   : {'✓' if permissions['owner_write'] else '✗'}")
        print(f"  Çalıştır: {'✓' if permissions['owner_execute'] else '✗'}")
        print(f"\nGrup İzinleri:")
        print(f"  Okuma   : {'✓' if permissions['group_read'] else '✗'}")
        print(f"  Yazma   : {'✓' if permissions['group_write'] else '✗'}")
        print(f"  Çalıştır: {'✓' if permissions['group_execute'] else '✗'}")
        print(f"\nDiğer İzinleri:")
        print(f"  Okuma   : {'✓' if permissions['other_read'] else '✗'}")
        print(f"  Yazma   : {'✓' if permissions['other_write'] else '✗'}")
        print(f"  Çalıştır: {'✓' if permissions['other_execute'] else '✗'}")
        
        if permissions['other_write']:
            print(f"\n[!] UYARI: Dosya herkes tarafından yazılabilir!")
        
        if permissions['other_execute'] and not os.path.isdir(filepath):
            print(f"[!] UYARI: Dosya herkes tarafından çalıştırılabilir!")
        
    except FileNotFoundError:
        print(f"[!] Dosya bulunamadı: {filepath}")
    except Exception as e:
        print(f"[!] Hata: {e}")

def scan_directory_permissions(directory):
    print(f"[*] Dizin izinleri taranıyor: {directory}\n")
    
    vulnerable_files = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            
            try:
                stat_info = os.stat(filepath)
                mode = stat_info.st_mode
                
                other_write = bool(mode & 0o002)
                other_execute = bool(mode & 0o001)
                
                if other_write or (other_execute and not os.path.isdir(filepath)):
                    vulnerable_files.append(filepath)
                    print(f"[!] ZAFİYET: {filepath}")
                    print(f"    İzinler: {oct(mode)[-3:]}")
                    if other_write:
                        print(f"    - Herkes yazabilir")
                    if other_execute:
                        print(f"    - Herkes çalıştırabilir")
                    print()
                    
            except Exception as e:
                pass
    
    print("-" * 60)
    print(f"[*] Toplam {len(vulnerable_files)} güvenlik açığı bulundu.")

def check_suid_sgid():
    print("[*] SUID/SGID dosyaları aranıyor...\n")
    
    suid_files = []
    
    search_paths = ['/usr/bin', '/usr/sbin', '/bin', '/sbin']
    
    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue
            
        for root, dirs, files in os.walk(search_path):
            for file in files:
                filepath = os.path.join(root, file)
                
                try:
                    stat_info = os.stat(filepath)
                    mode = stat_info.st_mode
                    
                    has_suid = bool(mode & 0o4000)
                    has_sgid = bool(mode & 0o2000)
                    
                    if has_suid or has_sgid:
                        suid_files.append(filepath)
                        print(f"[!] {'SUID' if has_suid else 'SGID'}: {filepath}")
                        print(f"    İzinler: {oct(mode)[-4:]}\n")
                        
                except Exception:
                    pass
    
    print(f"[*] Toplam {len(suid_files)} SUID/SGID dosyası bulundu.")

def check_world_writable():
    print("[*] Herkes tarafından yazılabilir dosyalar aranıyor...\n")
    
    writable_files = []
    
    search_paths = ['/tmp', '/var/tmp', '/home']
    
    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue
            
        for root, dirs, files in os.walk(search_path):
            for file in files:
                filepath = os.path.join(root, file)
                
                try:
                    stat_info = os.stat(filepath)
                    mode = stat_info.st_mode
                    
                    if mode & 0o002:
                        writable_files.append(filepath)
                        print(f"[!] YAZILABILIR: {filepath}")
                        print(f"    İzinler: {oct(mode)[-3:]}\n")
                        
                except Exception:
                    pass
    
    print(f"[*] Toplam {len(writable_files)} yazılabilir dosya bulundu.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Dosya kontrolü  : python permission_auditor.py check <dosya>")
        print("  Dizin tarama    : python permission_auditor.py scan <dizin>")
        print("  SUID/SGID       : python permission_auditor.py suid")
        print("  Yazılabilir     : python permission_auditor.py writable")
        print("\nÖrnekler:")
        print("  python permission_auditor.py check /etc/passwd")
        print("  python permission_auditor.py scan /var/www")
        print("  python permission_auditor.py suid")
        sys.exit()
    
    command = sys.argv[1]
    
    if command == 'check' and len(sys.argv) >= 3:
        filepath = sys.argv[2]
        check_permissions(filepath)
    elif command == 'scan' and len(sys.argv) >= 3:
        directory = sys.argv[2]
        scan_directory_permissions(directory)
    elif command == 'suid':
        check_suid_sgid()
    elif command == 'writable':
        check_world_writable()
    else:
        print("[!] Geçersiz kullanım!")

Şimdiimport os
import sys
import hashlib
from datetime import datetime

def calculate_file_hash(filepath, algorithm='sha256'):
    hash_func = getattr(hashlib, algorithm)()
    
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        return None

def scan_directory(directory, baseline_file=None):
    print(f"[*] Dizin taranıyor: {directory}\n")
    
    file_info = {}
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            
            try:
                stat_info = os.stat(filepath)
                file_hash = calculate_file_hash(filepath)
                
                file_info[filepath] = {
                    'hash': file_hash,
                    'size': stat_info.st_size,
                    'modified': datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'created': datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                }
                
                print(f"[+] {filepath}")
                print(f"    Hash: {file_hash}")
                print(f"    Boyut: {stat_info.st_size} bytes")
                print(f"    Değiştirilme: {file_info[filepath]['modified']}\n")
                
            except Exception as e:
                print(f"[!] Hata: {filepath} - {e}\n")
    
    if baseline_file:
        save_baseline(file_info, baseline_file)
    
    return file_info

def save_baseline(file_info, baseline_file):
    print(f"[*] Baseline kaydediliyor: {baseline_file}\n")
    
    with open(baseline_file, 'w') as f:
        f.write(f"# File Integrity Baseline - {datetime.now()}\n")
        f.write(f"# Total Files: {len(file_info)}\n\n")
        
        for filepath, info in file_info.items():
            f.write(f"{filepath}|{info['hash']}|{info['size']}|{info['modified']}\n")
    
    print(f"[+] Baseline kaydedildi: {baseline_file}")

def load_baseline(baseline_file):
    baseline = {}
    
    try:
        with open(baseline_file, 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                
                parts = line.strip().split('|')
                if len(parts) >= 4:
                    filepath = parts[0]
                    baseline[filepath] = {
                        'hash': parts[1],
                        'size': int(parts[2]),
                        'modified': parts[3]
                    }
    except FileNotFoundError:
        print(f"[!] Baseline dosyası bulunamadı: {baseline_file}")
        return None
    
    return baseline

def compare_with_baseline(directory, baseline_file):
    print(f"[*] Baseline ile karşılaştırma yapılıyor...\n")
    
    baseline = load_baseline(baseline_file)
    if baseline is None:
        return
    
    current_files = scan_directory(directory)
    
    print("\n" + "="*60)
    print("BÜTÜNLÜK KONTROLÜ SONUÇLARI")
    print("="*60 + "\n")
    
    modified_files = []
    new_files = []
    deleted_files = []
    
    for filepath, info in current_files.items():
        if filepath in baseline:
            if info['hash'] != baseline[filepath]['hash']:
                modified_files.append(filepath)
                print(f"[!] DEĞİŞTİRİLDİ: {filepath}")
                print(f"    Eski Hash: {baseline[filepath]['hash']}")
                print(f"    Yeni Hash: {info['hash']}\n")
        else:
            new_files.append(filepath)
            print(f"[+] YENİ DOSYA: {filepath}\n")
    
    for filepath in baseline:
        if filepath not in current_files:
            deleted_files.append(filepath)
            print(f"[-] SİLİNDİ: {filepath}\n")
    
    print("="*60)
    print(f"Toplam Değişiklik: {len(modified_files)}")
    print(f"Yeni Dosyalar    : {len(new_files)}")
    print(f"Silinen Dosyalar : {len(deleted_files)}")
    print("="*60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Baseline oluştur: python file_integrity_checker.py create <dizin> <baseline_dosya>")
        print("  Kontrol et      : python file_integrity_checker.py check <dizin> <baseline_dosya>")
        print("\nÖrnekler:")
        print("  python file_integrity_checker.py create /var/www baseline.txt")
        print("  python file_integrity_checker.py check /var/www baseline.txt")
        sys.exit()
    
    command = sys.argv[1]
    
    if command == 'create' and len(sys.argv) >= 4:
        directory = sys.argv[2]
        baseline_file = sys.argv[3]
        scan_directory(directory, baseline_file)
        
    elif command == 'check' and len(sys.argv) >= 4:
        directory = sys.argv[2]
        baseline_file = sys.argv[3]
        compare_with_baseline(directory, baseline_file)
        
    else:
        print("[!] Geçersiz kullanım!")

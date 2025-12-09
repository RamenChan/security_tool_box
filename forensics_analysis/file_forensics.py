import os
import sys
import hashlib
from datetime import datetime

def get_file_metadata(filepath):
    try:
        stat_info = os.stat(filepath)
        
        metadata = {
            'path': filepath,
            'size': stat_info.st_size,
            'created': datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
            'modified': datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'accessed': datetime.fromtimestamp(stat_info.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
            'permissions': oct(stat_info.st_mode)[-3:]
        }
        
        return metadata
    except Exception as e:
        return None

def calculate_hashes(filepath):
    hashes = {}
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
        
        return hashes
    except Exception as e:
        return None

def analyze_file(filepath):
    print(f"[*] Dosya analiz ediliyor: {filepath}\n")
    
    if not os.path.exists(filepath):
        print(f"[!] Dosya bulunamadı: {filepath}")
        return
    
    metadata = get_file_metadata(filepath)
    
    if metadata:
        print("Dosya Bilgileri:")
        print("-" * 60)
        print(f"Yol          : {metadata['path']}")
        print(f"Boyut        : {metadata['size']:,} bytes ({metadata['size'] / 1024:.2f} KB)")
        print(f"Oluşturulma  : {metadata['created']}")
        print(f"Değiştirilme : {metadata['modified']}")
        print(f"Erişim       : {metadata['accessed']}")
        print(f"İzinler      : {metadata['permissions']}")
    
    print("\nHash Değerleri:")
    print("-" * 60)
    
    hashes = calculate_hashes(filepath)
    
    if hashes:
        print(f"MD5    : {hashes['md5']}")
        print(f"SHA1   : {hashes['sha1']}")
        print(f"SHA256 : {hashes['sha256']}")
    
    print("\nDosya İçeriği Analizi:")
    print("-" * 60)
    
    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)
        
        file_signatures = {
            b'\x4D\x5A': 'Windows Executable (PE)',
            b'\x7F\x45\x4C\x46': 'Linux Executable (ELF)',
            b'\x50\x4B\x03\x04': 'ZIP Archive',
            b'\x50\x4B\x05\x06': 'ZIP Archive (Empty)',
            b'\x52\x61\x72\x21': 'RAR Archive',
            b'\x1F\x8B': 'GZIP Archive',
            b'\x42\x5A\x68': 'BZIP2 Archive',
            b'\x89\x50\x4E\x47': 'PNG Image',
            b'\xFF\xD8\xFF': 'JPEG Image',
            b'\x47\x49\x46\x38': 'GIF Image',
            b'\x25\x50\x44\x46': 'PDF Document',
            b'\xD0\xCF\x11\xE0': 'Microsoft Office Document',
            b'\x50\x4B\x03\x04\x14\x00\x06\x00': 'Microsoft Office (DOCX/XLSX/PPTX)'
        }
        
        detected = False
        for signature, file_type in file_signatures.items():
            if header.startswith(signature):
                print(f"Dosya Türü: {file_type}")
                detected = True
                break
        
        if not detected:
            print("Dosya Türü: Bilinmeyen veya Metin Dosyası")
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read(1000)
                if content:
                    print(f"\nİlk 1000 Karakter:")
                    print("-" * 60)
                    print(content)
        except:
            print("\n[*] Dosya binary formatta veya okunamıyor.")
            
    except Exception as e:
        print(f"[!] Dosya analiz hatası: {e}")

def search_files_by_extension(directory, extension):
    print(f"[*] {extension} uzantılı dosyalar aranıyor: {directory}\n")
    
    found_files = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(extension):
                filepath = os.path.join(root, file)
                found_files.append(filepath)
                
                metadata = get_file_metadata(filepath)
                if metadata:
                    print(f"[+] {filepath}")
                    print(f"    Boyut: {metadata['size']:,} bytes")
                    print(f"    Değiştirilme: {metadata['modified']}\n")
    
    print(f"[*] Toplam {len(found_files)} dosya bulundu.")

def find_recently_modified(directory, days=7):
    print(f"[*] Son {days} gün içinde değiştirilen dosyalar aranıyor: {directory}\n")
    
    import time
    
    current_time = time.time()
    cutoff_time = current_time - (days * 24 * 60 * 60)
    
    recent_files = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            
            try:
                stat_info = os.stat(filepath)
                
                if stat_info.st_mtime > cutoff_time:
                    recent_files.append(filepath)
                    modified_time = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"[+] {filepath}")
                    print(f"    Değiştirilme: {modified_time}\n")
            except:
                pass
    
    print(f"[*] Toplam {len(recent_files)} dosya bulundu.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Dosya analizi   : python file_forensics.py analyze <dosya>")
        print("  Uzantı arama    : python file_forensics.py search <dizin> <uzantı>")
        print("  Son değişiklikler: python file_forensics.py recent <dizin> [gün]")
        print("\nÖrnekler:")
        print("  python file_forensics.py analyze suspicious.exe")
        print("  python file_forensics.py search /home/user .pdf")
        print("  python file_forensics.py recent /var/www 7")
        sys.exit()
    
    command = sys.argv[1]
    
    if command == 'analyze' and len(sys.argv) >= 3:
        filepath = sys.argv[2]
        analyze_file(filepath)
    elif command == 'search' and len(sys.argv) >= 4:
        directory = sys.argv[2]
        extension = sys.argv[3]
        search_files_by_extension(directory, extension)
    elif command == 'recent' and len(sys.argv) >= 3:
        directory = sys.argv[2]
        days = int(sys.argv[3]) if len(sys.argv) > 3 else 7
        find_recently_modified(directory, days)
    else:
        print("[!] Geçersiz kullanım!")

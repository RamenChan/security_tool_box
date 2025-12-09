import hashlib
import sys

def hash_text(text, algorithm='all'):
    print(f"[*] Metin hash'leniyor...\n")
    print(f"Orijinal Metin: {text}\n")
    print("-" * 60)
    
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s
    }
    
    if algorithm == 'all':
        for name, func in algorithms.items():
            hash_obj = func(text.encode())
            print(f"{name.upper():10} : {hash_obj.hexdigest()}")
    elif algorithm in algorithms:
        hash_obj = algorithms[algorithm](text.encode())
        print(f"{algorithm.upper():10} : {hash_obj.hexdigest()}")
    else:
        print(f"[!] Geçersiz algoritma: {algorithm}")
        print(f"[*] Desteklenen algoritmalar: {', '.join(algorithms.keys())}")

def hash_file(filename, algorithm='sha256'):
    print(f"[*] Dosya hash'leniyor: {filename}\n")
    
    try:
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        if algorithm not in algorithms:
            print(f"[!] Geçersiz algoritma: {algorithm}")
            return
        
        hash_obj = algorithms[algorithm]()
        
        with open(filename, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)
        
        print(f"Dosya: {filename}")
        print(f"Algoritma: {algorithm.upper()}")
        print(f"Hash: {hash_obj.hexdigest()}")
        
    except FileNotFoundError:
        print(f"[!] Dosya bulunamadı: {filename}")
    except Exception as e:
        print(f"[!] Hata: {e}")

def verify_hash(text, hash_value, algorithm='sha256'):
    print(f"[*] Hash doğrulaması yapılıyor...\n")
    
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    if algorithm not in algorithms:
        print(f"[!] Geçersiz algoritma: {algorithm}")
        return
    
    hash_obj = algorithms[algorithm](text.encode())
    calculated_hash = hash_obj.hexdigest()
    
    print(f"Verilen Hash  : {hash_value}")
    print(f"Hesaplanan Hash: {calculated_hash}")
    print()
    
    if calculated_hash == hash_value.lower():
        print("[+] DOĞRULAMA BAŞARILI! Hash değerleri eşleşiyor.")
    else:
        print("[!] DOĞRULAMA BAŞARISIZ! Hash değerleri eşleşmiyor.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Metin hash: python hash_generator.py text <metin> [algoritma]")
        print("  Dosya hash: python hash_generator.py file <dosya> [algoritma]")
        print("  Hash doğrulama: python hash_generator.py verify <metin> <hash> [algoritma]")
        print("\nÖrnekler:")
        print("  python hash_generator.py text 'Merhaba Dünya'")
        print("  python hash_generator.py file document.pdf sha256")
        print("  python hash_generator.py verify 'test' 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        sys.exit()
    
    mode = sys.argv[1]
    
    if mode == 'text' and len(sys.argv) >= 3:
        text = sys.argv[2]
        algo = sys.argv[3] if len(sys.argv) > 3 else 'all'
        hash_text(text, algo)
    elif mode == 'file' and len(sys.argv) >= 3:
        filename = sys.argv[2]
        algo = sys.argv[3] if len(sys.argv) > 3 else 'sha256'
        hash_file(filename, algo)
    elif mode == 'verify' and len(sys.argv) >= 4:
        text = sys.argv[2]
        hash_val = sys.argv[3]
        algo = sys.argv[4] if len(sys.argv) > 4 else 'sha256'
        verify_hash(text, hash_val, algo)
    else:
        print("[!] Geçersiz kullanım. Yardım için parametresiz çalıştırın.")

from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import sys

class SymmetricEncryption:
    def __init__(self, algorithm='AES'):
        self.algorithm = algorithm
        
    def encrypt_aes(self, plaintext, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return iv, ct
    
    def decrypt_aes(self, iv, ciphertext, key):
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ciphertext)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    
    def encrypt_des3(self, plaintext, key):
        cipher = DES3.new(key, DES3.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode(), DES3.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return iv, ct
    
    def decrypt_des3(self, iv, ciphertext, key):
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ciphertext)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), DES3.block_size)
        return pt.decode('utf-8')

def generate_key(algorithm='AES'):
    if algorithm == 'AES':
        return get_random_bytes(32)
    elif algorithm == 'DES3':
        return get_random_bytes(24)
    elif algorithm == 'Blowfish':
        return get_random_bytes(32)
    else:
        return get_random_bytes(32)

def main():
    if len(sys.argv) < 3:
        print("Kullanım:")
        print("  Şifreleme: python symmetric_encryption.py encrypt <metin> [algoritma]")
        print("  Şifre çözme: python symmetric_encryption.py decrypt <iv> <ciphertext> <key>")
        print("\nAlgoritmalar: AES (varsayılan), DES3")
        print("\nÖrnek:")
        print("  python symmetric_encryption.py encrypt 'Gizli Mesaj' AES")
        sys.exit()
    
    mode = sys.argv[1]
    
    if mode == 'encrypt':
        plaintext = sys.argv[2]
        algorithm = sys.argv[3] if len(sys.argv) > 3 else 'AES'
        
        key = generate_key(algorithm)
        enc = SymmetricEncryption(algorithm)
        
        print(f"[*] {algorithm} ile şifreleme yapılıyor...\n")
        
        if algorithm == 'AES':
            iv, ciphertext = enc.encrypt_aes(plaintext, key)
        elif algorithm == 'DES3':
            iv, ciphertext = enc.encrypt_des3(plaintext, key)
        else:
            print(f"[!] Desteklenmeyen algoritma: {algorithm}")
            sys.exit()
        
        key_b64 = base64.b64encode(key).decode('utf-8')
        
        print(f"Orijinal Metin: {plaintext}")
        print(f"\nŞifrelenmiş Veri:")
        print(f"  IV        : {iv}")
        print(f"  Ciphertext: {ciphertext}")
        print(f"  Key       : {key_b64}")
        print(f"\n[*] Bu bilgileri şifre çözme için saklayın!")
        
    elif mode == 'decrypt':
        if len(sys.argv) < 5:
            print("[!] Şifre çözme için IV, ciphertext ve key gerekli!")
            sys.exit()
        
        iv = sys.argv[2]
        ciphertext = sys.argv[3]
        key_b64 = sys.argv[4]
        algorithm = sys.argv[5] if len(sys.argv) > 5 else 'AES'
        
        key = base64.b64decode(key_b64)
        enc = SymmetricEncryption(algorithm)
        
        print(f"[*] {algorithm} ile şifre çözme yapılıyor...\n")
        
        try:
            if algorithm == 'AES':
                plaintext = enc.decrypt_aes(iv, ciphertext, key)
            elif algorithm == 'DES3':
                plaintext = enc.decrypt_des3(iv, ciphertext, key)
            else:
                print(f"[!] Desteklenmeyen algoritma: {algorithm}")
                sys.exit()
            
            print(f"Çözülen Metin: {plaintext}")
            
        except Exception as e:
            print(f"[!] Şifre çözme hatası: {e}")
    
    else:
        print("[!] Geçersiz mod. 'encrypt' veya 'decrypt' kullanın.")

if __name__ == "__main__":
    main()

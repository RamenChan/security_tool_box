from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import sys

def generate_keypair(key_size=2048):
    print(f"[*] {key_size} bit RSA anahtar çifti oluşturuluyor...\n")
    
    key = RSA.generate(key_size)
    
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    with open('private_key.pem', 'wb') as f:
        f.write(private_key)
    
    with open('public_key.pem', 'wb') as f:
        f.write(public_key)
    
    print("[+] Anahtar çifti oluşturuldu!")
    print("    Private Key: private_key.pem")
    print("    Public Key : public_key.pem")

def encrypt_message(message, public_key_file):
    print(f"[*] Mesaj şifreleniyor...\n")
    
    try:
        with open(public_key_file, 'rb') as f:
            public_key = RSA.import_key(f.read())
        
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(message.encode())
        encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
        
        print(f"Orijinal Mesaj: {message}")
        print(f"\nŞifrelenmiş Mesaj (Base64):")
        print(encrypted_b64)
        
        with open('encrypted_message.txt', 'w') as f:
            f.write(encrypted_b64)
        
        print("\n[+] Şifrelenmiş mesaj 'encrypted_message.txt' dosyasına kaydedildi.")
        
    except FileNotFoundError:
        print(f"[!] Public key dosyası bulunamadı: {public_key_file}")
    except Exception as e:
        print(f"[!] Şifreleme hatası: {e}")

def decrypt_message(encrypted_b64, private_key_file):
    print(f"[*] Mesaj şifresi çözülüyor...\n")
    
    try:
        with open(private_key_file, 'rb') as f:
            private_key = RSA.import_key(f.read())
        
        cipher = PKCS1_OAEP.new(private_key)
        encrypted = base64.b64decode(encrypted_b64)
        decrypted = cipher.decrypt(encrypted)
        
        print(f"Çözülen Mesaj: {decrypted.decode('utf-8')}")
        
    except FileNotFoundError:
        print(f"[!] Private key dosyası bulunamadı: {private_key_file}")
    except Exception as e:
        print(f"[!] Şifre çözme hatası: {e}")

def sign_message(message, private_key_file):
    print(f"[*] Mesaj imzalanıyor...\n")
    
    try:
        with open(private_key_file, 'rb') as f:
            private_key = RSA.import_key(f.read())
        
        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(private_key).sign(h)
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        print(f"Mesaj: {message}")
        print(f"\nİmza (Base64):")
        print(signature_b64)
        
        with open('signature.txt', 'w') as f:
            f.write(signature_b64)
        
        print("\n[+] İmza 'signature.txt' dosyasına kaydedildi.")
        
    except FileNotFoundError:
        print(f"[!] Private key dosyası bulunamadı: {private_key_file}")
    except Exception as e:
        print(f"[!] İmzalama hatası: {e}")

def verify_signature(message, signature_b64, public_key_file):
    print(f"[*] İmza doğrulanıyor...\n")
    
    try:
        with open(public_key_file, 'rb') as f:
            public_key = RSA.import_key(f.read())
        
        h = SHA256.new(message.encode())
        signature = base64.b64decode(signature_b64)
        
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            print("[+] İMZA GEÇERLİ! Mesaj doğrulandı.")
        except (ValueError, TypeError):
            print("[!] İMZA GEÇERSİZ! Mesaj değiştirilmiş olabilir.")
        
    except FileNotFoundError:
        print(f"[!] Public key dosyası bulunamadı: {public_key_file}")
    except Exception as e:
        print(f"[!] Doğrulama hatası: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Anahtar oluştur: python rsa_encryption.py generate [key_size]")
        print("  Şifrele        : python rsa_encryption.py encrypt <mesaj> <public_key.pem>")
        print("  Şifre çöz      : python rsa_encryption.py decrypt <encrypted_b64> <private_key.pem>")
        print("  İmzala         : python rsa_encryption.py sign <mesaj> <private_key.pem>")
        print("  İmza doğrula   : python rsa_encryption.py verify <mesaj> <signature_b64> <public_key.pem>")
        print("\nÖrnekler:")
        print("  python rsa_encryption.py generate 2048")
        print("  python rsa_encryption.py encrypt 'Gizli Mesaj' public_key.pem")
        sys.exit()
    
    command = sys.argv[1]
    
    if command == 'generate':
        key_size = int(sys.argv[2]) if len(sys.argv) > 2 else 2048
        generate_keypair(key_size)
    elif command == 'encrypt' and len(sys.argv) >= 4:
        message = sys.argv[2]
        public_key = sys.argv[3]
        encrypt_message(message, public_key)
    elif command == 'decrypt' and len(sys.argv) >= 4:
        encrypted = sys.argv[2]
        private_key = sys.argv[3]
        decrypt_message(encrypted, private_key)
    elif command == 'sign' and len(sys.argv) >= 4:
        message = sys.argv[2]
        private_key = sys.argv[3]
        sign_message(message, private_key)
    elif command == 'verify' and len(sys.argv) >= 5:
        message = sys.argv[2]
        signature = sys.argv[3]
        public_key = sys.argv[4]
        verify_signature(message, signature, public_key)
    else:
        print("[!] Geçersiz komut veya eksik parametre!")

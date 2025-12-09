import sys
import string
import random

def caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    
    if mode == 'decrypt':
        shift = -shift
    
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shifted = (ord(char) - ascii_offset + shift) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    
    return result

def vigenere_cipher(text, key, mode='encrypt'):
    result = ""
    key = key.upper()
    key_index = 0
    
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            key_char = key[key_index % len(key)]
            shift = ord(key_char) - 65
            
            if mode == 'decrypt':
                shift = -shift
            
            shifted = (ord(char) - ascii_offset + shift) % 26
            result += chr(shifted + ascii_offset)
            key_index += 1
        else:
            result += char
    
    return result

def substitution_cipher(text, key=None, mode='encrypt'):
    if key is None:
        alphabet = string.ascii_uppercase
        key = ''.join(random.sample(alphabet, len(alphabet)))
    
    alphabet = string.ascii_uppercase
    
    if mode == 'encrypt':
        trans_table = str.maketrans(alphabet + alphabet.lower(), 
                                     key + key.lower())
    else:
        trans_table = str.maketrans(key + key.lower(), 
                                     alphabet + alphabet.lower())
    
    return text.translate(trans_table), key

def atbash_cipher(text):
    result = ""
    
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr(90 - (ord(char) - 65))
            else:
                result += chr(122 - (ord(char) - 97))
        else:
            result += char
    
    return result

def brute_force_caesar(ciphertext):
    print("[*] Caesar Cipher brute force saldırısı başlatılıyor...\n")
    
    for shift in range(26):
        decrypted = caesar_cipher(ciphertext, shift, 'decrypt')
        print(f"Shift {shift:2d}: {decrypted}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Caesar    : python classical_ciphers.py caesar <metin> <shift> [encrypt/decrypt]")
        print("  Vigenere  : python classical_ciphers.py vigenere <metin> <anahtar> [encrypt/decrypt]")
        print("  Substitution: python classical_ciphers.py substitution <metin> [anahtar] [encrypt/decrypt]")
        print("  Atbash    : python classical_ciphers.py atbash <metin>")
        print("  Brute Force: python classical_ciphers.py bruteforce <ciphertext>")
        print("\nÖrnekler:")
        print("  python classical_ciphers.py caesar 'HELLO WORLD' 3 encrypt")
        print("  python classical_ciphers.py vigenere 'HELLO' 'KEY' encrypt")
        print("  python classical_ciphers.py bruteforce 'KHOOR ZRUOG'")
        sys.exit()
    
    cipher_type = sys.argv[1]
    
    if cipher_type == 'caesar' and len(sys.argv) >= 4:
        text = sys.argv[2]
        shift = int(sys.argv[3])
        mode = sys.argv[4] if len(sys.argv) > 4 else 'encrypt'
        
        result = caesar_cipher(text, shift, mode)
        print(f"\nOrijinal: {text}")
        print(f"Sonuç   : {result}")
        
    elif cipher_type == 'vigenere' and len(sys.argv) >= 4:
        text = sys.argv[2]
        key = sys.argv[3]
        mode = sys.argv[4] if len(sys.argv) > 4 else 'encrypt'
        
        result = vigenere_cipher(text, key, mode)
        print(f"\nOrijinal: {text}")
        print(f"Anahtar : {key}")
        print(f"Sonuç   : {result}")
        
    elif cipher_type == 'substitution' and len(sys.argv) >= 3:
        text = sys.argv[2]
        key = sys.argv[3] if len(sys.argv) > 3 and len(sys.argv[3]) == 26 else None
        mode = sys.argv[4] if len(sys.argv) > 4 else 'encrypt'
        
        result, used_key = substitution_cipher(text, key, mode)
        print(f"\nOrijinal: {text}")
        print(f"Anahtar : {used_key}")
        print(f"Sonuç   : {result}")
        
    elif cipher_type == 'atbash' and len(sys.argv) >= 3:
        text = sys.argv[2]
        result = atbash_cipher(text)
        print(f"\nOrijinal: {text}")
        print(f"Sonuç   : {result}")
        
    elif cipher_type == 'bruteforce' and len(sys.argv) >= 3:
        ciphertext = sys.argv[2]
        brute_force_caesar(ciphertext)
        
    else:
        print("[!] Geçersiz kullanım!")

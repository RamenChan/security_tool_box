import sys
import secrets
import string

def generate_password(length=16, use_uppercase=True, use_lowercase=True, 
                     use_digits=True, use_special=True):
    
    characters = ""
    
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation
    
    if not characters:
        print("[!] En az bir karakter türü seçilmelidir!")
        return None
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    
    return password

def generate_multiple_passwords(count=10, length=16):
    print(f"[*] {count} adet {length} karakterli güçlü şifre oluşturuluyor...\n")
    
    passwords = []
    
    for i in range(count):
        password = generate_password(length)
        passwords.append(password)
        print(f"{i+1:2d}. {password}")
    
    return passwords

def generate_passphrase(word_count=4):
    words = [
        'correct', 'horse', 'battery', 'staple', 'dragon', 'monkey', 'elephant',
        'giraffe', 'penguin', 'dolphin', 'tiger', 'lion', 'eagle', 'falcon',
        'mountain', 'river', 'ocean', 'forest', 'desert', 'valley', 'island',
        'thunder', 'lightning', 'rainbow', 'sunset', 'sunrise', 'moonlight',
        'crystal', 'diamond', 'emerald', 'sapphire', 'ruby', 'pearl', 'amber',
        'phoenix', 'griffin', 'unicorn', 'wizard', 'knight', 'castle', 'sword',
        'shield', 'armor', 'crown', 'throne', 'kingdom', 'empire', 'legend'
    ]
    
    selected_words = [secrets.choice(words) for _ in range(word_count)]
    passphrase = '-'.join(selected_words)
    
    return passphrase

def check_password_strength(password):
    print(f"\n[*] Şifre gücü analizi: {password}\n")
    
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    score = 0
    
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    if has_upper:
        score += 1
    if has_lower:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 1
    
    print(f"Uzunluk        : {length} karakter")
    print(f"Büyük harf     : {'✓' if has_upper else '✗'}")
    print(f"Küçük harf     : {'✓' if has_lower else '✗'}")
    print(f"Rakam          : {'✓' if has_digit else '✗'}")
    print(f"Özel karakter  : {'✓' if has_special else '✗'}")
    print(f"\nGüç Skoru      : {score}/7")
    
    if score <= 2:
        strength = "ÇOK ZAYIF"
    elif score <= 4:
        strength = "ZAYIF"
    elif score <= 5:
        strength = "ORTA"
    elif score <= 6:
        strength = "GÜÇLÜ"
    else:
        strength = "ÇOK GÜÇLÜ"
    
    print(f"Değerlendirme  : {strength}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Şifre oluştur    : python password_generator.py generate [uzunluk]")
        print("  Çoklu şifre      : python password_generator.py multiple [adet] [uzunluk]")
        print("  Passphrase       : python password_generator.py passphrase [kelime_sayısı]")
        print("  Güç kontrolü     : python password_generator.py check <şifre>")
        print("\nÖrnekler:")
        print("  python password_generator.py generate 20")
        print("  python password_generator.py multiple 10 16")
        print("  python password_generator.py passphrase 5")
        print("  python password_generator.py check 'MyP@ssw0rd123'")
        sys.exit()
    
    command = sys.argv[1]
    
    if command == 'generate':
        length = int(sys.argv[2]) if len(sys.argv) > 2 else 16
        password = generate_password(length)
        print(f"\n[+] Oluşturulan Şifre: {password}")
        check_password_strength(password)
        
    elif command == 'multiple':
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        length = int(sys.argv[3]) if len(sys.argv) > 3 else 16
        generate_multiple_passwords(count, length)
        
    elif command == 'passphrase':
        word_count = int(sys.argv[2]) if len(sys.argv) > 2 else 4
        passphrase = generate_passphrase(word_count)
        print(f"\n[+] Oluşturulan Passphrase: {passphrase}")
        
    elif command == 'check':
        if len(sys.argv) < 3:
            print("[!] Kontrol edilecek şifreyi belirtin!")
            sys.exit()
        password = sys.argv[2]
        check_password_strength(password)
        
    else:
        print("[!] Geçersiz komut!")

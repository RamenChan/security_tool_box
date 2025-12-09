import sys
import struct

def hex_dump(filepath, offset=0, length=512):
    print(f"[*] Hex dump oluşturuluyor: {filepath}\n")
    print(f"Offset: {offset}, Uzunluk: {length} bytes\n")
    
    try:
        with open(filepath, 'rb') as f:
            f.seek(offset)
            data = f.read(length)
        
        print(f"{'Offset':<10} {'Hex':<50} {'ASCII':<20}")
        print("-" * 80)
        
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            hex_part = hex_part.ljust(48)
            
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            
            print(f"{offset + i:08X}   {hex_part}  {ascii_part}")
        
        print(f"\n[*] Toplam {len(data)} byte görüntülendi.")
        
    except FileNotFoundError:
        print(f"[!] Dosya bulunamadı: {filepath}")
    except Exception as e:
        print(f"[!] Hata: {e}")

def compare_files(file1, file2):
    print(f"[*] Dosyalar karşılaştırılıyor:\n")
    print(f"  Dosya 1: {file1}")
    print(f"  Dosya 2: {file2}\n")
    
    try:
        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            data1 = f1.read()
            data2 = f2.read()
        
        if len(data1) != len(data2):
            print(f"[!] Dosya boyutları farklı:")
            print(f"    Dosya 1: {len(data1)} bytes")
            print(f"    Dosya 2: {len(data2)} bytes\n")
        
        min_length = min(len(data1), len(data2))
        differences = []
        
        for i in range(min_length):
            if data1[i] != data2[i]:
                differences.append(i)
        
        if differences:
            print(f"[!] {len(differences)} farklılık bulundu.\n")
            print(f"{'Offset':<10} {'Dosya 1':<10} {'Dosya 2':<10}")
            print("-" * 30)
            
            for offset in differences[:50]:
                print(f"{offset:08X}   {data1[offset]:02X}         {data2[offset]:02X}")
            
            if len(differences) > 50:
                print(f"\n... ve {len(differences) - 50} farklılık daha.")
        else:
            print("[+] Dosyalar özdeş!")
        
    except FileNotFoundError as e:
        print(f"[!] Dosya bulunamadı: {e}")
    except Exception as e:
        print(f"[!] Hata: {e}")

def analyze_pe_header(filepath):
    print(f"[*] PE header analiz ediliyor: {filepath}\n")
    
    try:
        with open(filepath, 'rb') as f:
            dos_header = f.read(64)
            
            if dos_header[:2] != b'MZ':
                print("[!] Geçerli bir PE dosyası değil (MZ imzası bulunamadı).")
                return
            
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            
            f.seek(pe_offset)
            pe_signature = f.read(4)
            
            if pe_signature != b'PE\x00\x00':
                print("[!] Geçerli bir PE imzası bulunamadı.")
                return
            
            coff_header = f.read(20)
            
            machine = struct.unpack('<H', coff_header[0:2])[0]
            num_sections = struct.unpack('<H', coff_header[2:4])[0]
            timestamp = struct.unpack('<I', coff_header[4:8])[0]
            characteristics = struct.unpack('<H', coff_header[18:20])[0]
            
            print("PE Header Bilgileri:")
            print("-" * 60)
            
            machine_types = {
                0x014c: 'x86 (32-bit)',
                0x8664: 'x64 (64-bit)',
                0x01c0: 'ARM',
                0xaa64: 'ARM64'
            }
            
            print(f"Mimari        : {machine_types.get(machine, f'Bilinmeyen (0x{machine:04X})')}")
            print(f"Bölüm Sayısı  : {num_sections}")
            
            from datetime import datetime
            compile_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            print(f"Derleme Zamanı: {compile_time}")
            
            print(f"\nÖzellikler:")
            if characteristics & 0x0001:
                print("  - Relocation bilgisi kaldırılmış")
            if characteristics & 0x0002:
                print("  - Çalıştırılabilir")
            if characteristics & 0x2000:
                print("  - DLL dosyası")
            
            optional_header = f.read(224)
            
            if len(optional_header) >= 2:
                magic = struct.unpack('<H', optional_header[0:2])[0]
                if magic == 0x010b:
                    print("\nFormat: PE32 (32-bit)")
                elif magic == 0x020b:
                    print("\nFormat: PE32+ (64-bit)")
            
            print("\n[+] PE header analizi tamamlandı.")
            
    except FileNotFoundError:
        print(f"[!] Dosya bulunamadı: {filepath}")
    except Exception as e:
        print(f"[!] Hata: {e}")

def search_bytes(filepath, search_pattern):
    print(f"[*] Byte dizisi aranıyor: {filepath}\n")
    print(f"Aranan desen: {search_pattern}\n")
    
    try:
        pattern_bytes = bytes.fromhex(search_pattern.replace(' ', ''))
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        matches = []
        offset = 0
        
        while True:
            index = data.find(pattern_bytes, offset)
            if index == -1:
                break
            matches.append(index)
            offset = index + 1
        
        if matches:
            print(f"[+] {len(matches)} eşleşme bulundu:\n")
            
            for match in matches[:20]:
                print(f"Offset: 0x{match:08X} ({match})")
                
                context_start = max(0, match - 8)
                context_end = min(len(data), match + len(pattern_bytes) + 8)
                context = data[context_start:context_end]
                
                hex_context = ' '.join(f'{b:02X}' for b in context)
                print(f"  Context: {hex_context}\n")
            
            if len(matches) > 20:
                print(f"... ve {len(matches) - 20} eşleşme daha.")
        else:
            print("[-] Eşleşme bulunamadı.")
        
    except ValueError:
        print("[!] Geçersiz hex formatı. Örnek: 'FF D0 90 90'")
    except FileNotFoundError:
        print(f"[!] Dosya bulunamadı: {filepath}")
    except Exception as e:
        print(f"[!] Hata: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Hex dump        : python memory_analyzer.py hexdump <dosya> [offset] [uzunluk]")
        print("  Dosya karşılaştır: python memory_analyzer.py compare <dosya1> <dosya2>")
        print("  PE analizi      : python memory_analyzer.py pe <dosya>")
        print("  Byte arama      : python memory_analyzer.py search <dosya> <hex_pattern>")
        print("\nÖrnekler:")
        print("  python memory_analyzer.py hexdump malware.exe 0 256")
        print("  python memory_analyzer.py compare file1.bin file2.bin")
        print("  python memory_analyzer.py pe program.exe")
        print("  python memory_analyzer.py search malware.exe 'FF D0 90 90'")
        sys.exit()
    
    command = sys.argv[1]
    
    if command == 'hexdump' and len(sys.argv) >= 3:
        filepath = sys.argv[2]
        offset = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        length = int(sys.argv[4]) if len(sys.argv) > 4 else 512
        hex_dump(filepath, offset, length)
    elif command == 'compare' and len(sys.argv) >= 4:
        file1 = sys.argv[2]
        file2 = sys.argv[3]
        compare_files(file1, file2)
    elif command == 'pe' and len(sys.argv) >= 3:
        filepath = sys.argv[2]
        analyze_pe_header(filepath)
    elif command == 'search' and len(sys.argv) >= 4:
        filepath = sys.argv[2]
        pattern = sys.argv[3]
        search_bytes(filepath, pattern)
    else:
        print("[!] Geçersiz kullanım!")

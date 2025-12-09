import socket
import sys
from datetime import datetime

def port_scanner(target, start_port=1, end_port=1024):
    print(f"\n[*] Port tarama başlatılıyor: {target}")
    print(f"[*] Tarama zamanı: {datetime.now()}\n")
    
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[!] Hostname çözümlenemedi. Çıkılıyor...")
        sys.exit()
    
    print(f"[*] Hedef IP: {target_ip}")
    print("-" * 50)
    
    open_ports = []
    
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "Bilinmeyen"
            print(f"[+] Port {port} AÇIK - Servis: {service}")
            open_ports.append(port)
        
        sock.close()
    
    print("-" * 50)
    print(f"\n[*] Tarama tamamlandı. {len(open_ports)} açık port bulundu.")
    print(f"[*] Bitiş zamanı: {datetime.now()}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python port_scanner.py <hedef> [başlangıç_port] [bitiş_port]")
        sys.exit()
    
    target = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
    
    port_scanner(target, start, end)

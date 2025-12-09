import socket
import struct
import sys
from datetime import datetime

def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i] << 8) + data[i + 1]
    if n:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def create_syn_packet(src_ip, dst_ip, src_port, dst_port):
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            69, 0, 40, 54321, 0, 64, 6, 0,
                            socket.inet_aton(src_ip),
                            socket.inet_aton(dst_ip))
    
    tcp_header = struct.pack('!HHLLBBHHH',
                             src_port, dst_port, 0, 0,
                             80, 2, 8192, 0, 0)
    
    pseudo_header = struct.pack('!4s4sBBH',
                                socket.inet_aton(src_ip),
                                socket.inet_aton(dst_ip),
                                0, 6, len(tcp_header))
    
    tcp_checksum = checksum(pseudo_header + tcp_header)
    
    tcp_header = struct.pack('!HHLLBBH',
                             src_port, dst_port, 0, 0,
                             80, 2, 8192) + struct.pack('H', tcp_checksum) + struct.pack('!H', 0)
    
    return ip_header + tcp_header

def syn_scan(target, ports):
    print(f"[*] SYN taraması başlatılıyor: {target}")
    print(f"[*] Zaman: {datetime.now()}\n")
    
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[!] Hostname çözümlenemedi")
        sys.exit()
    
    print(f"[*] Hedef IP: {target_ip}")
    print("-" * 50)
    
    open_ports = []
    
    for port in ports:
        try:
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
            
        except socket.error as e:
            print(f"[!] Port {port} taranırken hata: {e}")
    
    print("-" * 50)
    print(f"\n[*] Tarama tamamlandı. {len(open_ports)} açık port bulundu.")
    print(f"[*] Bitiş zamanı: {datetime.now()}")
    
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python syn_scanner.py <hedef> [port1,port2,port3...]")
        print("Örnek: python syn_scanner.py example.com 80,443,22")
        sys.exit()
    
    target = sys.argv[1]
    
    if len(sys.argv) > 2:
        ports = [int(p) for p in sys.argv[2].split(',')]
    else:
        ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 8080]
    
    syn_scan(target, ports)

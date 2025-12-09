import socket
import sys
import re

def banner_grabbing(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        
        print(f"[*] {target}:{port} bağlantısı kuruluyor...")
        sock.connect((target, port))
        
        sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        
        if banner:
            print(f"\n[+] Banner bilgisi alındı:\n")
            print(banner)
            
            server_match = re.search(r'Server: (.+)', banner)
            if server_match:
                print(f"\n[*] Sunucu: {server_match.group(1)}")
            
            powered_by = re.search(r'X-Powered-By: (.+)', banner)
            if powered_by:
                print(f"[*] Powered By: {powered_by.group(1)}")
        else:
            print("[-] Banner bilgisi alınamadı")
        
        sock.close()
        
    except socket.timeout:
        print(f"[-] Bağlantı zaman aşımına uğradı")
    except socket.error as e:
        print(f"[!] Socket hatası: {e}")
    except Exception as e:
        print(f"[!] Hata: {e}")

def scan_common_ports(target):
    common_ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP-Alt'
    }
    
    print(f"\n[*] {target} için yaygın portlar taranıyor...\n")
    
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        result = sock.connect_ex((target, port))
        
        if result == 0:
            print(f"[+] Port {port} ({service}) AÇIK")
            print(f"    Banner bilgisi alınıyor...")
            banner_grabbing(target, port)
            print("-" * 60)
        
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  python banner_grabber.py <hedef> [port]")
        print("  python banner_grabber.py example.com 80")
        print("  python banner_grabber.py example.com (yaygın portları tarar)")
        sys.exit()
    
    target = sys.argv[1]
    
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
        banner_grabbing(target, port)
    else:
        scan_common_ports(target)

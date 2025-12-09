import socket
import sys
import ipaddress

def ping_sweep(network):
    print(f"[*] {network} ağında ping taraması başlatılıyor...\n")
    
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"[!] Geçersiz ağ adresi: {e}")
        sys.exit()
    
    active_hosts = []
    
    for ip in net.hosts():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        
        try:
            result = sock.connect_ex((str(ip), 80))
            if result == 0:
                print(f"[+] Aktif host bulundu: {ip}")
                active_hosts.append(str(ip))
        except socket.error:
            pass
        finally:
            sock.close()
    
    print(f"\n[*] Tarama tamamlandı. {len(active_hosts)} aktif host bulundu.")
    
    if active_hosts:
        print("\n[*] Aktif hostlar:")
        for host in active_hosts:
            print(f"    - {host}")

def check_single_host(host, port=80):
    print(f"[*] {host} kontrolü yapılıyor...\n")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"[+] {host} AKTİF (Port {port} açık)")
            return True
        else:
            print(f"[-] {host} KAPALI veya erişilemiyor")
            return False
    except socket.error as e:
        print(f"[!] Hata: {e}")
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Ağ taraması: python network_scanner.py 192.168.1.0/24")
        print("  Tekil host: python network_scanner.py 192.168.1.1")
        sys.exit()
    
    target = sys.argv[1]
    
    if '/' in target:
        ping_sweep(target)
    else:
        check_single_host(target)

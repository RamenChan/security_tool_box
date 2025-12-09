import psutil
import sys
from datetime import datetime

def get_network_connections():
    print("[*] Aktif ağ bağlantıları listeleniyor...\n")
    
    connections = psutil.net_connections(kind='inet')
    
    print(f"{'Protokol':<10} {'Yerel Adres':<25} {'Uzak Adres':<25} {'Durum':<15} {'PID':<8}")
    print("-" * 90)
    
    for conn in connections:
        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        status = conn.status if conn.status else "N/A"
        pid = conn.pid if conn.pid else "N/A"
        
        print(f"{conn.type.name:<10} {local:<25} {remote:<25} {status:<15} {pid:<8}")
    
    print(f"\n[*] Toplam {len(connections)} bağlantı bulundu.")

def get_listening_ports():
    print("[*] Dinlenen portlar listeleniyor...\n")
    
    connections = psutil.net_connections(kind='inet')
    listening = [conn for conn in connections if conn.status == 'LISTEN']
    
    print(f"{'Port':<8} {'Protokol':<10} {'Adres':<20} {'PID':<8} {'Program':<30}")
    print("-" * 80)
    
    for conn in listening:
        port = conn.laddr.port
        protocol = conn.type.name
        address = conn.laddr.ip
        pid = conn.pid if conn.pid else "N/A"
        
        try:
            if pid != "N/A":
                proc = psutil.Process(pid)
                program = proc.name()
            else:
                program = "N/A"
        except:
            program = "N/A"
        
        print(f"{port:<8} {protocol:<10} {address:<20} {pid:<8} {program:<30}")
    
    print(f"\n[*] Toplam {len(listening)} dinlenen port bulundu.")

def find_suspicious_connections():
    print("[*] Şüpheli bağlantılar aranıyor...\n")
    
    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345]
    suspicious = []
    
    connections = psutil.net_connections(kind='inet')
    
    for conn in connections:
        if conn.raddr:
            remote_port = conn.raddr.port
            
            if remote_port in suspicious_ports:
                suspicious.append(conn)
                print(f"[!] ŞÜPHELİ PORT: {conn.raddr.ip}:{remote_port}")
                
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        print(f"    Süreç: {proc.name()} (PID: {conn.pid})")
                    except:
                        pass
                print()
        
        if conn.laddr and conn.status == 'LISTEN':
            local_port = conn.laddr.port
            
            if local_port in suspicious_ports:
                suspicious.append(conn)
                print(f"[!] ŞÜPHELİ DİNLEME: Port {local_port}")
                
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        print(f"    Süreç: {proc.name()} (PID: {conn.pid})")
                    except:
                        pass
                print()
    
    if not suspicious:
        print("[+] Şüpheli bağlantı bulunamadı.")
    else:
        print(f"[!] {len(suspicious)} şüpheli bağlantı tespit edildi!")

def get_network_stats():
    print("[*] Ağ istatistikleri alınıyor...\n")
    
    stats = psutil.net_io_counters()
    
    print("Ağ İstatistikleri:")
    print("-" * 60)
    print(f"Gönderilen Byte  : {stats.bytes_sent:,} ({stats.bytes_sent / (1024**3):.2f} GB)")
    print(f"Alınan Byte      : {stats.bytes_recv:,} ({stats.bytes_recv / (1024**3):.2f} GB)")
    print(f"Gönderilen Paket : {stats.packets_sent:,}")
    print(f"Alınan Paket     : {stats.packets_recv:,}")
    print(f"Giriş Hataları   : {stats.errin:,}")
    print(f"Çıkış Hataları   : {stats.errout:,}")
    print(f"Düşen Paketler   : {stats.dropin + stats.dropout:,}")

def monitor_connections(duration=60):
    print(f"[*] Ağ bağlantıları izleniyor ({duration} saniye)...\n")
    
    import time
    
    start_time = time.time()
    connection_history = {}
    
    while time.time() - start_time < duration:
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            if conn.raddr:
                key = f"{conn.raddr.ip}:{conn.raddr.port}"
                
                if key not in connection_history:
                    connection_history[key] = 1
                    print(f"[+] YENİ BAĞLANTI: {key}")
                    
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            print(f"    Süreç: {proc.name()} (PID: {conn.pid})")
                        except:
                            pass
                    print()
        
        time.sleep(5)
    
    print(f"\n[*] İzleme tamamlandı. {len(connection_history)} benzersiz bağlantı tespit edildi.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Tüm bağlantılar : python network_monitor.py connections")
        print("  Dinlenen portlar: python network_monitor.py listening")
        print("  Şüpheli bağlantı: python network_monitor.py suspicious")
        print("  Ağ istatistikleri: python network_monitor.py stats")
        print("  Bağlantı izleme : python network_monitor.py monitor [süre]")
        print("\nÖrnekler:")
        print("  python network_monitor.py connections")
        print("  python network_monitor.py suspicious")
        print("  python network_monitor.py monitor 120")
        sys.exit()
    
    command = sys.argv[1]
    
    if command == 'connections':
        get_network_connections()
    elif command == 'listening':
        get_listening_ports()
    elif command == 'suspicious':
        find_suspicious_connections()
    elif command == 'stats':
        get_network_stats()
    elif command == 'monitor':
        duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        monitor_connections(duration)
    else:
        print("[!] Geçersiz kullanım!")

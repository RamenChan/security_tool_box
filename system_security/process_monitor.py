import psutil
import sys
from datetime import datetime
import time

def list_all_processes():
    print("[*] Çalışan süreçler listeleniyor...\n")
    print(f"{'PID':<8} {'İsim':<30} {'Durum':<12} {'CPU%':<8} {'Bellek%':<10}")
    print("-" * 80)
    
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent']):
        try:
            pinfo = proc.info
            processes.append(pinfo)
            print(f"{pinfo['pid']:<8} {pinfo['name'][:29]:<30} {pinfo['status']:<12} "
                  f"{pinfo['cpu_percent']:<8.2f} {pinfo['memory_percent']:<10.2f}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    print(f"\n[*] Toplam {len(processes)} süreç bulundu.")
    return processes

def find_suspicious_processes():
    print("[*] Şüpheli süreçler aranıyor...\n")
    
    suspicious = []
    
    suspicious_names = ['nc', 'netcat', 'ncat', 'nmap', 'metasploit', 'msfconsole', 
                       'mimikatz', 'psexec', 'backdoor', 'rootkit']
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            pinfo = proc.info
            name = pinfo['name'].lower()
            
            if any(sus in name for sus in suspicious_names):
                suspicious.append(pinfo)
                print(f"[!] ŞÜPHELİ: PID {pinfo['pid']} - {pinfo['name']}")
                print(f"    Komut: {' '.join(pinfo['cmdline']) if pinfo['cmdline'] else 'N/A'}\n")
            
            if proc.cpu_percent(interval=0.1) > 80:
                print(f"[!] YÜKSEK CPU: PID {pinfo['pid']} - {pinfo['name']} ({proc.cpu_percent():.1f}%)")
            
            if proc.memory_percent() > 50:
                print(f"[!] YÜKSEK BELLEK: PID {pinfo['pid']} - {pinfo['name']} ({proc.memory_percent():.1f}%)")
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    if not suspicious:
        print("[+] Şüpheli süreç bulunamadı.")
    
    return suspicious

def monitor_process(pid, duration=60):
    print(f"[*] PID {pid} izleniyor ({duration} saniye)...\n")
    
    try:
        proc = psutil.Process(pid)
        print(f"Süreç: {proc.name()}")
        print(f"Durum: {proc.status()}")
        print(f"Başlangıç: {datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            cpu = proc.cpu_percent(interval=1)
            mem = proc.memory_percent()
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] CPU: {cpu:.1f}% | Bellek: {mem:.1f}%")
            
            time.sleep(5)
        
        print(f"\n[*] İzleme tamamlandı.")
        
    except psutil.NoSuchProcess:
        print(f"[!] PID {pid} bulunamadı.")
    except psutil.AccessDenied:
        print(f"[!] PID {pid} için erişim engellendi.")

def kill_process(pid):
    print(f"[*] PID {pid} sonlandırılıyor...\n")
    
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc.terminate()
        proc.wait(timeout=3)
        print(f"[+] Süreç sonlandırıldı: {proc_name} (PID: {pid})")
    except psutil.NoSuchProcess:
        print(f"[!] PID {pid} bulunamadı.")
    except psutil.AccessDenied:
        print(f"[!] PID {pid} için erişim engellendi. Yönetici yetkisi gerekebilir.")
    except psutil.TimeoutExpired:
        print(f"[!] Süreç yanıt vermiyor. Zorla sonlandırılıyor...")
        proc.kill()
        print(f"[+] Süreç zorla sonlandırıldı.")

def get_process_connections(pid):
    print(f"[*] PID {pid} için ağ bağlantıları listeleniyor...\n")
    
    try:
        proc = psutil.Process(pid)
        connections = proc.connections()
        
        if connections:
            print(f"{'Protokol':<10} {'Yerel Adres':<25} {'Uzak Adres':<25} {'Durum':<15}")
            print("-" * 80)
            
            for conn in connections:
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                print(f"{conn.type.name:<10} {local:<25} {remote:<25} {conn.status:<15}")
        else:
            print("[-] Aktif bağlantı bulunamadı.")
            
    except psutil.NoSuchProcess:
        print(f"[!] PID {pid} bulunamadı.")
    except psutil.AccessDenied:
        print(f"[!] PID {pid} için erişim engellendi.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Tüm süreçler    : python process_monitor.py list")
        print("  Şüpheli süreçler: python process_monitor.py suspicious")
        print("  Süreç izle      : python process_monitor.py monitor <pid> [süre]")
        print("  Süreç sonlandır : python process_monitor.py kill <pid>")
        print("  Ağ bağlantıları : python process_monitor.py connections <pid>")
        print("\nÖrnekler:")
        print("  python process_monitor.py list")
        print("  python process_monitor.py monitor 1234 60")
        print("  python process_monitor.py kill 1234")
        sys.exit()
    
    command = sys.argv[1]
    
    if command == 'list':
        list_all_processes()
    elif command == 'suspicious':
        find_suspicious_processes()
    elif command == 'monitor' and len(sys.argv) >= 3:
        pid = int(sys.argv[2])
        duration = int(sys.argv[3]) if len(sys.argv) > 3 else 60
        monitor_process(pid, duration)
    elif command == 'kill' and len(sys.argv) >= 3:
        pid = int(sys.argv[2])
        kill_process(pid)
    elif command == 'connections' and len(sys.argv) >= 3:
        pid = int(sys.argv[2])
        get_process_connections(pid)
    else:
        print("[!] Geçersiz kullanım!")

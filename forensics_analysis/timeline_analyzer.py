import sys
import os
from datetime import datetime, timedelta

def parse_timestamp(timestamp_str):
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%d/%b/%Y:%H:%M:%S',
        '%Y/%m/%d %H:%M:%S',
        '%b %d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S'
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except:
            continue
    
    return None

def create_timeline(log_files):
    print("[*] Timeline oluşturuluyor...\n")
    
    events = []
    
    for log_file in log_files:
        if not os.path.exists(log_file):
            print(f"[!] Dosya bulunamadı: {log_file}")
            continue
        
        print(f"[*] İşleniyor: {log_file}")
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    words = line.split()
                    if len(words) < 3:
                        continue
                    
                    timestamp_candidates = [
                        ' '.join(words[:2]),
                        ' '.join(words[:3]),
                        words[0]
                    ]
                    
                    for candidate in timestamp_candidates:
                        timestamp = parse_timestamp(candidate)
                        if timestamp:
                            events.append({
                                'timestamp': timestamp,
                                'source': os.path.basename(log_file),
                                'line': line,
                                'line_num': line_num
                            })
                            break
        
        except Exception as e:
            print(f"[!] Hata: {log_file} - {e}")
    
    events.sort(key=lambda x: x['timestamp'])
    
    print(f"\n[+] {len(events)} olay bulundu.\n")
    print("="*80)
    print("TIMELINE")
    print("="*80 + "\n")
    
    print(f"{'Zaman':<20} {'Kaynak':<20} {'Olay':<40}")
    print("-"*80)
    
    for event in events:
        timestamp_str = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        source = event['source'][:19]
        line = event['line'][:39]
        
        print(f"{timestamp_str:<20} {source:<20} {line:<40}")
    
    return events

def filter_timeline_by_time(events, start_time, end_time):
    print(f"\n[*] Timeline filtreleniyor: {start_time} - {end_time}\n")
    
    try:
        start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
        end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
    except:
        print("[!] Geçersiz zaman formatı. Format: YYYY-MM-DD HH:MM:SS")
        return
    
    filtered = [e for e in events if start_dt <= e['timestamp'] <= end_dt]
    
    print(f"[+] {len(filtered)} olay bulundu.\n")
    
    for event in filtered:
        timestamp_str = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp_str}] {event['source']}")
        print(f"  {event['line']}\n")

def analyze_event_frequency(events, interval_minutes=60):
    print(f"\n[*] Olay frekansı analiz ediliyor ({interval_minutes} dakikalık aralıklar)...\n")
    
    if not events:
        print("[-] Analiz edilecek olay bulunamadı.")
        return
    
    frequency = {}
    
    for event in events:
        timestamp = event['timestamp']
        interval_key = timestamp.replace(minute=0, second=0, microsecond=0)
        
        frequency[interval_key] = frequency.get(interval_key, 0) + 1
    
    sorted_freq = sorted(frequency.items(), key=lambda x: x[1], reverse=True)
    
    print("En Yoğun Zaman Dilimleri:")
    print("-"*60)
    print(f"{'Zaman':<20} {'Olay Sayısı':<15} {'Grafik':<25}")
    print("-"*60)
    
    max_count = sorted_freq[0][1] if sorted_freq else 1
    
    for timestamp, count in sorted_freq[:20]:
        timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M')
        bar_length = int((count / max_count) * 20)
        bar = '█' * bar_length
        
        print(f"{timestamp_str:<20} {count:<15} {bar}")

def correlate_events(events, keyword):
    print(f"\n[*] '{keyword}' ile ilgili olaylar aranıyor...\n")
    
    related_events = []
    
    for event in events:
        if keyword.lower() in event['line'].lower():
            related_events.append(event)
    
    if related_events:
        print(f"[+] {len(related_events)} ilgili olay bulundu.\n")
        
        for event in related_events[:30]:
            timestamp_str = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp_str}] {event['source']}")
            print(f"  {event['line']}\n")
    else:
        print("[-] İlgili olay bulunamadı.")

def export_timeline(events, output_file):
    print(f"\n[*] Timeline dışa aktarılıyor: {output_file}\n")
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("Timestamp,Source,Event\n")
            
            for event in events:
                timestamp_str = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                source = event['source']
                line = event['line'].replace(',', ';')
                
                f.write(f"{timestamp_str},{source},{line}\n")
        
        print(f"[+] Timeline başarıyla dışa aktarıldı: {output_file}")
        
    except Exception as e:
        print(f"[!] Hata: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım:")
        print("  Timeline oluştur: python timeline_analyzer.py create <log1> <log2> ...")
        print("  Zaman filtresi  : python timeline_analyzer.py filter <log1> <log2> ... --start <zaman> --end <zaman>")
        print("  Frekans analizi : python timeline_analyzer.py frequency <log1> <log2> ...")
        print("  Olay korelasyon : python timeline_analyzer.py correlate <log1> <log2> ... --keyword <anahtar>")
        print("  Dışa aktar      : python timeline_analyzer.py export <log1> <log2> ... --output <dosya>")
        print("\nÖrnekler:")
        print("  python timeline_analyzer.py create /var/log/auth.log /var/log/syslog")
        print("  python timeline_analyzer.py frequency access.log error.log")
        print("  python timeline_analyzer.py correlate auth.log --keyword 'failed'")
        sys.exit()
    
    command = sys.argv[1]
    
    log_files = []
    for arg in sys.argv[2:]:
        if arg.startswith('--'):
            break
        if os.path.exists(arg):
            log_files.append(arg)
    
    if not log_files:
        print("[!] Geçerli log dosyası belirtilmedi!")
        sys.exit()
    
    if command == 'create':
        create_timeline(log_files)
    elif command == 'frequency':
        events = create_timeline(log_files)
        analyze_event_frequency(events)
    elif command == 'correlate':
        if '--keyword' in sys.argv:
            keyword_index = sys.argv.index('--keyword')
            if keyword_index + 1 < len(sys.argv):
                keyword = sys.argv[keyword_index + 1]
                events = create_timeline(log_files)
                correlate_events(events, keyword)
            else:
                print("[!] --keyword parametresi için değer belirtilmedi!")
        else:
            print("[!] --keyword parametresi gerekli!")
    elif command == 'export':
        if '--output' in sys.argv:
            output_index = sys.argv.index('--output')
            if output_index + 1 < len(sys.argv):
                output_file = sys.argv[output_index + 1]
                events = create_timeline(log_files)
                export_timeline(events, output_file)
            else:
                print("[!] --output parametresi için değer belirtilmedi!")
        else:
            print("[!] --output parametresi gerekli!")
    else:
        print("[!] Geçersiz komut!")

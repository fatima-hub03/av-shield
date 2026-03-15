#!/usr/bin/env python3
import subprocess
import threading
import time
import json
import os
import sqlite3
from datetime import datetime

WATCH_DIRS = ["/tmp", "/home/fatima/Downloads", "/home/fatima/Desktop"]
AVSHIELD_BIN = "/home/fatima/av-shield/avshield"
DB_PATH = "/home/fatima/av-shield/database/avshield.db"
EVENTS_FILE = "/home/fatima/av-shield/database/realtime_events.json"

def load_events():
    if os.path.exists(EVENTS_FILE):
        with open(EVENTS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_event(filepath, result, threat):
    events = load_events()
    events.insert(0, {
        "filepath": filepath,
        "filename": os.path.basename(filepath),
        "result": result,
        "threat": threat or "None",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    events = events[:50]  # garder les 50 derniers
    with open(EVENTS_FILE, 'w') as f:
        json.dump(events, f)

def scan_file(filepath):
    try:
        # Ignorer fichiers système
        if any(x in filepath for x in ['.quar', '/quarantine/', '/reports/', '/logs/', '.tmp']):
            return
        if not os.path.isfile(filepath):
            return
        
        print(f"[RT] Scan: {filepath}")
        import requests as req
        response = req.post('http://localhost:5000/api/scan', 
            json={'path': filepath, 'auto': False, 'report': False, 'realtime': True},
            timeout=60)
        
        file_result = "CLEAN"
        threat = "None"
        
        if response.status_code == 200:
            try:
                data = response.json()
                if data:
                    # Chercher dans report.files
                    files = (data.get('report') or {}).get('files', [])
                    for f_info in files:
                        if f_info.get('filepath') == filepath:
                            file_result = f_info.get('result', 'CLEAN')
                            threat = f_info.get('threat', 'None')
                            break
                    # Si pas trouvé chercher dans files directement
                    if file_result == 'CLEAN' and not files:
                        files = data.get('files', [])
                        for f_info in files:
                            if f_info.get('filepath') == filepath:
                                file_result = f_info.get('result', 'CLEAN')
                                threat = f_info.get('threat', 'None')
                                break
            except Exception as e:
                print(f"[RT] Erreur parsing: {e}")
        
        print(f"[RT] {filepath} → {file_result}")
        
        save_event(filepath, file_result, threat)
        print(f"[RT] Résultat: {filepath} → {file_result}")
        
    except Exception as e:
        print(f"[RT] Erreur scan {filepath}: {e}")

def watch_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    
    print(f"[RT] Surveillance: {directory}")
    process = subprocess.Popen(
        ["inotifywait", "-m", "-e", "create,moved_to", "--format", "%w%f", directory],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    
    for line in process.stdout:
        filepath = line.strip()
        if filepath:
            time.sleep(0.5)  # attendre que le fichier soit écrit
            threading.Thread(target=scan_file, args=(filepath,), daemon=True).start()

def start_monitoring():
    print("[RT] Démarrage surveillance temps réel...")
    threads = []
    for d in WATCH_DIRS:
        t = threading.Thread(target=watch_directory, args=(d,), daemon=True)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()

if __name__ == "__main__":
    start_monitoring()

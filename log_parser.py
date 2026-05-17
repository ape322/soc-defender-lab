import time
import subprocess
import urllib.request
import json
import os
import re

WEBHOOK_URL = "https://discord.com/api/webhooks/1488632654864846992/LFyLjcbHTdjjl5hUh_DH4npvQRRZQ9Vvkg7Rz5blP-6RFq4xRpyE1bVKOdej0Ka-4biw"
ACTIVE_LOG = "/var/log/nginx/access.log"
LEDGER_FILE = "/var/log/soc_threat_ledger.json"

ATTACK_PATTERN = re.compile(r"(\.\./|\.env|phpmyadmin|wp-admin|<script>)", re.IGNORECASE)

def load_ledger():
    if os.path.exists(LEDGER_FILE):
        try:
            with open(LEDGER_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error reading ledger: {e}")
            return []
    return []

def save_ledger(banned_list):
    try:
        with open(LEDGER_FILE, 'w') as f:
            json.dump(banned_list, f)
    except Exception as e:
        print(f"[!] Error writing to ledger: {e}")

banned_ips_session = load_ledger()

def send_alert(ip, trigger):
    payload = {
        "content": f"🚨 **[SOC DEFENSE SYSTEM]** Attack Intercepted.\n🛡️ **Action:** IP successfully banned at Priority 1.\n🎯 **Target IP:** `{ip}`\n🔍 **Trigger:** `{trigger}`"
    }
    
    req = urllib.request.Request(
        WEBHOOK_URL, 
        data=json.dumps(payload).encode('utf-8'), 
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'SOC-Defender/1.3-Stable'
        }
    )
    
    try:
        urllib.request.urlopen(req)
    except Exception as e:
        print(f"[!] Webhook failure: {e}")

print(f"[*] Live Sentry Active. Loaded {len(banned_ips_session)} persistent bans.")
print(f"[*] Monitoring {ACTIVE_LOG} for malicious traffic...")
print("-" * 50)

try:
    # 1. Capture the initial inode (file ID) before we enter the loop
    current_ino = os.stat(ACTIVE_LOG).st_ino
    file = open(ACTIVE_LOG, 'r')
    file.seek(0, os.SEEK_END)
    
    while True:
        line = file.readline()
        
        if not line:
            # 2. THE FIX: The Log Rotation Heartbeat
            try:
                # Check if the file on disk has a different ID than the one we started with
                if os.stat(ACTIVE_LOG).st_ino != current_ino:
                    print("[*] WARNING: Log rotation detected! Re-attaching to new log file...")
                    file.close()
                    
                    # Open the new file created by Nginx/logrotate
                    file = open(ACTIVE_LOG, 'r')
                    current_ino = os.stat(ACTIVE_LOG).st_ino
                    
                    # Note: We do NOT use file.seek() here because we want to read 
                    # the new file from the very beginning so we don't miss attacks.
                    continue
            except FileNotFoundError:
                # If logrotate is in the split-second process of moving the file, 
                # os.stat might fail. We just sleep and try again.
                time.sleep(0.5)
                continue

            time.sleep(0.5)
            continue
            
        parts = line.split()
        
        if len(parts) > 6:
            suspect_ip = parts[0]
            request_uri = parts[6]
            
            match = ATTACK_PATTERN.search(request_uri)
            
            if match:
                matched_string = match.group(0)
                
                if not suspect_ip.startswith("127.") and suspect_ip not in banned_ips_session:
                    banned_ips_session.append(suspect_ip)
                    save_ledger(banned_ips_session)
                    
                    cmd = f"sudo ufw insert 1 deny from {suspect_ip}"
                    subprocess.run(cmd, shell=True, capture_output=True)
                    
                    print(f"[+] DEFENSE ACTIVE: Banned {suspect_ip} for requesting {matched_string}")
                    send_alert(suspect_ip, matched_string)
                
except Exception as e:
    print(f"[!] Critical System Error: {e}")
finally:
    # Failsafe to release the file lock if the daemon is killed
    try:
        file.close()
    except:
        pass

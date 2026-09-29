import time
import subprocess
import urllib.request
import json
import os
import re
import sys

WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK")
def get_webhook(url):
    if url is None:
        print("Error: DISCORD_WEBHOOK not set")
        sys.exit(1)
get_webhook(WEBHOOK_URL)
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

def is_valid_ip(text):
    numbers = text.split(".")
    if len(numbers) != 4:
        return False
    for i in numbers:
        if not i.isdigit():
            return False
        if int(i) > 255:
            return False
    return True

def ban_ip(ip):
    result = subprocess.run(["/usr/sbin/iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    if result.returncode == 0:
        return True
    else:
        result = subprocess.run(["/usr/sbin/iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], capture_output=True)
        if result.returncode == 0:
            return True
        return False


print(f"[*] Live Sentry Active. Loaded {len(banned_ips_session)} persistent bans.")
print(f"[*] Monitoring {ACTIVE_LOG} for malicious traffic...")
print("-" * 50)

try:
    # 1. Capture the initial inode (file ID) before we enter the loop
    current_ino = os.stat(ACTIVE_LOG).st_ino
    file = open(ACTIVE_LOG, 'r')
    file.seek(0, os.SEEK_END)

    for ip in banned_ips_session:
        result = ban_ip(ip)
        if result != True:
            print(f"[!] Banned ip loading failed: {ip}")
            sys.exit(1)
    
    
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
            if not is_valid_ip(suspect_ip):
                continue
            
            match = ATTACK_PATTERN.search(request_uri)
            
            if match:
                matched_string = match.group(0)
                
                if not suspect_ip.startswith("127.") and suspect_ip not in banned_ips_session:
                    banned_ips_session.append(suspect_ip)
                    save_ledger(banned_ips_session)
                    
                    cmd = ["/usr/sbin/iptables", "-I", "INPUT", "1", "-s", suspect_ip, "-j", "DROP"]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode != 0:
                        print(f"[!] FIREWALL INJECTION FAILED: {result.stderr}")
                    else:
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

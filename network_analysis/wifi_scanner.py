import sys
import subprocess
import re
import shutil
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def scan_wifi_networks():
    """Scans for available WiFi networks using native Windows commands."""
    print(f"\n{Style.BRIGHT}Scanning for WiFi networks...{Style.RESET_ALL}")

    netsh_path = shutil.which('netsh')
    if not netsh_path:
        print(f"{Fore.RED}Error: 'netsh' command not found. Please ensure it is in your system's PATH.")
        return

    try:
        command = [netsh_path, 'wlan', 'show', 'networks', 'mode=bssid']
        command_output = subprocess.check_output(
            command, 
            stderr=subprocess.DEVNULL, 
            encoding='utf-8',
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Fore.RED}Error: Could not execute 'netsh wlan show networks'. Ensure WiFi is enabled and you have permissions.")
        return

    networks = []
    current_network_info = {}
    # Process line by line, as block parsing has proven unreliable
    for line in command_output.split('\n'):
        line = line.strip()
        if not line:
            continue

        if line.startswith('SSID'):
            # When we find a new SSID, store the previous network's info if it exists
            if current_network_info.get('SSID'):
                networks.append(current_network_info)
            current_network_info = {'SSID': re.sub(r'SSID \d+ : ', '', line).strip()}
        elif line.startswith('Authentication'):
            current_network_info['Auth'] = re.sub(r'Authentication\s+: ', '', line).strip()
        elif line.startswith('Encryption'):
            current_network_info['Encryption'] = re.sub(r'Encryption\s+: ', '', line).strip()
        elif line.startswith('BSSID'):
            # A network can have multiple BSSIDs, so we treat each as a new entry
            # inheriting the parent SSID's info.
            bssid_info = current_network_info.copy()
            bssid_info['BSSID'] = re.sub(r'BSSID \d+\s+: ', '', line).strip()
            networks.append(bssid_info)
        elif line.startswith('Signal'):
            # The signal belongs to the most recently added BSSID
            if networks and 'BSSID' in networks[-1]:
                networks[-1]['Signal'] = re.sub(r'Signal\s+: ', '', line).strip()

    # Add the last parsed network if it wasn't added yet
    if current_network_info.get('SSID') and not any(d.get('SSID') == current_network_info['SSID'] for d in networks):
        networks.append(current_network_info)

    if not networks:
        print(f"{Fore.YELLOW}No WiFi networks found.")
        return

    print(f"\n{Style.BRIGHT}{'SSID':<30} {'BSSID':<20} {'SIGNAL':<10} {'AUTH':<20} {'ENCRYPTION'}{Style.RESET_ALL}")
    print("-" * 100)
    for network in networks:
        ssid = network.get('SSID', 'N/A')
        bssid = network.get('BSSID', 'N/A')
        signal = network.get('Signal', 'N/A')
        auth = network.get('Auth', 'N/A')
        enc = network.get('Encryption', 'N/A')
        print(f"{Fore.CYAN}{ssid:<30} {Fore.WHITE}{bssid:<20} {Fore.GREEN}{signal:<10} {Fore.YELLOW}{auth:<20} {Fore.YELLOW}{enc}")

if __name__ == "__main__":
    scan_wifi_networks()


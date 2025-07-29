import sys
import subprocess
from scapy.all import sniff, ARP
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

ip_mac_map = {}

def get_gateway_ip():
    """Finds the default gateway IP address by parsing 'ipconfig' output on Windows."""
    try:
        result = subprocess.check_output(['ipconfig'], stderr=subprocess.DEVNULL, encoding='utf-8')
        gateway_line = [line for line in result.split('\n') if 'Default Gateway' in line]
        if gateway_line:
            # Extract the IP address, which is the last part of the line
            gateway_ip = gateway_line[0].split(':')[-1].strip()
            if gateway_ip and gateway_ip != '0.0.0.0':
                return gateway_ip
    except (subprocess.CalledProcessError, FileNotFoundError, IndexError) as e:
        print(f"{Fore.RED}Error finding gateway IP via ipconfig: {e}")
    
    print(f"{Fore.RED}Could not determine gateway IP. Please check your network connection.")
    return None

def get_mac(ip):
    """Returns the MAC address for a given IP using multiple methods."""
    # Try using Scapy first
    try:
        ans, _ = sys.modules['scapy.all'].srp(
            sys.modules['scapy.all'].Ether(dst='ff:ff:ff:ff:ff:ff')/sys.modules['scapy.all'].ARP(pdst=ip),
            timeout=2,
            verbose=False,
            retry=2
        )
        if ans:
            return ans[0][1].hwsrc
    except Exception as e:
        print(f"{Fore.YELLOW}Note: Could not use Scapy to get MAC: {e}")
    
    # Fallback to arp command
    try:
        # Run arp -a and parse the output
        result = subprocess.check_output(['arp', '-a'], stderr=subprocess.DEVNULL, encoding='utf-8')
        for line in result.split('\n'):
            if ip in line:
                # Extract MAC address (format: XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX)
                mac_match = re.search(r'([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}', line)
                if mac_match:
                    return mac_match.group(0).replace('-', ':')
    except Exception as e:
        print(f"{Fore.YELLOW}Note: Could not use arp command: {e}")
    
    print(f"{Fore.RED}Warning: Could not resolve MAC address for {ip}")
    print(f"{Fore.YELLOW}This is normal if the device is not responding to ARP requests.")
    return None

def process_arp_packet(packet):
    """Processes ARP packets to detect potential spoofing."""
    global ip_mac_map
    gateway_ip = ip_mac_map.get("gateway_ip")
    gateway_mac = ip_mac_map.get("gateway_mac")

    if packet.haslayer(ARP) and packet[ARP].op == 2: # op=2 is 'is-at' (reply)
        ip_addr = packet[ARP].psrc
        mac_addr = packet[ARP].hwsrc

        # HIGH-PRIORITY CHECK: Is someone impersonating the gateway?
        if ip_addr == gateway_ip and mac_addr != gateway_mac:
            print(f"{Fore.RED}{Style.BRIGHT}[!!!] CRITICAL: GATEWAY ARP SPOOFING DETECTED! [!!!]{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Gateway IP:   {gateway_ip}")
            print(f"{Fore.GREEN}Legitimate MAC: {gateway_mac}")
            print(f"{Fore.RED}Spoofed MAC:    {mac_addr}")
            print("-"*50)
            return

        if ip_addr in ip_mac_map and ip_mac_map[ip_addr] != mac_addr:
            print(f"{Fore.YELLOW}[!] WARNING: ARP entry changed for {ip_addr}{Style.RESET_ALL}")
            print(f"    Original MAC: {ip_mac_map[ip_addr]}")
            print(f"    New MAC:      {mac_addr}")
            print("-"*50)
        
        # Update the map for all devices
        if ip_addr not in ip_mac_map:
             print(f"{Fore.GREEN}[+] New device found: {ip_addr} is at {mac_addr}")
        ip_mac_map[ip_addr] = mac_addr

def start_detector():
    """Starts the ARP spoof detector."""
    global ip_mac_map
    
    print(f"{Fore.CYAN}Detecting network gateway...{Style.RESET_ALL}")
    gateway_ip = get_gateway_ip()
    if not gateway_ip:
        print(f"{Fore.RED}Could not determine gateway IP. Continuing with basic ARP monitoring...")
        gateway_ip = None
        gateway_mac = None
    else:
        print(f"{Fore.GREEN}Found gateway IP: {gateway_ip}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Resolving gateway MAC address...{Style.RESET_ALL}")
        gateway_mac = get_mac(gateway_ip)
        if not gateway_mac:
            print(f"{Fore.YELLOW}Warning: Could not resolve gateway MAC address. Continuing with IP-only monitoring.{Style.RESET_ALL}"
                  f"{Fore.YELLOW}This is normal if the gateway doesn't respond to ARP requests.{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}Gateway MAC: {gateway_mac}{Style.RESET_ALL}")
    
    # Store gateway info if available
    if gateway_ip:
        ip_mac_map["gateway_ip"] = gateway_ip
        if gateway_mac:
            ip_mac_map["gateway_mac"] = gateway_mac
            ip_mac_map[gateway_ip] = gateway_mac

    print(f"\n{Style.BRIGHT}Starting ARP Spoof Detector... Press Ctrl+C to stop.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Monitoring Gateway: {gateway_ip} ({gateway_mac}){Style.RESET_ALL}")
    print("Monitoring network for ARP replies...")

    try:
        sniff(store=False, prn=process_arp_packet, filter="arp")
    except PermissionError:
        print(f"{Fore.RED}Permission Error: Please run this script with administrator/root privileges.")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

if __name__ == "__main__":
    print(f"{Fore.RED}{Style.BRIGHT}NOTE: This script requires administrator/root privileges to capture network packets.")
    start_detector()

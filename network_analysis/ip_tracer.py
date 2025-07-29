import sys
import socket
import struct
import requests
import concurrent.futures
from scapy.all import IP, UDP, sr1, conf, ARP, Ether, srp, ICMP, TCP
from colorama import Fore, Style, init
from datetime import datetime

# Initialize colorama
init(autoreset=True)

# Scapy can be verbose, this quiets it down
conf.verb = 0

# Common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                993, 995, 1723, 3306, 3389, 5900, 8080]

class NetworkScanner:
    """Class to handle network scanning operations."""
    
    @staticmethod
    def get_hostname(ip):
        """Get hostname for a given IP address."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return "N/A"
    
    @staticmethod
    def get_mac(ip):
        """Get MAC address for a given IP using ARP."""
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                        timeout=2, verbose=0)
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass
        return "N/A"
    
    @staticmethod
    def scan_ports(ip, ports=COMMON_PORTS, max_workers=50):
        """Scan common ports on a target IP."""
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return port
            except (socket.timeout, socket.error):
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(check_port, port): port 
                           for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result() is not None:
                        open_ports.append(port)
                except Exception:
                    pass
        
        return sorted(open_ports) if open_ports else []

    @staticmethod
    def get_network_info(ip):
        """Get comprehensive network information for an IP."""
        if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', 
                         '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                         '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
            return {
                'type': 'private',
                'hostname': NetworkScanner.get_hostname(ip),
                'mac': NetworkScanner.get_mac(ip),
                'ports': NetworkScanner.scan_ports(ip)
            }
        return {'type': 'public'}

def get_geolocation(ip):
    """Fetches detailed geolocation data for a given IP address."""
    # Check for private IPs
    if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', 
                     '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                     '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
        return {
            'status': 'private',
            'type': 'Private IP Address',
            'info': NetworkScanner.get_network_info(ip)
        }
    
    try:
        # Request detailed geolocation data
        response = requests.get(
            f"http://ip-api.com/json/{ip}?"
            "fields=status,message,continent,continentCode,country,countryCode,"
            "region,regionName,city,district,zip,lat,lon,timezone,offset,"
            "currency,isp,org,as,asname,reverse,mobile,proxy,hosting",
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        
        if data.get('status') == 'success':
            # Format detailed location information
            location = {
                'status': 'success',
                'location': {
                    'city': data.get('city', 'N/A'),
                    'region': data.get('regionName', 'N/A'),
                    'country': data.get('country', 'N/A'),
                    'coordinates': f"{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}",
                    'timezone': data.get('timezone', 'N/A')
                },
                'network': {
                    'isp': data.get('isp', 'N/A'),
                    'org': data.get('org', 'N/A'),
                    'as': data.get('as', 'N/A'),
                    'asname': data.get('asname', 'N/A'),
                    'mobile': data.get('mobile', False),
                    'proxy': data.get('proxy', False),
                    'hosting': data.get('hosting', False)
                },
                'ports': NetworkScanner.scan_ports(ip)  # Scan ports for public IPs too
            }
            return location
        else:
            return {
                'status': 'error',
                'message': data.get('message', 'Geolocation lookup failed')
            }
    except requests.exceptions.RequestException as e:
        return {
            'status': 'error',
            'message': f"API request error: {str(e)}"
        }

def trace_route(target):
    """Performs a traceroute to the target and displays geolocation for each hop."""
    print(f"\n{Style.BRIGHT}Tracing route to {target} [max 30 hops]:{Style.RESET_ALL}\n")
    
    for ttl in range(1, 31):
        # Create a UDP packet with increasing TTL
        pkt = IP(dst=target, ttl=ttl) / UDP(dport=33434)
        
        # Send the packet and wait for a reply
        reply = sr1(pkt, timeout=2)

        if reply is None:
            # No reply from a hop
            print(f"{ttl:2d}. {Fore.YELLOW}* * * Request timed out.{Fore.RESET}")
        elif reply.type == 3:  # ICMP 'Time Exceeded' message
            hop_ip = reply.src
            location = get_geolocation(hop_ip)
            print(f"{ttl:2d}. {Fore.CYAN}{hop_ip:<15} {Fore.GREEN}{location}")
            # If we've reached the destination, we can stop
            if hop_ip == target:
                break
        elif reply.type == 0:  # ICMP 'Echo Reply' means we've reached the destination
            hop_ip = reply.src
            location = get_geolocation(hop_ip)
            print(f"{ttl:2d}. {Fore.CYAN}{hop_ip:<15} {Fore.GREEN}{location}")
            print(f"\n{Style.BRIGHT}Trace complete.{Style.RESET_ALL}")
            break
        else:
            # Unexpected reply
            print(f"{ttl:2d}. Unexpected reply from {reply.src}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{Fore.YELLOW}Usage: python {sys.argv[0]} <hostname_or_ip>")
        sys.exit(1)

    target_host = sys.argv[1]
    trace_route(target_host)

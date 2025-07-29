import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def packet_callback(packet):
    """Callback function to process each captured packet."""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        proto_color = Fore.WHITE
        protocol_name = 'Other'

        if protocol == 6:  # TCP
            protocol_name = 'TCP'
            proto_color = Fore.CYAN
            try:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                print(f"{proto_color}{protocol_name:<5} {Fore.YELLOW}{ip_src}:{src_port} -> {Fore.GREEN}{ip_dst}:{dst_port}")
            except IndexError:
                pass
        elif protocol == 17:  # UDP
            protocol_name = 'UDP'
            proto_color = Fore.MAGENTA
            try:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"{proto_color}{protocol_name:<5} {Fore.YELLOW}{ip_src}:{src_port} -> {Fore.GREEN}{ip_dst}:{dst_port}")
            except IndexError:
                pass
        elif protocol == 1:  # ICMP
            protocol_name = 'ICMP'
            proto_color = Fore.RED
            print(f"{proto_color}{protocol_name:<5} {Fore.YELLOW}{ip_src} -> {Fore.GREEN}{ip_dst}")

def start_sniffer(count=0):
    """Starts the network sniffer."""
    print(f"\n{Style.BRIGHT}Starting network sniffer... Press Ctrl+C to stop.{Style.RESET_ALL}")
    if count > 0:
        print(f"Capturing {count} packets.")
        sniff(prn=packet_callback, store=0, count=count)
    else:
        print("Capturing packets indefinitely.")
        sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    # This tool requires administrative/root privileges to run.
    print(f"{Fore.RED}{Style.BRIGHT}NOTE: This script may require administrator/root privileges to capture network packets.")
    
    num_packets = 0
    if len(sys.argv) > 1:
        try:
            num_packets = int(sys.argv[1])
        except ValueError:
            print(f"{Fore.YELLOW}Usage: python {sys.argv[0]} [number_of_packets]")
            sys.exit(1)

    try:
        start_sniffer(num_packets)
    except PermissionError:
        print(f"{Fore.RED}Permission Error: Please run this script with administrator/root privileges.")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

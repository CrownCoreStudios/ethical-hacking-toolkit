import socket
import sys
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def scan_ports(target, start_port, end_port):
    """Scans a target for open ports within a given range."""
    print(f"\n{Style.BRIGHT}Scanning target: {target}{Style.RESET_ALL}")
    print(f"Time started: {datetime.now()}\n")

    try:
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"{Fore.GREEN}[+] Port {port} is open")
            else:
                # To avoid clutter, we can choose not to print closed ports
                # print(f"{Fore.RED}[-] Port {port} is closed")
                pass
            sock.close()

    except socket.gaierror:
        print(f"{Fore.RED}Hostname could not be resolved. Exiting.")
        sys.exit()
    except socket.error:
        print(f"{Fore.RED}Couldn't connect to server. Exiting.")
        sys.exit()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan stopped by user.")
        sys.exit()

    print(f"\n{Style.BRIGHT}Scan finished at: {datetime.now()}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"{Fore.YELLOW}Usage: python {sys.argv[0]} <target> <start_port> <end_port>")
        sys.exit()

    target_host = sys.argv[1]
    start = int(sys.argv[2])
    end = int(sys.argv[3])

    scan_ports(target_host, start, end)

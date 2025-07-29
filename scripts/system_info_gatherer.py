import psutil
import platform
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def get_size(bytes, suffix="B"):
    """Scale bytes to its proper format e.g: 1024 bytes -> 1 KB"""
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

def get_system_info():
    """Gathers and displays detailed system information."""
    print(f"\n{Style.BRIGHT}--- System Information ---")

    # OS Info
    uname = platform.uname()
    print(f"{Fore.CYAN}{'OS:':<20} {uname.system} {uname.release} ({uname.version})")
    print(f"{Fore.CYAN}{'Machine:':<20} {uname.machine}")

    # CPU Info
    print(f"\n{Style.BRIGHT}--- CPU Information ---")
    cpu_freq = psutil.cpu_freq()
    print(f"{Fore.GREEN}{'Physical Cores:':<20} {psutil.cpu_count(logical=False)}")
    print(f"{Fore.GREEN}{'Total Cores:':<20} {psutil.cpu_count(logical=True)}")
    print(f"{Fore.GREEN}{'Max Frequency:':<20} {cpu_freq.max:.2f}Mhz")
    print(f"{Fore.GREEN}{'Current Frequency:':<20} {cpu_freq.current:.2f}Mhz")

    # Memory Info
    print(f"\n{Style.BRIGHT}--- Memory Information ---")
    svmem = psutil.virtual_memory()
    print(f"{Fore.YELLOW}{'Total Memory:':<20} {get_size(svmem.total)}")
    print(f"{Fore.YELLOW}{'Available Memory:':<20} {get_size(svmem.available)}")
    print(f"{Fore.YELLOW}{'Used Memory:':<20} {get_size(svmem.used)} ({svmem.percent}%)")

    # Disk Info
    print(f"\n{Style.BRIGHT}--- Disk Information ---")
    partitions = psutil.disk_partitions()
    for partition in partitions:
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
            print(f"{Fore.MAGENTA}  Device: {partition.device}, Mountpoint: {partition.mountpoint}")
            print(f"{Fore.MAGENTA}{'    Total Size:':<20} {get_size(partition_usage.total)}")
            print(f"{Fore.MAGENTA}{'    Used:':<20} {get_size(partition_usage.used)} ({partition_usage.percent}%)")
        except PermissionError:
            continue

    # Running Processes (Top 5 by memory)
    print(f"\n{Style.BRIGHT}--- Top 5 Processes by Memory ---")
    processes = sorted(psutil.process_iter(['pid', 'name', 'memory_info']), key=lambda p: p.info['memory_info'].rss, reverse=True)
    for process in processes[:5]:
        print(f"{Fore.WHITE}{process.info['pid']:<10} {process.info['name']:<40} {get_size(process.info['memory_info'].rss)}")

if __name__ == "__main__":
    get_system_info()

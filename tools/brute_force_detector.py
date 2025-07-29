#!/usr/bin/env python3
"""
Brute Force Attack Detector

This script monitors network traffic to detect potential brute force attacks
against various services (SSH, FTP, RDP, etc.). It analyzes connection attempts
and generates alerts when suspicious patterns are detected.

Usage:
    python brute_force_detector.py -i <interface> -t <threshold> -w <time_window>
    python brute_force_detector.py -i eth0 -t 5 -w 60
"""

import argparse
import pyshark
import time
from collections import defaultdict, deque
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class BruteForceDetector:
    """Detect brute force attacks by monitoring network traffic."""
    
    def __init__(self, interface, threshold=5, time_window=60):
        """
        Initialize the detector.
        
        Args:
            interface: Network interface to monitor
            threshold: Number of failed attempts to trigger an alert
            time_window: Time window in seconds to monitor for failed attempts
        """
        self.interface = interface
        self.threshold = threshold
        self.time_window = time_window
        self.attempts = defaultdict(lambda: {
            'failed': deque(),
            'successful': deque(),
            'alerted': False
        })
        
        # Common ports for various services
        self.service_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            445: 'SMB',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Proxy'
        }
        
        # Status messages
        self.status_colors = {
            'INFO': Fore.CYAN,
            'WARNING': Fore.YELLOW,
            'ALERT': Fore.RED,
            'SUCCESS': Fore.GREEN
        }
    
    def get_service_name(self, port):
        """Get service name from port number."""
        return self.service_ports.get(int(port), f'Port {port}')
    
    def log(self, level, message, src_ip=None, dst_port=None):
        """Print a formatted log message."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        color = self.status_colors.get(level, Fore.WHITE)
        
        if src_ip and dst_port:
            service = self.get_service_name(dst_port)
            print(f"{Fore.WHITE}[{timestamp}] {color}{level:<8}{Style.RESET_ALL} "
                  f"{Fore.CYAN}{src_ip:<15} -> {service:<10}{Style.RESET_ALL} {message}")
        else:
            print(f"{Fore.WHITE}[{timestamp}] {color}{level:<8}{Style.RESET_ALL} {message}")
    
    def detect_brute_force(self, packet):
        """Analyze packet for potential brute force attempts."""
        try:
            # Check if packet has IP and TCP layers
            if 'IP' not in packet or 'TCP' not in packet:
                return
            
            src_ip = packet.ip.src
            dst_port = int(packet.tcp.dstport)
            flags = int(packet.tcp.flags, 16)
            
            # Check for RST/ACK (connection refused) or SYN/ACK (successful connection)
            is_failed = (flags & 0x04) or (flags & 0x12)  # RST or SYN-ACK
            is_successful = (flags & 0x12) == 0x12  # SYN-ACK
            
            current_time = time.time()
            
            # Get or create entry for this source IP
            ip_data = self.attempts[src_ip]
            
            # Remove old entries outside our time window
            while ip_data['failed'] and current_time - ip_data['failed'][0] > self.time_window:
                ip_data['failed'].popleft()
            
            while ip_data['successful'] and current_time - ip_data['successful'][0] > self.time_window:
                ip_data['successful'].popleft()
            
            # Log the attempt
            if is_successful:
                ip_data['successful'].append(current_time)
                self.log('SUCCESS', 'Successful login', src_ip, dst_port)
            elif is_failed:
                ip_data['failed'].append(current_time)
                
                # Check for potential brute force
                if len(ip_data['failed']) >= self.threshold and not ip_data['alerted']:
                    service = self.get_service_name(dst_port)
                    self.log('ALERT', 
                           f'Possible brute force attack detected: {len(ip_data["failed"])} ' 
                           f'failed attempts in {self.time_window} seconds',
                           src_ip, dst_port)
                    ip_data['alerted'] = True
                else:
                    self.log('WARNING', 'Failed login attempt', src_ip, dst_port)
            
            # Reset alert if we see a successful login
            if is_successful and ip_data['alerted']:
                self.log('INFO', 'Attack alert reset - successful login detected', src_ip, dst_port)
                ip_data['alerted'] = False
                
        except Exception as e:
            self.log('ERROR', f'Error processing packet: {str(e)}')
    
    def start(self):
        """Start monitoring network traffic."""
        try:
            self.log('INFO', f'Starting Brute Force Detector on interface {self.interface}')
            self.log('INFO', f'Threshold: {self.threshold} failed attempts in {self.time_window} seconds')
            
            # Set up capture filter for common authentication ports
            ports = ','.join(map(str, self.service_ports.keys()))
            capture_filter = f'tcp port {ports} and (tcp.flags.syn==1 or tcp.flags.rst==1)'
            
            # Start capturing packets
            capture = pyshark.LiveCapture(
                interface=self.interface,
                display_filter=capture_filter,
                only_summaries=False
            )
            
            self.log('INFO', f'Monitoring ports: {ports}')
            self.log('INFO', 'Press Ctrl+C to stop...')
            
            for packet in capture.sniff_continuously():
                self.detect_brute_force(packet)
                
        except KeyboardInterrupt:
            self.log('INFO', 'Stopping Brute Force Detector...')
        except Exception as e:
            self.log('ERROR', f'Fatal error: {str(e)}')

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Brute Force Attack Detector')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to monitor')
    parser.add_argument('-t', '--threshold', type=int, default=5, 
                       help='Number of failed attempts to trigger an alert (default: 5)')
    parser.add_argument('-w', '--window', type=int, default=60,
                       help='Time window in seconds to monitor (default: 60)')
    return parser.parse_args()

def main():
    """Main function."""
    try:
        args = parse_args()
        detector = BruteForceDetector(
            interface=args.interface,
            threshold=args.threshold,
            time_window=args.window
        )
        detector.start()
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        return 1
    return 0

if __name__ == "__main__":
    main()

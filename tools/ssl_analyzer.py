#!/usr/bin/env python3
"""
SSL/TLS Configuration Analyzer

This script checks the SSL/TLS configuration of a web server and identifies potential security issues.
It checks for weak ciphers, SSL/TLS versions, certificate validity, and other security-related settings.

Usage:
    python ssl_analyzer.py <hostname:port>
    python ssl_analyzer.py example.com:443
    python ssl_analyzer.py 192.168.1.1:8443
"""

import ssl
import socket
import argparse
import datetime
from OpenSSL import SSL
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class SSLAnalyzer:
    """Analyze SSL/TLS configuration of a web server."""
    
    def __init__(self, hostname, port=443):
        self.hostname = hostname
        self.port = port
        self.context = SSL.Context(SSL.TLS_METHOD)
        self.conn = None
        self.cert = None
        self.findings = []
    
    def connect(self):
        """Establish an SSL connection to the server."""
        try:
            # Create a socket and wrap it with SSL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            self.conn = SSL.Connection(self.context, sock)
            self.conn.connect((self.hostname, self.port))
            self.conn.set_tlsext_host_name(self.hostname.encode())
            self.conn.set_connect_state()
            self.conn.do_handshake()
            self.cert = self.conn.get_peer_certificate()
            return True
        except Exception as e:
            self.findings.append(("Error", f"Connection failed: {str(e)}"))
            return False
    
    def check_certificate(self):
        """Check certificate validity and details."""
        if not self.cert:
            self.findings.append(("Error", "No certificate found"))
            return
        
        # Check certificate expiration
        not_after = datetime.datetime.strptime(
            self.cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        days_remaining = (not_after - datetime.datetime.now()).days
        
        if days_remaining < 0:
            self.findings.append(("Critical", f"Certificate expired {abs(days_remaining)} days ago"))
        elif days_remaining < 15:
            self.findings.append(("High", f"Certificate expires in {days_remaining} days"))
        else:
            self.findings.append(("Info", f"Certificate valid for {days_remaining} more days"))
        
        # Check certificate subject
        subject = self.cert.get_subject()
        self.findings.append(("Info", f"Subject: {subject.CN if hasattr(subject, 'CN') else 'N/A'}"))
        
        # Check issuer
        issuer = self.cert.get_issuer()
        self.findings.append(("Info", f"Issuer: {issuer.O if hasattr(issuer, 'O') else 'N/A'}"))
        
        # Check key size
        try:
            key_size = self.cert.get_pubkey().bits()
            if key_size < 2048:
                self.findings.append(("High", f"Weak key size: {key_size} bits (recommended: ≥ 2048)"))
            else:
                self.findings.append(("Info", f"Key size: {key_size} bits"))
        except:
            pass
    
    def check_tls_versions(self):
        """Check supported TLS versions."""
        tls_versions = {
            'SSLv2': (False, 'Insecure'),
            'SSLv3': (False, 'Insecure'),
            'TLSv1': (False, 'Deprecated'),
            'TLSv1.1': (False, 'Deprecated'),
            'TLSv1.2': (True, 'Secure'),
            'TLSv1.3': (True, 'Secure')
        }
        
        for version_name, (is_secure, status) in tls_versions.items():
            try:
                context = SSL.Context(getattr(SSL, f'{version_name.upper()}_METHOD', None))
                conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                conn.settimeout(5)
                conn.connect((self.hostname, self.port))
                conn.set_tlsext_host_name(self.hostname.encode())
                conn.set_connect_state()
                conn.do_handshake()
                conn.close()
                
                if is_secure:
                    self.findings.append(("Info", f"{version_name}: Supported ({status})"))
                else:
                    self.findings.append(("High", f"{version_name}: Supported ({status})"))
            except:
                if not is_secure:
                    self.findings.append(("Info", f"{version_name}: Not supported (Good)"))
    
    def check_ciphers(self):
        """Check supported cipher suites."""
        try:
            context = SSL.Context(SSL.TLS_METHOD)
            conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            conn.settimeout(5)
            conn.connect((self.hostname, self.port))
            conn.set_tlsext_host_name(self.hostname.encode())
            conn.set_connect_state()
            cipher = conn.cipher()
            self.findings.append(("Info", f"Current Cipher: {cipher[0]} ({cipher[2]} bits)"))
            conn.close()
        except Exception as e:
            self.findings.append(("Error", f"Failed to get cipher info: {str(e)}"))
    
    def analyze(self):
        """Run all security checks."""
        if not self.connect():
            return
            
        self.check_certificate()
        self.check_tls_versions()
        self.check_ciphers()
        
        if self.conn:
            self.conn.close()
    
    def print_results(self):
        """Print the analysis results with color coding."""
        print(f"\n{Style.BRIGHT}SSL/TLS Analysis for {self.hostname}:{self.port}{Style.RESET_ALL}")
        print("-" * 60)
        
        for severity, message in self.findings:
            color = {
                'Critical': Fore.RED,
                'High': Fore.YELLOW,
                'Medium': Fore.LIGHTYELLOW_EX,
                'Low': Fore.CYAN,
                'Info': Fore.GREEN,
                'Error': Fore.RED
            }.get(severity, Fore.WHITE)
            
            print(f"[{color}{severity}{Style.RESET_ALL}] {message}")
        
        print("\n" + "=" * 60)
        print(f"{Style.BRIGHT}Legend:{Style.RESET_ALL}")
        print(f"{Fore.RED}Critical{Style.RESET_ALL}: Immediate action required")
        print(f"{Fore.YELLOW}High{Style.RESET_ALL}: Should be addressed")
        print(f"{Fore.LIGHTYELLOW_EX}Medium{Style.RESET_ALL}: Consider addressing")
        print(f"{Fore.CYAN}Low{Style.RESET_ALL}: Informational")
        print(f"{Fore.GREEN}Info{Style.RESET_ALL}: General information")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='SSL/TLS Configuration Analyzer')
    parser.add_argument('target', help='Target hostname and port (e.g., example.com:443)')
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_args()
    
    # Parse hostname and port
    if ':' in args.target:
        hostname, port = args.target.split(':', 1)
        port = int(port)
    else:
        hostname = args.target
        port = 443  # Default HTTPS port
    
    # Run the analysis
    analyzer = SSLAnalyzer(hostname, port)
    analyzer.analyze()
    analyzer.print_results()

if __name__ == "__main__":
    main()

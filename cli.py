#!/usr/bin/env python3
"""
Ethical Hacking Toolkit - Command Line Interface

This module provides a command-line interface for the Ethical Hacking Toolkit.
"""

import argparse
import sys
from typing import List, Optional

from rich.console import Console
from rich.table import Table

# Import tool modules
from network_analysis import ip_tracer, network_sniffer, port_scanner, wifi_scanner
from forensic_analysis import memory_analyzer, browser_history
from reverse_engineering import pe_analyzer

# Initialize console for rich output
console = Console()

def print_banner() -> None:
    """Print the toolkit banner."""
    banner = """
    [bold blue]╔══════════════════════════════════════════╗[/]
    [bold blue]║    🛡️  ETHICAL HACKING TOOLKIT  🛡️     ║[/]
    [bold blue]╚══════════════════════════════════════════╝[/]
    [dim]A comprehensive toolkit for security analysis[/]
    """
    console.print(banner)

def print_available_tools() -> None:
    """Print a table of available tools."""
    tools = [
        {"Name": "IP Tracer", "Module": "ip_tracer", "Description": "Trace IP addresses and get geolocation"},
        {"Name": "Network Sniffer", "Module": "network_sniffer", "Description": "Capture and analyze network traffic"},
        {"Name": "Port Scanner", "Module": "port_scanner", "Description": "Scan for open ports on a target"},
        {"Name": "WiFi Scanner", "Module": "wifi_scanner", "Description": "Scan for available WiFi networks"},
        {"Name": "Memory Analyzer", "Module": "memory_analyzer", "Description": "Analyze memory dumps for forensic investigation"},
        {"Name": "Browser History", "Module": "browser_history", "Description": "Extract and analyze browser history"},
        {"Name": "PE Analyzer", "Module": "pe_analyzer", "Description": "Analyze Windows PE files"},
    ]
    
    table = Table(title="\n[bold]Available Tools[/]")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Module", style="magenta")
    table.add_column("Description")
    
    for tool in tools:
        table.add_row(tool["Name"], tool["Module"], tool["Description"])
    
    console.print(table)

def parse_args(args: List[str]) -> argparse.Namespace:
    """Parse command line arguments.
    
    Args:
        args: List of command line arguments
        
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Ethical Hacking Toolkit - A collection of security analysis tools"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Tool to run")
    
    # IP Tracer
    ip_parser = subparsers.add_parser("ip-trace", help="Trace an IP address")
    ip_parser.add_argument("ip", help="IP address to trace")
    
    # Port Scanner
    port_parser = subparsers.add_parser("port-scan", help="Scan ports on a target")
    port_parser.add_argument("target", help="Target IP or hostname")
    port_parser.add_argument("-p", "--ports", default="1-1024", 
                           help="Port range to scan (e.g., 1-1000 or 80,443,8080)")
    
    # Memory Analyzer
    mem_parser = subparsers.add_parser("analyze-memory", help="Analyze a memory dump")
    mem_parser.add_argument("dump_file", help="Path to memory dump file")
    mem_parser.add_argument("-p", "--profile", help="Volatility profile (optional)")
    
    # List command
    subparsers.add_parser("list", help="List all available tools")
    
    return parser.parse_args(args)

def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI.
    
    Args:
        args: Command line arguments (defaults to sys.argv[1:])
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    if args is None:
        args = sys.argv[1:]
    
    if not args:
        print_banner()
        print_available_tools()
        return 0
    
    try:
        parsed_args = parse_args(args)
        
        if parsed_args.command == "list" or not parsed_args.command:
            print_banner()
            print_available_tools()
        elif parsed_args.command == "ip-trace":
            ip_tracer.trace(parsed_args.ip)
        elif parsed_args.command == "port-scan":
            port_scanner.scan(parsed_args.target, parsed_args.ports)
        elif parsed_args.command == "analyze-memory":
            memory_analyzer.analyze(parsed_args.dump_file, parsed_args.profile)
        else:
            console.print(f"[red]Error:[/] Unknown command '{parsed_args.command}'")
            return 1
            
    except KeyboardInterrupt:
        console.print("\n[red]Operation cancelled by user[/]")
        return 1
    except Exception as e:
        console.print(f"[red]Error:[/] {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Memory Forensics Analyzer

Basic memory analysis using Volatility 3. Extracts processes, network connections,
and other forensic artifacts from memory dumps.

Usage:
    python memory_analyzer.py <memory_dump> [--profile=PROFILE] [--output=DIR]
"""

import os
import json
import argparse
import subprocess
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class MemoryAnalyzer:
    """Analyze memory dumps using Volatility 3."""
    
    def __init__(self, memory_dump, profile=None, output_dir='memory_analysis'):
        self.memory_dump = os.path.abspath(memory_dump)
        self.profile = profile
        self.output_dir = output_dir
        self.results = {}
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_volatility(self, plugin, output_file=None):
        """Run a Volatility plugin and return the output."""
        try:
            cmd = ['vol', '-f', self.memory_dump, '--renderer=json', plugin]
            if self.profile:
                cmd.extend(['--profile', self.profile])
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            if result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    if output_file:
                        with open(os.path.join(self.output_dir, output_file), 'w') as f:
                            json.dump(data, f, indent=2)
                    return data
                except json.JSONDecodeError:
                    if output_file:
                        with open(os.path.join(self.output_dir, output_file), 'w') as f:
                            f.write(result.stdout)
                    return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Error: {e.stderr}{Style.RESET_ALL}")
        return None
    
    def detect_profile(self):
        """Detect the appropriate Volatility profile."""
        if self.profile:
            return self.profile
            
        print(f"{Fore.CYAN}Detecting memory profile...{Style.RESET_ALL}")
        result = self.run_volatility('windows.info.Info')
        
        if result and 'Suggested Profile(s)' in result:
            self.profile = result['Suggested Profile(s)'].split(',')[0].strip()
            print(f"{Fore.GREEN}Detected profile: {self.profile}{Style.RESET_ALL}")
            return self.profile
        return None
    
    def analyze(self):
        """Run all available analyses."""
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Starting memory analysis at {datetime.now()}{Style.RESET_ALL}")
        
        self.detect_profile()
        
        # Run analyses
        analyses = {
            'Process Tree': 'windows.pstree.PsTree',
            'Network Connections': 'windows.netscan.NetScan',
            'DLLs': 'windows.dlllist.DllList',
            'Malware Indicators': 'windows.malfind.Malfind',
            'Registry Hives': 'windows.registry.hivelist.HiveList'
        }
        
        for name, plugin in analyses.items():
            print(f"{Fore.CYAN}Analyzing {name.lower()}...{Style.RESET_ALL}")
            output_file = f"{plugin.split('.')[-1].lower()}.json"
            self.results[name.lower().replace(' ', '_')] = self.run_volatility(plugin, output_file)
        
        print(f"\n{Fore.GREEN}Analysis completed at {datetime.now()}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Results saved to: {os.path.abspath(self.output_dir)}{Style.RESET_ALL}")
        return self.results

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Memory Forensics Analyzer')
    parser.add_argument('memory_dump', help='Path to the memory dump file')
    parser.add_argument('--profile', help='Volatility profile to use')
    parser.add_argument('-o', '--output', default='memory_analysis',
                      help='Output directory for analysis results')
    return parser.parse_args()

def main():
    """Main function."""
    try:
        args = parse_args()
        
        if not os.path.isfile(args.memory_dump):
            print(f"{Fore.RED}Error: Memory dump file not found{Style.RESET_ALL}")
            return 1
        
        analyzer = MemoryAnalyzer(
            memory_dump=args.memory_dump,
            profile=args.profile,
            output_dir=args.output
        )
        
        analyzer.analyze()
        return 0
        
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        return 1

if __name__ == "__main__":
    main()

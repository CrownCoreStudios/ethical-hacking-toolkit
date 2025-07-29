#!/usr/bin/env python3
"""PE File Analyzer - Enhanced with security features and detailed analysis."""

import sys
import os
import hashlib
import math
import pefile
import peutils
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class PEAnalyzer:
    """Enhanced PE file analyzer with security features."""
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.pe = None
        self.file_size = os.path.getsize(filepath)
        self.file_hash = self._calculate_file_hash()
    
    def _calculate_file_hash(self):
        """Calculate file hashes."""
        hashes = {}
        with open(self.filepath, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
        return hashes
    
    def _get_entropy(self, data):
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    
    def analyze(self):
        """Perform comprehensive PE analysis."""
        try:
            self.pe = pefile.PE(self.filepath)
            
            # Basic info
            result = {
                'file_info': {
                    'filename': os.path.basename(self.filepath),
                    'size': f"{self.file_size} bytes",
                    'hashes': self.file_hash,
                    'compile_time': datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S'),
                    'machine': hex(self.pe.FILE_HEADER.Machine),
                    'sections_count': self.pe.FILE_HEADER.NumberOfSections,
                    'is_dll': bool(self.pe.FILE_HEADER.Characteristics & 0x2000)
                },
                'sections': [],
                'imports': {},
                'security': {
                    'aslr': bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040),
                    'dep': bool(self.pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100)
                }
            }
            
            # Sections
            for section in self.pe.sections:
                section_data = section.get_data()
                result['sections'].append({
                    'name': section.Name.decode('utf-8').strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': hex(section.Misc_VirtualSize),
                    'raw_size': hex(section.SizeOfRawData),
                    'entropy': f"{self._get_entropy(section_data):.4f}",
                    'md5': hashlib.md5(section_data).hexdigest()
                })
            
            # Imports
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8')
                    result['imports'][dll] = [
                        imp.name.decode('utf-8') 
                        for imp in entry.imports 
                        if imp.name
                    ]
            
            return result
            
        except pefile.PEFormatError as e:
            print(f"{Fore.RED}Error: Not a valid PE file - {e}")
            return None
        finally:
            if hasattr(self, 'pe'):
                self.pe.close()
    
    def print_results(self, results):
        """Print analysis results."""
        if not results:
            return
        
        # File Info
        print(f"\n{Style.BRIGHT}{Fore.CYAN}=== File Information ==={Style.RESET}")
        info = results['file_info']
        print(f"{Fore.YELLOW}File:{Fore.WHITE} {info['filename']}")
        print(f"{Fore.YELLOW}Size:{Fore.WHITE} {info['size']}")
        print(f"{Fore.YELLOW}Type:{Fore.WHITE} {'DLL' if info['is_dll'] else 'EXE'}")
        print(f"{Fore.YELLOW}Compile Time:{Fore.WHITE} {info['compile_time']}")
        
        # Hashes
        print(f"\n{Fore.YELLOW}Hashes:")
        for name, value in info['hashes'].items():
            print(f"  {name.upper()}: {Fore.WHITE}{value}")
        
        # Security
        print(f"\n{Style.BRIGHT}{Fore.CYAN}=== Security Features ==={Style.RESET}")
        sec = results['security']
        print(f"{Fore.YELLOW}ASLR:{Fore.WHITE} {'Enabled' if sec['aslr'] else 'Disabled'}")
        print(f"{Fore.YELLOW}DEP:{Fore.WHITE} {'Enabled' if sec['dep'] else 'Disabled'}")
        
        # Sections
        print(f"\n{Style.BRIGHT}{Fore.CYAN}=== Sections ({len(results['sections'])}) ==={Style.RESET}")
        print(f"{'Name':<10} {'Virtual Addr':<15} {'Size':<15} {'Entropy':<10} MD5")
        print("-" * 70)
        for section in results['sections']:
            print(f"{Fore.GREEN}{section['name']:<10}{Style.RESET_ALL} "
                  f"{section['virtual_address']:<15} {section['virtual_size']:<15} "
                  f"{section['entropy']:<10} {section['md5']}")
        
        # Imports
        if results['imports']:
            print(f"\n{Style.BRIGHT}{Fore.CYAN}=== Imports ==={Style.RESET}")
            for dll, functions in results['imports'].items():
                if not functions:
                    continue
                print(f"\n{Fore.YELLOW}{dll}{Style.RESET_ALL}")
                for func in functions[:10]:  # Show first 10 functions
                    print(f"  - {func}")
                if len(functions) > 10:
                    print(f"  ... and {len(functions) - 10} more")

def main():
    if len(sys.argv) != 2:
        print(f"{Fore.YELLOW}Usage: python {sys.argv[0]} <path_to_pe_file>")
        sys.exit(1)
    
    analyzer = PEAnalyzer(sys.argv[1])
    results = analyzer.analyze()
    analyzer.print_results(results)

if __name__ == "__main__":
    main()

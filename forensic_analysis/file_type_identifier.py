import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# A dictionary of common file signatures (magic numbers)
MAGIC_NUMBERS = {
    b'\x89PNG\r\n\x1a\n': 'PNG Image',
    b'\xFF\xD8\xFF': 'JPEG Image',
    b'GIF87a': 'GIF Image',
    b'GIF89a': 'GIF Image',
    b'%PDF-': 'PDF Document',
    b'PK\x03\x04': 'ZIP Archive (e.g., .zip, .docx, .jar)',
    b'MZ': 'Windows PE File (e.g., .exe, .dll)',
    b'\x7fELF': 'Linux Executable (ELF)',
    b'\xCA\xFE\xBA\xBE': 'Java Class File',
    b'#!/bin/bash': 'Bash Script',
    b'-- SQLite format 3': 'SQLite Database',
}

def identify_file(filepath):
    """Identifies a file's type based on its magic numbers."""
    print(f"\n{Style.BRIGHT}Identifying file type for: {filepath}{Style.RESET_ALL}\n")
    try:
        with open(filepath, 'rb') as f:
            # Read the first 32 bytes for matching
            file_signature = f.read(32)

        found_type = 'Unknown'
        for magic, filetype in MAGIC_NUMBERS.items():
            if file_signature.startswith(magic):
                found_type = filetype
                break
        
        if found_type != 'Unknown':
            print(f"{Fore.GREEN}Detected File Type: {found_type}")
        else:
            print(f"{Fore.YELLOW}Could not determine file type based on known signatures.")

    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found at '{filepath}'")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{Fore.YELLOW}Usage: python {sys.argv[0]} <file_path>")
        sys.exit(1)

    file_to_identify = sys.argv[1]
    identify_file(file_to_identify)

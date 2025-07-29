import sys
import string
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def extract_strings(filepath, min_len=4):
    """Extracts printable strings from a file."""
    print(f"\n{Style.BRIGHT}Extracting strings from: {filepath}{Style.RESET_ALL}\n")
    try:
        with open(filepath, "rb") as f:
            result = ""
            for char_byte in f.read():
                char = chr(char_byte)
                if char in string.printable:
                    result += char
                else:
                    if len(result) >= min_len:
                        print(f"{Fore.GREEN}{result}")
                    result = ""
            if len(result) >= min_len:
                print(f"{Fore.GREEN}{result}")
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found at '{filepath}'")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{Fore.YELLOW}Usage: python {sys.argv[0]} <file_path>")
        sys.exit(1)

    file_to_analyze = sys.argv[1]
    extract_strings(file_to_analyze)

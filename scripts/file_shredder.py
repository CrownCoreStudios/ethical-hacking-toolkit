import sys
import os
import random
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def shred_file(filepath, passes=3):
    """Securely deletes a file by overwriting it with random data."""
    print(f"\n{Style.BRIGHT}Shredding file: {filepath}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}This action is irreversible. Please be certain.")
    
    confirm = input("Type 'yes' to confirm and proceed: ")
    if confirm.lower() != 'yes':
        print(f"{Fore.GREEN}Aborted by user.")
        return

    try:
        if not os.path.exists(filepath):
            raise FileNotFoundError

        file_size = os.path.getsize(filepath)
        print(f"File size: {file_size} bytes. Starting shredding process...")

        with open(filepath, 'rb+') as f:
            for i in range(passes):
                print(f"  - Pass {i + 1}/{passes}...")
                f.seek(0)
                # Generate and write random bytes
                random_data = os.urandom(file_size)
                f.write(random_data)
                f.flush() # Ensure data is written to disk
        
        # After overwriting, delete the file
        os.remove(filepath)
        print(f"\n{Fore.GREEN}File '{filepath}' has been securely shredded and deleted.")

    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found at '{filepath}'")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{Fore.YELLOW}Usage: python {sys.argv[0]} <file_to_shred>")
        sys.exit(1)

    file_to_destroy = sys.argv[1]
    shred_file(file_to_destroy)

import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def process_xor(input_file, output_file, key):
    """Applies a repeating XOR key to a file."""
    print(f"\n{Style.BRIGHT}Processing file: {input_file}{Style.RESET_ALL}")
    print(f"Using key: '{key}'")
    try:
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            key_bytes = key.encode('utf-8')
            key_len = len(key_bytes)
            i = 0
            while (byte := f_in.read(1)):
                xor_byte = bytes([byte[0] ^ key_bytes[i % key_len]])
                f_out.write(xor_byte)
                i += 1
        print(f"{Fore.GREEN}Successfully processed and saved to: {output_file}")
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Input file not found at '{input_file}'")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"{Fore.YELLOW}Usage: python {sys.argv[0]} <input_file> <output_file> <key>")
        print(f"{Fore.YELLOW}Example: python {sys.argv[0]} encoded.bin decoded.txt mysecretkey")
        sys.exit(1)

    in_file = sys.argv[1]
    out_file = sys.argv[2]
    xor_key = sys.argv[3]

    if not xor_key:
        print(f"{Fore.RED}Error: The key cannot be empty.")
        sys.exit(1)

    process_xor(in_file, out_file, xor_key)

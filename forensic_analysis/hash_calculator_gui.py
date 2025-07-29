import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib

class HashCalculatorApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("File Hash Calculator")
        self.geometry("600x400")
        self.configure(bg="#2E2E2E")

        self.file_path = ""

        self.create_widgets()

    def create_widgets(self):
        # Style configurations
        label_font = ("Helvetica", 12)
        button_font = ("Helvetica", 10, "bold")
        result_font = ("Courier", 11)
        bg_color = "#2E2E2E"
        fg_color = "#F0F0F0"
        button_bg = "#4A4A4A"
        button_fg = "#FFFFFF"

        # Frame for better organization
        main_frame = tk.Frame(self, padx=20, pady=20, bg=bg_color)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # File selection button
        select_button = tk.Button(main_frame, text="Select File", font=button_font, bg=button_bg, fg=button_fg, command=self.select_file)
        select_button.pack(pady=(0, 10))

        # Label to display selected file path
        self.file_label = tk.Label(main_frame, text="No file selected", font=label_font, bg=bg_color, fg="#AAAAAA")
        self.file_label.pack(pady=(0, 20), fill=tk.X)

        # Frame for hash results
        results_frame = tk.Frame(main_frame, bg="#3C3C3C", bd=1, relief=tk.SUNKEN)
        results_frame.pack(fill=tk.BOTH, expand=True)

        # Hash labels and results
        self.md5_label = self.create_hash_label(results_frame, "MD5:", result_font)
        self.sha1_label = self.create_hash_label(results_frame, "SHA-1:", result_font)
        self.sha256_label = self.create_hash_label(results_frame, "SHA-256:", result_font)

    def create_hash_label(self, parent, text, font):
        frame = tk.Frame(parent, bg="#3C3C3C")
        frame.pack(pady=10, padx=10, fill=tk.X)
        
        label = tk.Label(frame, text=text, font=font, bg="#3C3C3C", fg="#00A0D0")
        label.pack(side=tk.LEFT)
        
        result_var = tk.StringVar()
        result_entry = tk.Entry(frame, textvariable=result_var, state='readonly', readonlybackground="#3C3C3C", fg="#F0F0F0", bd=0, font=font)
        result_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        return result_var

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.file_label.config(text=self.file_path)
            self.calculate_hashes()
        else:
            self.file_label.config(text="No file selected")

    def calculate_hashes(self):
        try:
            with open(self.file_path, 'rb') as f:
                file_bytes = f.read()
                md5_hash = hashlib.md5(file_bytes).hexdigest()
                sha1_hash = hashlib.sha1(file_bytes).hexdigest()
                sha256_hash = hashlib.sha256(file_bytes).hexdigest()

                self.md5_label.set(md5_hash)
                self.sha1_label.set(sha1_hash)
                self.sha256_label.set(sha256_hash)

        except Exception as e:
            messagebox.showerror("Error", f"Could not read file: {e}")
            self.md5_label.set("")
            self.sha1_label.set("")
            self.sha256_label.set("")

if __name__ == "__main__":
    app = HashCalculatorApp()
    app.mainloop()

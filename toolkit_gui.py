import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import subprocess
import threading
import os

class ToolGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ethical Malware Toolkit")
        self.geometry("1000x800")

        # Configure dark theme
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.configure_dark_theme()

        # Create Tabbed Interface
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # Create Output Console
        self.output_console = scrolledtext.ScrolledText(self, height=15, bg='#1e1e1e', fg='white', font=("Consolas", 10))
        self.output_console.pack(expand=True, fill='both', padx=10, pady=(0, 10))

        # --- Define Tools by Category ---
        self.tools = {
            "Network Analysis": [
                {'name': 'Port Scanner', 'script': 'network_analysis/port_scanner.py', 'args': ['Target Host', 'Port Range (e.g., 1-1000)']},
                {'name': 'IP Tracer', 'script': 'network_analysis/ip_tracer.py', 'args': ['Target Host']},
                {'name': 'Network Sniffer', 'script': 'network_analysis/network_sniffer.py', 'args': ['Packet Count']},
                {'name': 'ARP Spoof Detector', 'script': 'network_analysis/arp_spoof_detector.py', 'args': []},
                {'name': 'WiFi Scanner', 'script': 'network_analysis/wifi_scanner.py', 'args': []}
            ],
            "Vulnerability Assessment": [
                {'name': 'Header Checker', 'script': 'vulnerability_assessment/header_checker.py', 'args': ['Target URL']},
                {'name': 'Subdomain Scanner', 'script': 'vulnerability_assessment/subdomain_scanner.py', 'args': ['Domain']},
                {'name': 'Web Crawler', 'script': 'vulnerability_assessment/web_crawler.py', 'args': ['Start URL']},
                {'name': 'Password Cracker', 'script': 'vulnerability_assessment/password_cracker.py', 'args': ['Hash Type', 'Target Hash', 'Wordlist Path']}
            ],
            "Reverse Engineering": [
                {'name': 'String Extractor', 'script': 'reverse_engineering/string_extractor.py', 'args': ['File Path']},
                {'name': 'PE Analyzer', 'script': 'reverse_engineering/pe_analyzer.py', 'args': ['File Path']},
                {'name': 'XOR Cipher', 'script': 'reverse_engineering/xor_cipher.py', 'args': ['File Path', 'Key']},
                {'name': 'Disassembler', 'script': 'reverse_engineering/disassembler.py', 'args': ['File Path', 'Arch (x86/x64)', 'Count']}
            ],
            "Forensic Analysis": [
                {'name': 'Hash Calculator', 'script': 'forensic_analysis/hash_calculator_gui.py', 'args': []},
                {'name': 'EXIF Viewer', 'script': 'forensic_analysis/exif_viewer.py', 'args': ['Image Path']},
                {'name': 'File Type Identifier', 'script': 'forensic_analysis/file_type_identifier.py', 'args': ['File Path']}
            ],
            "Scripts": [
                {'name': 'Keylogger', 'script': 'scripts/keylogger.py', 'args': []},
                {'name': 'File Shredder', 'script': 'scripts/file_shredder.py', 'args': ['File Path']},
                {'name': 'System Info', 'script': 'scripts/system_info_gatherer.py', 'args': []}
            ]
        }

        self.create_tabs()

    def configure_dark_theme(self):
        self.style.configure('.', background='#2d2d2d', foreground='white')
        self.style.configure('TFrame', background='#2d2d2d')
        self.style.configure('TLabel', background='#2d2d2d', foreground='white', font=('Segoe UI', 10))
        self.style.configure('TButton', background='#4CAF50', foreground='white', font=('Segoe UI', 10, 'bold'), borderwidth=0)
        self.style.map('TButton', background=[('active', '#45a049')])
        self.style.configure('TNotebook', background='#2d2d2d', borderwidth=0)
        self.style.configure('TNotebook.Tab', background='#3c3c3c', foreground='white', padding=[10, 5])
        self.style.map('TNotebook.Tab', background=[('selected', '#4CAF50'), ('active', '#555555')])
        self.style.configure('TEntry', fieldbackground='#3c3c3c', foreground='white', borderwidth=1, insertcolor='white')

    def create_tabs(self):
        for category, tools in self.tools.items():
            tab = ttk.Frame(self.notebook, style='TFrame')
            self.notebook.add(tab, text=category)
            self.populate_tab(tab, tools)

    def populate_tab(self, tab, tools):
        for i, tool in enumerate(tools):
            frame = ttk.LabelFrame(tab, text=tool['name'], style='TFrame')
            frame.grid(row=i, column=0, padx=10, pady=10, sticky='ew')
            
            entries = {}
            for j, arg in enumerate(tool['args']):
                label = ttk.Label(frame, text=f"{arg}:")
                label.grid(row=j, column=0, padx=5, pady=5, sticky='w')
                entry = ttk.Entry(frame, width=50)
                entry.grid(row=j, column=1, padx=5, pady=5, sticky='ew')
                entries[arg] = entry

                # Add browse button for file/path arguments
                if 'path' in arg.lower() or 'file' in arg.lower():
                    browse_btn = ttk.Button(frame, text="Browse...", 
                                            command=lambda e=entry: self.browse_file(e))
                    browse_btn.grid(row=j, column=2, padx=5, pady=5)

            run_button = ttk.Button(frame, text=f"Run {tool['name']}", 
                                    command=lambda t=tool, e=entries: self.run_script(t, e))
            run_button.grid(row=len(tool['args']), column=0, columnspan=3, pady=10)

    def browse_file(self, entry_widget):
        file_path = filedialog.askopenfilename()
        if file_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, file_path)

    def run_script(self, tool, entries):
        self.output_console.delete('1.0', tk.END)
        self.output_console.insert(tk.END, f">>> Running {tool['name']}...\n\n")
        
        script_path = os.path.join(os.path.dirname(__file__), tool['script'])
        args = [entry.get() for entry in entries.values()]

        # For GUI tools, just launch them
        if tool['script'].endswith('_gui.py'):
            command = [sys.executable, script_path]
        else:
            command = [sys.executable, script_path] + args

        # Run in a separate thread to keep GUI responsive
        thread = threading.Thread(target=self.execute_command, args=(command,))
        thread.daemon = True
        thread.start()

    def execute_command(self, command):
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            for line in iter(process.stdout.readline, ''):
                self.output_console.insert(tk.END, line)
                self.output_console.see(tk.END)
                self.update_idletasks()

            for line in iter(process.stderr.readline, ''):
                self.output_console.insert(tk.END, f"ERROR: {line}")
                self.output_console.see(tk.END)
                self.update_idletasks()

        except Exception as e:
            self.output_console.insert(tk.END, f"Failed to run script: {e}\n")

if __name__ == "__main__":
    import sys
    app = ToolGUI()
    app.mainloop()

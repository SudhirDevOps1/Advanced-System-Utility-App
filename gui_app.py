import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.simpledialog as tk_simpledialog
import tkinter.colorchooser
import threading
import time
import os
import hashlib
import tempfile
import subprocess
import sys
import datetime
from pathlib import Path
import shutil
import psutil
try:
    from importlib.metadata import distribution, distributions
except ImportError:
    # Python < 3.8
    from importlib_metadata import distribution, distributions


class SystemUtilityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced System Utility App")
        self.root.geometry("900x700")
        
        # Theme management
        self.current_theme = "light"  # Default theme
        self.setup_themes()
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create notebook for tabs with custom style
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_duplicate_finder_tab()
        self.create_file_searcher_tab()
        self.create_privacy_cleaner_tab()
        self.create_package_manager_tab()
        self.create_system_cleaner_tab()
        
        # Create additional features tab
        self.create_additional_features_tab()
        
        # Create terminal tab
        self.create_terminal_tab()
        
        # Create real-time monitoring tab
        self.create_realtime_monitoring_tab()
        
        # Create security tools tab
        self.create_security_tools_tab()
        
        # Create network tools tab
        self.create_network_tools_tab()
        
        # Create developer tools tab
        self.create_dev_tools_tab()
        
        # Create system tools tab
        self.create_system_tools_tab()
        
        # Create settings/customization tab
        self.create_settings_tab()
    
    def setup_themes(self):
        # Configure styles for better appearance
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Use a theme that allows customization
        
        # Define light theme colors
        self.light_colors = {
            'bg_color': '#f0f0f0',
            'button_color': '#4a86e8',
            'button_hover_color': '#3a76d8',
            'text_bg': '#ffffff',
            'text_fg': '#000000',
            'label_fg': '#333333',
            'frame_bg': '#e0e0e0'
        }
        
        # Define dark theme colors
        self.dark_colors = {
            'bg_color': '#2d2d2d',
            'button_color': '#3a76d8',
            'button_hover_color': '#4a86e8',
            'text_bg': '#1e1e1e',
            'text_fg': '#ffffff',
            'label_fg': '#dcdcdc',
            'frame_bg': '#3d3d3d'
        }
        
        # Apply initial theme
        self.apply_theme(self.current_theme)
    
    def create_menu_bar(self):
        # Create menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Settings menu - consolidate all settings here
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Theme submenu
        theme_submenu = tk.Menu(settings_menu, tearoff=0)
        settings_menu.add_cascade(label="Theme", menu=theme_submenu)
        theme_submenu.add_command(label="Light Theme", command=lambda: self.apply_theme("light"))
        theme_submenu.add_command(label="Dark Theme", command=lambda: self.apply_theme("dark"))
        
        # Font submenu
        font_submenu = tk.Menu(settings_menu, tearoff=0)
        settings_menu.add_cascade(label="Font", menu=font_submenu)
        font_submenu.add_command(label="Change Terminal Font", command=self.change_terminal_font)
        
        # Color submenu
        color_submenu = tk.Menu(settings_menu, tearoff=0)
        settings_menu.add_cascade(label="Colors", menu=color_submenu)
        color_submenu.add_command(label="Text Color", command=self.choose_text_color)
        color_submenu.add_command(label="Background Color", command=self.choose_bg_color)
        color_submenu.add_command(label="Cursor Color", command=self.choose_cursor_color)
        
        # Window submenu
        window_submenu = tk.Menu(settings_menu, tearoff=0)
        settings_menu.add_cascade(label="Window", menu=window_submenu)
        window_submenu.add_command(label="Minimize", command=self.minimize_window)
        window_submenu.add_command(label="Maximize", command=self.maximize_window)
        window_submenu.add_command(label="Fullscreen", command=self.toggle_fullscreen)
        
        # About menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def change_terminal_font(self):
        # Placeholder for font change functionality
        try:
            from tkinter import font
            # In a real implementation, this would open a font chooser dialog
            messagebox.showinfo("Font Change", "Font change functionality would be implemented here.")
        except ImportError:
            messagebox.showinfo("Font Change", "Font selection tool would be implemented here.")
    
    def minimize_window(self):
        self.root.iconify()
    
    def maximize_window(self):
        self.root.state('zoomed')
    
    def toggle_fullscreen(self):
        current_state = self.root.attributes('-fullscreen')
        self.root.attributes('-fullscreen', not current_state)
    
    def apply_theme(self, theme_name):
        if theme_name == "dark":
            colors = self.dark_colors
            self.current_theme = "dark"
        else:
            colors = self.light_colors
            self.current_theme = "light"
        
        self.bg_color = colors['bg_color']
        self.button_color = colors['button_color']
        self.button_hover_color = colors['button_hover_color']
        self.text_bg = colors['text_bg']
        self.text_fg = colors['text_fg']
        self.label_fg = colors['label_fg']
        self.frame_bg = colors['frame_bg']
        
        # Configure custom styles
        self.style.configure('Custom.TButton', 
                            background=self.button_color,
                            foreground='white',
                            font=('Arial', 10, 'bold'))
        self.style.map('Custom.TButton',
                      background=[('active', self.button_hover_color)])
        
        # Set window background
        self.root.configure(bg=self.bg_color)
        
        # Update notebook style
        self.style.configure('TNotebook', background=self.bg_color)
        self.style.configure('TNotebook.Tab', background=self.bg_color, foreground=self.text_fg)
        self.style.map("TNotebook.Tab", background=[("selected", self.frame_bg)], 
                      foreground=[("selected", self.text_fg)])
        
        # Update all text widgets if they exist
        self.update_widget_colors()
    
    def update_widget_colors(self):
        # This method updates the colors of existing widgets
        # It will be called when changing themes
        widgets_to_update = [
            # Text widgets
            getattr(self, 'dup_result_text', None),
            getattr(self, 'search_result_text', None),
            getattr(self, 'privacy_result_text', None),
            getattr(self, 'pkg_result_text', None),
            getattr(self, 'system_result_text', None),
            getattr(self, 'additional_result_text', None),
            getattr(self, 'terminal_output', None),
            getattr(self, 'cmd_entry', None),  # Add command entry widget
            getattr(self, 'json_input_text', None),
            getattr(self, 'json_output_text', None),
            getattr(self, 'ping_result_text', None),
            getattr(self, 'port_result_text', None),
            getattr(self, 'color_codes_text', None),
            getattr(self, 'bio_text', None),
            
            # Listbox widgets
            getattr(self, 'pkg_listbox', None),
            
            # Labels that might need updating
            getattr(self, 'cpu_label', None),
            getattr(self, 'ram_label', None),
            getattr(self, 'disk_label', None),
            getattr(self, 'network_label', None),
            getattr(self, 'commands_run_label', None),
            getattr(self, 'time_spent_label', None),
            getattr(self, 'last_login_label', None),
            getattr(self, 'badges_count_label', None),
        ]
        
        for widget in widgets_to_update:
            if widget:
                try:
                    # Check if it's a Text widget or Entry widget
                    if isinstance(widget, tk.Text) or isinstance(widget, tk.Entry) or isinstance(widget, tk.Label):
                        widget.config(bg=self.text_bg, fg=self.text_fg)
                    elif hasattr(widget, 'config'):
                        widget.config(bg=self.text_bg, fg=self.text_fg)
                except tk.TclError:
                    # Some widgets might not support these attributes
                    continue
    
    def show_about(self):
        messagebox.showinfo("About", "Advanced System Utility App v2.0\nA comprehensive system utility tool with dark theme support.")
    
    def create_realtime_monitoring_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📊 Real-Time Monitoring")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Monitoring controls
        control_frame = ttk.LabelFrame(main_frame, text="Monitoring Controls", padding=10)
        control_frame.pack(fill=tk.X, pady=5)
        
        # Start/Stop buttons
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        self.monitoring_active = False
        self.monitoring_thread = None
        
        self.start_monitor_btn = ttk.Button(btn_frame, text="Start Monitoring", 
                                          command=self.start_monitoring, 
                                          style='Custom.TButton')
        self.start_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_monitor_btn = ttk.Button(btn_frame, text="Stop Monitoring", 
                                         command=self.stop_monitoring, 
                                         style='Custom.TButton', state=tk.DISABLED)
        self.stop_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        # System metrics display
        metrics_frame = ttk.LabelFrame(main_frame, text="System Metrics", padding=10)
        metrics_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create labels for metrics
        self.cpu_label = ttk.Label(metrics_frame, text="CPU Usage: 0%", font=('Arial', 10, 'bold'))
        self.cpu_label.pack(anchor=tk.W, pady=2)
        
        self.ram_label = ttk.Label(metrics_frame, text="RAM Usage: 0%", font=('Arial', 10, 'bold'))
        self.ram_label.pack(anchor=tk.W, pady=2)
        
        self.disk_label = ttk.Label(metrics_frame, text="Disk Usage: 0%", font=('Arial', 10, 'bold'))
        self.disk_label.pack(anchor=tk.W, pady=2)
        
        self.network_label = ttk.Label(metrics_frame, text="Network: 0 KB/s", font=('Arial', 10, 'bold'))
        self.network_label.pack(anchor=tk.W, pady=2)
        
        # Progress bars for visualization
        ttk.Label(metrics_frame, text="CPU Bar:").pack(anchor=tk.W, pady=(10,2))
        self.cpu_bar = ttk.Progressbar(metrics_frame, length=400, mode='determinate')
        self.cpu_bar.pack(fill=tk.X, pady=2)
        
        ttk.Label(metrics_frame, text="RAM Bar:").pack(anchor=tk.W, pady=(5,2))
        self.ram_bar = ttk.Progressbar(metrics_frame, length=400, mode='determinate')
        self.ram_bar.pack(fill=tk.X, pady=2)
        
        ttk.Label(metrics_frame, text="Disk Bar:").pack(anchor=tk.W, pady=(5,2))
        self.disk_bar = ttk.Progressbar(metrics_frame, length=400, mode='determinate')
        self.disk_bar.pack(fill=tk.X, pady=2)
    
    def start_monitoring(self):
        self.monitoring_active = True
        self.start_monitor_btn.config(state=tk.DISABLED)
        self.stop_monitor_btn.config(state=tk.NORMAL)
        
        # Start monitoring in a separate thread
        self.monitoring_thread = threading.Thread(target=self.run_monitoring)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
    
    def stop_monitoring(self):
        self.monitoring_active = False
        self.start_monitor_btn.config(state=tk.NORMAL)
        self.stop_monitor_btn.config(state=tk.DISABLED)
    
    def run_monitoring(self):
        while self.monitoring_active:
            try:
                # Get system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                ram_percent = psutil.virtual_memory().percent
                disk_percent = psutil.disk_usage('/').percent
                
                # Update GUI in the main thread
                self.root.after(0, self.update_metrics_display, cpu_percent, ram_percent, disk_percent)
                
                # Sleep for a short time to reduce CPU usage
                time.sleep(1)
            except Exception as e:
                # Log the error but continue monitoring
                print(f"Error in monitoring: {e}")
                # Small delay before continuing to avoid rapid error loops
                time.sleep(1)
                continue
    
    def update_metrics_display(self, cpu_percent, ram_percent, disk_percent):
        # Update labels
        self.cpu_label.config(text=f"CPU Usage: {cpu_percent}%")
        self.ram_label.config(text=f"RAM Usage: {ram_percent}%")
        self.disk_label.config(text=f"Disk Usage: {disk_percent}%")
        
        # Update progress bars
        self.cpu_bar['value'] = cpu_percent
        self.ram_bar['value'] = ram_percent
        self.disk_bar['value'] = disk_percent
    
    def create_security_tools_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔐 Security Tools")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Password generator section
        pwd_frame = ttk.LabelFrame(main_frame, text="🔑 Password Generator", padding=10)
        pwd_frame.pack(fill=tk.X, pady=5)
        
        pwd_input_frame = ttk.Frame(pwd_frame)
        pwd_input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(pwd_input_frame, text="Password Length:", foreground=self.label_fg).pack(side=tk.LEFT, padx=(0, 5))
        self.pwd_length_var = tk.IntVar(value=12)
        pwd_spinbox = ttk.Spinbox(pwd_input_frame, from_=4, to=50, textvariable=self.pwd_length_var, width=10)
        pwd_spinbox.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(pwd_input_frame, text="Generate Password", command=self.generate_password,
                  style='Custom.TButton').pack(side=tk.LEFT)
        
        self.generated_pwd_var = tk.StringVar()
        pwd_result_frame = ttk.Frame(pwd_frame)
        pwd_result_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(pwd_result_frame, text="Generated Password:", foreground=self.label_fg).pack(anchor=tk.W)
        pwd_entry = ttk.Entry(pwd_result_frame, textvariable=self.generated_pwd_var, width=50)
        pwd_entry.pack(fill=tk.X, pady=2)
        
        # Hash calculator section
        hash_frame = ttk.LabelFrame(main_frame, text="🔢 Hash Calculator", padding=10)
        hash_frame.pack(fill=tk.X, pady=5)
        
        hash_input_frame = ttk.Frame(hash_frame)
        hash_input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(hash_input_frame, text="Input Text:", foreground=self.label_fg).pack(anchor=tk.W)
        self.hash_input_var = tk.StringVar()
        hash_entry = ttk.Entry(hash_input_frame, textvariable=self.hash_input_var, width=50)
        hash_entry.pack(fill=tk.X, pady=2)
        
        hash_btn_frame = ttk.Frame(hash_frame)
        hash_btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(hash_btn_frame, text="MD5", command=lambda: self.calculate_hash('md5'),
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(hash_btn_frame, text="SHA256", command=lambda: self.calculate_hash('sha256'),
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(hash_btn_frame, text="SHA1", command=lambda: self.calculate_hash('sha1'),
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        
        self.hash_result_var = tk.StringVar()
        hash_result_frame = ttk.Frame(hash_frame)
        hash_result_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(hash_result_frame, text="Hash Result:", foreground=self.label_fg).pack(anchor=tk.W)
        hash_result_entry = ttk.Entry(hash_result_frame, textvariable=self.hash_result_var, width=70)
        hash_result_entry.pack(fill=tk.X, pady=2)
    
    def generate_password(self):
        import secrets
        import string
        
        length = self.pwd_length_var.get()
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(chars) for _ in range(length))
        self.generated_pwd_var.set(password)
    
    def calculate_hash(self, algorithm):
        import hashlib
        
        input_text = self.hash_input_var.get()
        if not input_text:
            messagebox.showwarning("Warning", "Please enter text to hash.")
            return
        
        if algorithm == 'md5':
            hash_obj = hashlib.md5(input_text.encode())
        elif algorithm == 'sha256':
            hash_obj = hashlib.sha256(input_text.encode())
        elif algorithm == 'sha1':
            hash_obj = hashlib.sha1(input_text.encode())
        else:
            messagebox.showerror("Error", "Unsupported algorithm")
            return
        
        self.hash_result_var.set(hash_obj.hexdigest())
    
    def create_network_tools_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🌐 Network Tools")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Ping tool section
        ping_frame = ttk.LabelFrame(main_frame, text="📡 Ping Tool", padding=10)
        ping_frame.pack(fill=tk.X, pady=5)
        
        ping_input_frame = ttk.Frame(ping_frame)
        ping_input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(ping_input_frame, text="Host/IP:", foreground=self.label_fg).pack(side=tk.LEFT, padx=(0, 5))
        self.ping_host_var = tk.StringVar(value="google.com")
        ping_entry = ttk.Entry(ping_input_frame, textvariable=self.ping_host_var, width=30)
        ping_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(ping_input_frame, text="Ping", command=self.run_ping,
                  style='Custom.TButton').pack(side=tk.RIGHT)
        
        # Results area for ping
        self.ping_result_text = tk.Text(ping_frame, height=8, bg=self.text_bg, fg=self.text_fg)
        ping_scrollbar = ttk.Scrollbar(ping_frame, orient=tk.VERTICAL, command=self.ping_result_text.yview)
        self.ping_result_text.configure(yscrollcommand=ping_scrollbar.set)
        
        ping_result_frame = ttk.Frame(ping_frame)
        ping_result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.ping_result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ping_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Port scanner section
        port_frame = ttk.LabelFrame(main_frame, text="🔒 Port Scanner", padding=10)
        port_frame.pack(fill=tk.X, pady=5)
        
        port_input_frame = ttk.Frame(port_frame)
        port_input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(port_input_frame, text="Target IP:", foreground=self.label_fg).pack(side=tk.LEFT, padx=(0, 5))
        self.port_target_var = tk.StringVar(value="127.0.0.1")
        port_target_entry = ttk.Entry(port_input_frame, textvariable=self.port_target_var, width=20)
        port_target_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Label(port_input_frame, text="Ports (e.g., 20-80):", foreground=self.label_fg).pack(side=tk.LEFT, padx=(0, 5))
        self.port_range_var = tk.StringVar(value="1-1000")
        port_range_entry = ttk.Entry(port_input_frame, textvariable=self.port_range_var, width=15)
        port_range_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(port_input_frame, text="Scan Ports", command=self.scan_ports,
                  style='Custom.TButton').pack(side=tk.RIGHT)
        
        # Results area for port scanning
        self.port_result_text = tk.Text(port_frame, height=8, bg=self.text_bg, fg=self.text_fg)
        port_scrollbar = ttk.Scrollbar(port_frame, orient=tk.VERTICAL, command=self.port_result_text.yview)
        self.port_result_text.configure(yscrollcommand=port_scrollbar.set)
        
        port_result_frame = ttk.Frame(port_frame)
        port_result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.port_result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        port_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def run_ping(self):
        import subprocess
        import platform
        
        host = self.ping_host_var.get()
        if not host:
            messagebox.showwarning("Warning", "Please enter a host to ping.")
            return
        
        self.ping_result_text.delete(1.0, tk.END)
        self.ping_result_text.insert(tk.END, f"Pinging {host}...\n")
        
        try:
            # Use appropriate ping command based on OS
            param = "-n" if platform.system().lower()=="windows" else "-c"
            result = subprocess.run(["ping", param, "4", host], 
                                  capture_output=True, text=True)
            
            self.ping_result_text.insert(tk.END, result.stdout)
            if result.stderr:
                self.ping_result_text.insert(tk.END, f"\nError: {result.stderr}")
        except Exception as e:
            self.ping_result_text.insert(tk.END, f"\nError: {str(e)}")
    
    def scan_ports(self):
        import socket
        import threading
        
        target = self.port_target_var.get()
        port_range = self.port_range_var.get()
        
        if not target or not port_range:
            messagebox.showwarning("Warning", "Please enter both target and port range.")
            return
        
        try:
            # Parse port range
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
            else:
                start_port = end_port = int(port_range)
        except ValueError:
            messagebox.showerror("Error", "Invalid port range format. Use format like '1-1000'.")
            return
        
        self.port_result_text.delete(1.0, tk.END)
        self.port_result_text.insert(tk.END, f"Scanning ports {start_port}-{end_port} on {target}...\n")
        
        # Run port scan in a separate thread to prevent UI freeze
        scan_thread = threading.Thread(target=self.perform_port_scan, 
                                     args=(target, start_port, end_port))
        scan_thread.daemon = True
        scan_thread.start()
    
    def perform_port_scan(self, target, start_port, end_port):
        import socket
        
        open_ports = []
        
        for port in range(start_port, end_port + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # 1 second timeout
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass  # Continue to next port
        
        # Update UI in main thread
        self.root.after(0, self.display_port_results, open_ports)
    
    def display_port_results(self, open_ports):
        self.port_result_text.insert(tk.END, f"\nOpen ports found: {len(open_ports)}\n")
        if open_ports:
            for port in open_ports:
                self.port_result_text.insert(tk.END, f"Port {port} is open\n")
        else:
            self.port_result_text.insert(tk.END, "No open ports found in the specified range.\n")
    
    def create_dev_tools_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📝 Developer Tools")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Base64 encoder/decoder section
        base64_frame = ttk.LabelFrame(main_frame, text="🔄 Base64 Encoder/Decoder", padding=10)
        base64_frame.pack(fill=tk.X, pady=5)
        
        # Input section
        input_frame = ttk.Frame(base64_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="Input:", foreground=self.label_fg).pack(anchor=tk.W)
        self.base64_input_var = tk.StringVar()
        input_entry = ttk.Entry(input_frame, textvariable=self.base64_input_var, width=60)
        input_entry.pack(fill=tk.X, pady=2)
        
        # Buttons
        btn_frame = ttk.Frame(base64_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Encode to Base64", command=self.encode_base64,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Decode from Base64", command=self.decode_base64,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        
        # Result section
        result_frame = ttk.Frame(base64_frame)
        result_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(result_frame, text="Result:", foreground=self.label_fg).pack(anchor=tk.W)
        self.base64_result_var = tk.StringVar()
        result_entry = ttk.Entry(result_frame, textvariable=self.base64_result_var, width=60)
        result_entry.pack(fill=tk.X, pady=2)
        
        # JSON viewer section
        json_frame = ttk.LabelFrame(main_frame, text="📄 JSON Viewer", padding=10)
        json_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # JSON input
        json_input_frame = ttk.Frame(json_frame)
        json_input_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(json_input_frame, text="JSON Input:", foreground=self.label_fg).pack(anchor=tk.W)
        
        self.json_input_text = tk.Text(json_input_frame, height=8, bg=self.text_bg, fg=self.text_fg)
        json_input_scrollbar = ttk.Scrollbar(json_input_frame, orient=tk.VERTICAL, 
                                           command=self.json_input_text.yview)
        self.json_input_text.configure(yscrollcommand=json_input_scrollbar.set)
        
        json_input_text_frame = ttk.Frame(json_input_frame)
        json_input_text_frame.pack(fill=tk.BOTH, expand=True)
        self.json_input_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        json_input_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # JSON output
        json_output_frame = ttk.Frame(json_frame)
        json_output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(json_output_frame, text="Formatted JSON:", foreground=self.label_fg).pack(anchor=tk.W)
        
        self.json_output_text = tk.Text(json_output_frame, height=8, bg=self.text_bg, fg=self.text_fg)
        json_output_scrollbar = ttk.Scrollbar(json_output_frame, orient=tk.VERTICAL, 
                                            command=self.json_output_text.yview)
        self.json_output_text.configure(yscrollcommand=json_output_scrollbar.set)
        
        json_output_text_frame = ttk.Frame(json_output_frame)
        json_output_text_frame.pack(fill=tk.BOTH, expand=True)
        self.json_output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        json_output_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Format button
        format_btn_frame = ttk.Frame(json_frame)
        format_btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(format_btn_frame, text="Format JSON", command=self.format_json,
                  style='Custom.TButton').pack(side=tk.LEFT)
        ttk.Button(format_btn_frame, text="Clear", command=self.clear_json_fields,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
    
    def encode_base64(self):
        import base64
        
        input_text = self.base64_input_var.get()
        if not input_text:
            messagebox.showwarning("Warning", "Please enter text to encode.")
            return
        
        try:
            encoded_bytes = base64.b64encode(input_text.encode('utf-8'))
            encoded_str = encoded_bytes.decode('utf-8')
            self.base64_result_var.set(encoded_str)
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {str(e)}")
    
    def decode_base64(self):
        import base64
        
        input_text = self.base64_input_var.get()
        if not input_text:
            messagebox.showwarning("Warning", "Please enter Base64 text to decode.")
            return
        
        try:
            decoded_bytes = base64.b64decode(input_text.encode('utf-8'))
            decoded_str = decoded_bytes.decode('utf-8')
            self.base64_result_var.set(decoded_str)
        except Exception as e:
            messagebox.showerror("Error", f"Decoding failed: {str(e)}")
    
    def format_json(self):
        import json
        
        json_text = self.json_input_text.get(1.0, tk.END).strip()
        if not json_text:
            messagebox.showwarning("Warning", "Please enter JSON to format.")
            return
        
        try:
            parsed_json = json.loads(json_text)
            formatted_json = json.dumps(parsed_json, indent=2, ensure_ascii=False)
            self.json_output_text.delete(1.0, tk.END)
            self.json_output_text.insert(1.0, formatted_json)
        except json.JSONDecodeError as e:
            messagebox.showerror("Error", f"Invalid JSON: {str(e)}")
    
    def clear_json_fields(self):
        self.json_input_text.delete(1.0, tk.END)
        self.json_output_text.delete(1.0, tk.END)
    
    def create_system_tools_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🎛️ System Tools")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # System info section
        info_frame = ttk.LabelFrame(main_frame, text="📋 System Information", padding=10)
        info_frame.pack(fill=tk.X, pady=5)
        
        btn_info_frame = ttk.Frame(info_frame)
        btn_info_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_info_frame, text="Get System Info", command=self.get_system_info,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_info_frame, text="Get Hardware Info", command=self.get_hardware_info,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_info_frame, text="Get Network Info", command=self.get_network_info,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        
        # Results area for system info
        self.sysinfo_result_text = tk.Text(info_frame, height=10, bg=self.text_bg, fg=self.text_fg)
        sysinfo_scrollbar = ttk.Scrollbar(info_frame, orient=tk.VERTICAL, 
                                        command=self.sysinfo_result_text.yview)
        self.sysinfo_result_text.configure(yscrollcommand=sysinfo_scrollbar.set)
        
        sysinfo_result_frame = ttk.Frame(info_frame)
        sysinfo_result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.sysinfo_result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sysinfo_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Process manager section
        proc_frame = ttk.LabelFrame(main_frame, text="⚙️ Process Manager", padding=10)
        proc_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        proc_btn_frame = ttk.Frame(proc_frame)
        proc_btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(proc_btn_frame, text="Refresh Processes", command=self.refresh_processes,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(proc_btn_frame, text="Kill Selected Process", command=self.kill_selected_process,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        
        # Process list
        self.process_tree = ttk.Treeview(proc_frame, columns=("PID", "Name", "Status", "CPU%", "Memory"), 
                                       show="headings", height=10)
        
        # Define headings
        self.process_tree.heading("PID", text="PID")
        self.process_tree.heading("Name", text="Name")
        self.process_tree.heading("Status", text="Status")
        self.process_tree.heading("CPU%", text="CPU%")
        self.process_tree.heading("Memory", text="Memory (MB)")
        
        # Define column widths
        self.process_tree.column("PID", width=80)
        self.process_tree.column("Name", width=200)
        self.process_tree.column("Status", width=100)
        self.process_tree.column("CPU%", width=80)
        self.process_tree.column("Memory", width=100)
        
        # Add scrollbar
        proc_scrollbar = ttk.Scrollbar(proc_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=proc_scrollbar.set)
        
        proc_tree_frame = ttk.Frame(proc_frame)
        proc_tree_frame.pack(fill=tk.BOTH, expand=True)
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        proc_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load initial processes
        self.refresh_processes()
    
    def get_system_info(self):
        import platform
        
        self.sysinfo_result_text.delete(1.0, tk.END)
        self.sysinfo_result_text.insert(tk.END, "=== SYSTEM INFORMATION ===\n\n")
        
        # Basic system info
        self.sysinfo_result_text.insert(tk.END, f"System: {platform.system()}\n")
        self.sysinfo_result_text.insert(tk.END, f"Node Name: {platform.node()}\n")
        self.sysinfo_result_text.insert(tk.END, f"Release: {platform.release()}\n")
        self.sysinfo_result_text.insert(tk.END, f"Version: {platform.version()}\n")
        self.sysinfo_result_text.insert(tk.END, f"Machine: {platform.machine()}\n")
        self.sysinfo_result_text.insert(tk.END, f"Processor: {platform.processor()}\n")
        self.sysinfo_result_text.insert(tk.END, f"Architecture: {platform.architecture()[0]}\n\n")
        
        # Additional system info
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        self.sysinfo_result_text.insert(tk.END, f"Boot Time: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    def get_hardware_info(self):
        self.sysinfo_result_text.delete(1.0, tk.END)
        self.sysinfo_result_text.insert(tk.END, "=== HARDWARE INFORMATION ===\n\n")
        
        # CPU info
        self.sysinfo_result_text.insert(tk.END, f"CPU Cores (Logical): {psutil.cpu_count(logical=True)}\n")
        self.sysinfo_result_text.insert(tk.END, f"CPU Cores (Physical): {psutil.cpu_count(logical=False)}\n")
        self.sysinfo_result_text.insert(tk.END, f"CPU Frequency: {psutil.cpu_freq().current:.2f} MHz\n\n")
        
        # Memory info
        virtual_mem = psutil.virtual_memory()
        self.sysinfo_result_text.insert(tk.END, f"Total RAM: {virtual_mem.total / (1024**3):.2f} GB\n")
        self.sysinfo_result_text.insert(tk.END, f"Available RAM: {virtual_mem.available / (1024**3):.2f} GB\n")
        self.sysinfo_result_text.insert(tk.END, f"Used RAM: {virtual_mem.used / (1024**3):.2f} GB\n")
        self.sysinfo_result_text.insert(tk.END, f"RAM Percentage: {virtual_mem.percent}%\n\n")
        
        # Disk info
        disk_usage = psutil.disk_usage('/')
        self.sysinfo_result_text.insert(tk.END, f"Total Disk Space: {disk_usage.total / (1024**3):.2f} GB\n")
        self.sysinfo_result_text.insert(tk.END, f"Used Disk Space: {disk_usage.used / (1024**3):.2f} GB\n")
        self.sysinfo_result_text.insert(tk.END, f"Free Disk Space: {disk_usage.free / (1024**3):.2f} GB\n")
        self.sysinfo_result_text.insert(tk.END, f"Disk Usage: {disk_usage.percent}%\n\n")
    
    def get_network_info(self):
        self.sysinfo_result_text.delete(1.0, tk.END)
        self.sysinfo_result_text.insert(tk.END, "=== NETWORK INFORMATION ===\n\n")
        
        # Get network interfaces
        net_if_addrs = psutil.net_if_addrs()
        for interface, addresses in net_if_addrs.items():
            self.sysinfo_result_text.insert(tk.END, f"Interface: {interface}\n")
            for addr in addresses:
                if addr.family == 2:  # IPv4
                    self.sysinfo_result_text.insert(tk.END, f"  IPv4 Address: {addr.address}\n")
                    self.sysinfo_result_text.insert(tk.END, f"  Netmask: {addr.netmask}\n")
                elif addr.family == 10:  # IPv6
                    self.sysinfo_result_text.insert(tk.END, f"  IPv6 Address: {addr.address}\n")
            self.sysinfo_result_text.insert(tk.END, "\n")
    
    def refresh_processes(self):
        # Clear the treeview
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # Get process information
        for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_info']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                status = proc.info['status']
                cpu_percent = proc.info['cpu_percent']
                memory_mb = proc.info['memory_info'].rss / (1024 * 1024)  # Convert to MB
                
                self.process_tree.insert("", tk.END, values=(pid, name, status, cpu_percent, f"{memory_mb:.1f}"))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Process might have ended or we don't have permission
                continue
    
    def kill_selected_process(self):
        selected_item = self.process_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a process to kill.")
            return
        
        item = self.process_tree.item(selected_item)
        pid = item['values'][0]  # Get PID from the first column
        
        if messagebox.askyesno("Confirm", f"Are you sure you want to terminate process {pid}?"):
            try:
                process = psutil.Process(pid)
                process.terminate()
                messagebox.showinfo("Success", f"Process {pid} terminated successfully.")
                self.refresh_processes()  # Refresh the process list
            except psutil.NoSuchProcess:
                messagebox.showerror("Error", f"Process {pid} no longer exists.")
            except psutil.AccessDenied:
                messagebox.showerror("Error", f"Access denied to terminate process {pid}.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not terminate process {pid}: {str(e)}")
    
    def create_settings_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🎨 Settings & Customization")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for sub-tabs within settings
        settings_notebook = ttk.Notebook(main_frame)
        settings_notebook.pack(fill=tk.BOTH, expand=True)
        
        # User Profile Tab
        self.create_user_profile_tab(settings_notebook)
        
        # Terminal Customization Tab
        self.create_terminal_customization_tab(settings_notebook)
        
        # Color Tools Tab
        self.create_color_tools_tab(settings_notebook)
    
    def create_user_profile_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="👤 User Profile")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Profile info section
        profile_frame = ttk.LabelFrame(main_frame, text="Profile Information", padding=10)
        profile_frame.pack(fill=tk.X, pady=5)
        
        # Display name
        ttk.Label(profile_frame, text="Display Name:", foreground=self.label_fg).pack(anchor=tk.W)
        self.display_name_var = tk.StringVar(value="Sudhir Kumar")
        ttk.Entry(profile_frame, textvariable=self.display_name_var, width=30).pack(fill=tk.X, pady=2)
        
        # Username
        ttk.Label(profile_frame, text="Username:", foreground=self.label_fg).pack(anchor=tk.W, pady=(5,0))
        self.username_var = tk.StringVar(value="SudhirDevOps1")
        ttk.Entry(profile_frame, textvariable=self.username_var, width=30).pack(fill=tk.X, pady=2)
        
        # Bio/description
        ttk.Label(profile_frame, text="Bio/Description:", foreground=self.label_fg).pack(anchor=tk.W, pady=(5,0))
        self.bio_text = tk.Text(profile_frame, height=4, bg=self.text_bg, fg=self.text_fg)
        self.bio_text.pack(fill=tk.X, pady=2)
        self.bio_text.insert(tk.END, "System Administrator & Developer")
        
        # Social links
        social_frame = ttk.LabelFrame(main_frame, text="Social Links", padding=10)
        social_frame.pack(fill=tk.X, pady=5)
        
        # GitHub
        github_frame = ttk.Frame(social_frame)
        github_frame.pack(fill=tk.X, pady=2)
        ttk.Label(github_frame, text="GitHub:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.github_var = tk.StringVar()
        ttk.Entry(github_frame, textvariable=self.github_var, width=40).pack(side=tk.LEFT, padx=(5, 0))
        
        # LinkedIn
        linkedin_frame = ttk.Frame(social_frame)
        linkedin_frame.pack(fill=tk.X, pady=2)
        ttk.Label(linkedin_frame, text="LinkedIn:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.linkedin_var = tk.StringVar()
        ttk.Entry(linkedin_frame, textvariable=self.linkedin_var, width=40).pack(side=tk.LEFT, padx=(5, 0))
        
        # Twitter
        twitter_frame = ttk.Frame(social_frame)
        twitter_frame.pack(fill=tk.X, pady=2)
        ttk.Label(twitter_frame, text="Twitter:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.twitter_var = tk.StringVar()
        ttk.Entry(twitter_frame, textvariable=self.twitter_var, width=40).pack(side=tk.LEFT, padx=(5, 0))
        
        # Profile avatar section
        avatar_frame = ttk.LabelFrame(main_frame, text="Profile Avatar", padding=10)
        avatar_frame.pack(fill=tk.X, pady=5)
        
        self.avatar_path_var = tk.StringVar()
        avatar_info_frame = ttk.Frame(avatar_frame)
        avatar_info_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(avatar_info_frame, text="Avatar Path:", foreground=self.label_fg).pack(anchor=tk.W)
        avatar_path_entry = ttk.Entry(avatar_info_frame, textvariable=self.avatar_path_var, width=40)
        avatar_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(avatar_info_frame, text="Browse", command=self.browse_avatar,
                  style='Custom.TButton').pack(side=tk.RIGHT)
        
        # Stats section
        stats_frame = ttk.LabelFrame(main_frame, text="User Statistics", padding=10)
        stats_frame.pack(fill=tk.X, pady=5)
        
        stats_row1 = ttk.Frame(stats_frame)
        stats_row1.pack(fill=tk.X, pady=2)
        
        self.commands_run_var = tk.IntVar(value=0)
        ttk.Label(stats_row1, text="Commands Run:").pack(side=tk.LEFT)
        self.commands_run_label = ttk.Label(stats_row1, textvariable=self.commands_run_var)
        self.commands_run_label.pack(side=tk.LEFT, padx=(5, 20))
        
        self.time_spent_var = tk.StringVar(value="0h 0m")
        ttk.Label(stats_row1, text="Time Spent:").pack(side=tk.LEFT)
        self.time_spent_label = ttk.Label(stats_row1, textvariable=self.time_spent_var)
        self.time_spent_label.pack(side=tk.LEFT, padx=(5, 20))
        
        # Additional stats row
        stats_row2 = ttk.Frame(stats_frame)
        stats_row2.pack(fill=tk.X, pady=2)
        
        self.last_login_var = tk.StringVar(value="Never")
        ttk.Label(stats_row2, text="Last Login:").pack(side=tk.LEFT)
        self.last_login_label = ttk.Label(stats_row2, textvariable=self.last_login_var)
        self.last_login_label.pack(side=tk.LEFT, padx=(5, 20))
        
        self.badges_count_var = tk.IntVar(value=0)
        ttk.Label(stats_row2, text="Achievement Badges:").pack(side=tk.LEFT)
        self.badges_count_label = ttk.Label(stats_row2, textvariable=self.badges_count_var)
        self.badges_count_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # Login/Logout section
        login_frame = ttk.Frame(main_frame)
        login_frame.pack(fill=tk.X, pady=5)
        
        self.logged_in_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(login_frame, text="Logged In", variable=self.logged_in_var).pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Button(login_frame, text="Login", command=self.login_user,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(login_frame, text="Logout", command=self.logout_user,
                  style='Custom.TButton').pack(side=tk.LEFT)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Save Profile", command=self.save_profile,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Load Profile", command=self.load_profile,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Export Profile Card", command=self.export_profile_card,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Reset Profile", command=self.reset_profile,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
    
    def login_user(self):
        self.logged_in_var.set(True)
        # Update last login time
        import datetime
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_login_var.set(current_time)
        messagebox.showinfo("Login", "User logged in successfully!")
    
    def logout_user(self):
        self.logged_in_var.set(False)
        messagebox.showinfo("Logout", "User logged out successfully!")
    
    def export_profile_card(self):
        # This would export a profile card in a real application
        messagebox.showinfo("Export", "Profile card exported successfully!")
    
    def create_terminal_customization_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="🖥️ Terminal Customization")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for terminal customization sub-tabs
        term_notebook = ttk.Notebook(main_frame)
        term_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Font settings tab
        self.create_font_settings_tab(term_notebook)
        
        # Color settings tab
        self.create_color_settings_tab(term_notebook)
        
        # Background options tab
        self.create_background_options_tab(term_notebook)
        
        # Effects and animations tab
        self.create_effects_animations_tab(term_notebook)
        
        # Layout settings tab
        self.create_layout_settings_tab(term_notebook)
    
    def create_font_settings_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="🖋️ Font Settings")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Font family and size
        font_frame = ttk.LabelFrame(main_frame, text="Font Family & Size", padding=10)
        font_frame.pack(fill=tk.X, pady=5)
        
        font_row1 = ttk.Frame(font_frame)
        font_row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(font_row1, text="Font Family:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.font_family_var = tk.StringVar(value="Consolas")
        font_families = ["Consolas", "Courier New", "Monaco", "Lucida Console", "Andale Mono", "Source Code Pro", "Fira Code", "JetBrains Mono", "Ubuntu Mono", "Cascadia Code"]
        font_combo = ttk.Combobox(font_row1, textvariable=self.font_family_var, values=font_families, state="readonly", width=20)
        font_combo.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(font_row1, text="Font Size:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.font_size_var = tk.IntVar(value=10)
        font_size_spinbox = ttk.Spinbox(font_row1, from_=8, to=32, textvariable=self.font_size_var, width=5)
        font_size_spinbox.pack(side=tk.LEFT, padx=(5, 10))
        
        # Font weight and style
        style_frame = ttk.LabelFrame(main_frame, text="Font Weight & Style", padding=10)
        style_frame.pack(fill=tk.X, pady=5)
        
        style_row1 = ttk.Frame(style_frame)
        style_row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(style_row1, text="Font Weight:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.font_weight_var = tk.StringVar(value="normal")
        weight_options = ["normal", "bold", "light"]
        weight_combo = ttk.Combobox(style_row1, textvariable=self.font_weight_var, values=weight_options, state="readonly", width=10)
        weight_combo.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(style_row1, text="Font Style:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.font_style_var = tk.StringVar(value="normal")
        style_options = ["normal", "italic", "roman"]
        style_combo = ttk.Combobox(style_row1, textvariable=self.font_style_var, values=style_options, state="readonly", width=10)
        style_combo.pack(side=tk.LEFT, padx=(5, 10))
        
        # Spacing settings
        spacing_frame = ttk.LabelFrame(main_frame, text="Spacing", padding=10)
        spacing_frame.pack(fill=tk.X, pady=5)
        
        spacing_row1 = ttk.Frame(spacing_frame)
        spacing_row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(spacing_row1, text="Letter Spacing:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.letter_spacing_var = tk.DoubleVar(value=0.0)
        letter_spacing_scale = ttk.Scale(spacing_row1, from_=-2.0, to=5.0, variable=self.letter_spacing_var, length=200)
        letter_spacing_scale.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(spacing_row1, textvariable=self.letter_spacing_var, width=5).pack(side=tk.LEFT)
        
        spacing_row2 = ttk.Frame(spacing_frame)
        spacing_row2.pack(fill=tk.X, pady=2)
        
        ttk.Label(spacing_row2, text="Line Height:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.line_height_var = tk.DoubleVar(value=1.0)
        line_height_scale = ttk.Scale(spacing_row2, from_=0.5, to=2.0, variable=self.line_height_var, length=200)
        line_height_scale.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(spacing_row2, textvariable=self.line_height_var, width=5).pack(side=tk.LEFT)
        
        # Apply settings button
        ttk.Button(main_frame, text="Apply Font Settings", command=self.apply_font_settings,
                  style='Custom.TButton').pack(pady=10)
    
    def create_color_settings_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="🎨 Color Settings")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Primary colors
        primary_frame = ttk.LabelFrame(main_frame, text="Primary Colors", padding=10)
        primary_frame.pack(fill=tk.X, pady=5)
        
        primary_row1 = ttk.Frame(primary_frame)
        primary_row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(primary_row1, text="Text Color:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.text_color_var = tk.StringVar(value="#FFFFFF")
        text_color_btn = ttk.Button(primary_row1, text="Choose", command=self.choose_text_color,
                                  style='Custom.TButton')
        text_color_btn.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(primary_row1, text="Background:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.bg_color_var = tk.StringVar(value="#000000")
        bg_color_btn = ttk.Button(primary_row1, text="Choose", command=self.choose_bg_color,
                                style='Custom.TButton')
        bg_color_btn.pack(side=tk.LEFT, padx=(5, 10))
        
        # Additional colors
        additional_frame = ttk.LabelFrame(main_frame, text="Additional Colors", padding=10)
        additional_frame.pack(fill=tk.X, pady=5)
        
        # Cursor color
        cursor_row = ttk.Frame(additional_frame)
        cursor_row.pack(fill=tk.X, pady=2)
        
        ttk.Label(cursor_row, text="Cursor Color:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.cursor_color_var = tk.StringVar(value="#FFFFFF")
        cursor_color_btn = ttk.Button(cursor_row, text="Choose", command=self.choose_cursor_color,
                                    style='Custom.TButton')
        cursor_color_btn.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(cursor_row, text="Selection Color:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.selection_color_var = tk.StringVar(value="#3399FF")
        sel_color_btn = ttk.Button(cursor_row, text="Choose", command=self.choose_selection_color,
                                 style='Custom.TButton')
        sel_color_btn.pack(side=tk.LEFT, padx=(5, 10))
        
        # Status colors
        status_frame = ttk.LabelFrame(main_frame, text="Status Colors", padding=10)
        status_frame.pack(fill=tk.X, pady=5)
        
        # Error color
        error_row = ttk.Frame(status_frame)
        error_row.pack(fill=tk.X, pady=2)
        
        ttk.Label(error_row, text="Error Color:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.error_color_var = tk.StringVar(value="#FF5555")
        error_color_btn = ttk.Button(error_row, text="Choose", command=self.choose_error_color,
                                   style='Custom.TButton')
        error_color_btn.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(error_row, text="Success Color:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.success_color_var = tk.StringVar(value="#55AA55")
        success_color_btn = ttk.Button(error_row, text="Choose", command=self.choose_success_color,
                                     style='Custom.TButton')
        success_color_btn.pack(side=tk.LEFT, padx=(5, 10))
        
        # Warning and info colors
        warn_row = ttk.Frame(status_frame)
        warn_row.pack(fill=tk.X, pady=2)
        
        ttk.Label(warn_row, text="Warning Color:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.warning_color_var = tk.StringVar(value="#FFCC00")
        warning_color_btn = ttk.Button(warn_row, text="Choose", command=self.choose_warning_color,
                                     style='Custom.TButton')
        warning_color_btn.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(warn_row, text="Info Color:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.info_color_var = tk.StringVar(value="#3399FF")
        info_color_btn = ttk.Button(warn_row, text="Choose", command=self.choose_info_color,
                                  style='Custom.TButton')
        info_color_btn.pack(side=tk.LEFT, padx=(5, 10))
        
        # Apply settings button
        ttk.Button(main_frame, text="Apply Color Settings", command=self.apply_color_settings,
                  style='Custom.TButton').pack(pady=10)
    
    def create_background_options_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="🖼️ Background Options")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Background type selection
        type_frame = ttk.LabelFrame(main_frame, text="Background Type", padding=10)
        type_frame.pack(fill=tk.X, pady=5)
        
        self.bg_type_var = tk.StringVar(value="solid")
        bg_types = [("Solid Color", "solid"), ("Gradient", "gradient"), ("Image", "image")]
        
        for text, value in bg_types:
            ttk.Radiobutton(type_frame, text=text, variable=self.bg_type_var, value=value).pack(side=tk.LEFT, padx=5)
        
        # Solid color options
        solid_frame = ttk.LabelFrame(main_frame, text="Solid Color", padding=10)
        solid_frame.pack(fill=tk.X, pady=5)
        
        solid_row = ttk.Frame(solid_frame)
        solid_row.pack(fill=tk.X, pady=2)
        
        ttk.Label(solid_row, text="Background Color:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.solid_bg_color_var = tk.StringVar(value="#000000")
        solid_bg_btn = ttk.Button(solid_row, text="Choose", command=self.choose_solid_bg_color,
                                style='Custom.TButton')
        solid_bg_btn.pack(side=tk.LEFT, padx=(5, 10))
        
        # Gradient options
        gradient_frame = ttk.LabelFrame(main_frame, text="Gradient", padding=10)
        gradient_frame.pack(fill=tk.X, pady=5)
        
        grad_row1 = ttk.Frame(gradient_frame)
        grad_row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(grad_row1, text="Gradient Type:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.gradient_type_var = tk.StringVar(value="linear")
        grad_types = ["linear", "radial", "conic"]
        grad_combo = ttk.Combobox(grad_row1, textvariable=self.gradient_type_var, values=grad_types, state="readonly", width=10)
        grad_combo.pack(side=tk.LEFT, padx=(5, 10))
        
        grad_row2 = ttk.Frame(gradient_frame)
        grad_row2.pack(fill=tk.X, pady=2)
        
        ttk.Label(grad_row2, text="Start Color:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.grad_start_color_var = tk.StringVar(value="#000000")
        grad_start_btn = ttk.Button(grad_row2, text="Choose", command=self.choose_grad_start_color,
                                  style='Custom.TButton')
        grad_start_btn.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(grad_row2, text="End Color:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.grad_end_color_var = tk.StringVar(value="#333333")
        grad_end_btn = ttk.Button(grad_row2, text="Choose", command=self.choose_grad_end_color,
                                style='Custom.TButton')
        grad_end_btn.pack(side=tk.LEFT, padx=(5, 10))
        
        # Image options
        image_frame = ttk.LabelFrame(main_frame, text="Background Image", padding=10)
        image_frame.pack(fill=tk.X, pady=5)
        
        img_row1 = ttk.Frame(image_frame)
        img_row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(img_row1, text="Image Path:", foreground=self.label_fg).pack(anchor=tk.W)
        self.bg_image_path_var = tk.StringVar()
        img_path_entry = ttk.Entry(img_row1, textvariable=self.bg_image_path_var, width=40)
        img_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(img_row1, text="Browse", command=self.browse_bg_image,
                  style='Custom.TButton').pack(side=tk.RIGHT)
        
        # Apply settings button
        ttk.Button(main_frame, text="Apply Background Settings", command=self.apply_bg_settings,
                  style='Custom.TButton').pack(pady=10)
    
    def create_effects_animations_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="✨ Effects & Animations")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Effects settings
        effects_frame = ttk.LabelFrame(main_frame, text="Effects", padding=10)
        effects_frame.pack(fill=tk.X, pady=5)
        
        # Cursor blink speed
        cursor_row = ttk.Frame(effects_frame)
        cursor_row.pack(fill=tk.X, pady=2)
        
        ttk.Label(cursor_row, text="Cursor Blink Speed:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.cursor_blink_var = tk.DoubleVar(value=500)
        cursor_blink_scale = ttk.Scale(cursor_row, from_=100, to=2000, variable=self.cursor_blink_var, length=200)
        cursor_blink_scale.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(cursor_row, textvariable=self.cursor_blink_var, width=6).pack(side=tk.LEFT)
        
        # Cursor style
        cursor_style_row = ttk.Frame(effects_frame)
        cursor_style_row.pack(fill=tk.X, pady=2)
        
        ttk.Label(cursor_style_row, text="Cursor Style:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.cursor_style_var = tk.StringVar(value="block")
        cursor_styles = [("Block", "block"), ("Line", "line"), ("Underline", "underline")]
        
        for text, value in cursor_styles:
            ttk.Radiobutton(cursor_style_row, text=text, variable=self.cursor_style_var, value=value).pack(side=tk.LEFT, padx=5)
        
        # Text effects
        text_effects_frame = ttk.LabelFrame(main_frame, text="Text Effects", padding=10)
        text_effects_frame.pack(fill=tk.X, pady=5)
        
        text_effects_row = ttk.Frame(text_effects_frame)
        text_effects_row.pack(fill=tk.X, pady=2)
        
        self.text_shadow_var = tk.BooleanVar()
        ttk.Checkbutton(text_effects_row, text="Text Shadow", variable=self.text_shadow_var).pack(side=tk.LEFT, padx=5)
        
        self.text_glow_var = tk.BooleanVar()
        ttk.Checkbutton(text_effects_row, text="Text Glow", variable=self.text_glow_var).pack(side=tk.LEFT, padx=5)
        
        self.neon_effect_var = tk.BooleanVar()
        ttk.Checkbutton(text_effects_row, text="Neon Effect", variable=self.neon_effect_var).pack(side=tk.LEFT, padx=5)
        
        self.rainbow_text_var = tk.BooleanVar()
        ttk.Checkbutton(text_effects_row, text="Rainbow Text", variable=self.rainbow_text_var).pack(side=tk.LEFT, padx=5)
        
        # Animation effects
        anim_frame = ttk.LabelFrame(main_frame, text="Animations", padding=10)
        anim_frame.pack(fill=tk.X, pady=5)
        
        anim_row = ttk.Frame(anim_frame)
        anim_row.pack(fill=tk.X, pady=2)
        
        self.typing_anim_var = tk.BooleanVar()
        ttk.Checkbutton(anim_row, text="Typing Animation", variable=self.typing_anim_var).pack(side=tk.LEFT, padx=5)
        
        self.scan_lines_var = tk.BooleanVar()
        ttk.Checkbutton(anim_row, text="Scan Lines", variable=self.scan_lines_var).pack(side=tk.LEFT, padx=5)
        
        self.matrix_effect_var = tk.BooleanVar()
        ttk.Checkbutton(anim_row, text="Matrix Rain", variable=self.matrix_effect_var).pack(side=tk.LEFT, padx=5)
        
        # Apply settings button
        ttk.Button(main_frame, text="Apply Effect Settings", command=self.apply_effect_settings,
                  style='Custom.TButton').pack(pady=10)
    
    def create_layout_settings_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="📐 Layout Settings")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Dimensions
        dims_frame = ttk.LabelFrame(main_frame, text="Dimensions", padding=10)
        dims_frame.pack(fill=tk.X, pady=5)
        
        dims_row1 = ttk.Frame(dims_frame)
        dims_row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(dims_row1, text="Width:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.term_width_var = tk.IntVar(value=800)
        width_spinbox = ttk.Spinbox(dims_row1, from_=400, to=2000, textvariable=self.term_width_var, width=10)
        width_spinbox.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(dims_row1, text="Height:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.term_height_var = tk.IntVar(value=600)
        height_spinbox = ttk.Spinbox(dims_row1, from_=300, to=1500, textvariable=self.term_height_var, width=10)
        height_spinbox.pack(side=tk.LEFT, padx=(5, 10))
        
        # Padding and margins
        padding_frame = ttk.LabelFrame(main_frame, text="Padding & Margins", padding=10)
        padding_frame.pack(fill=tk.X, pady=5)
        
        pad_row1 = ttk.Frame(padding_frame)
        pad_row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(pad_row1, text="Padding (px):", foreground=self.label_fg).pack(side=tk.LEFT)
        self.padding_var = tk.IntVar(value=10)
        padding_spinbox = ttk.Spinbox(pad_row1, from_=0, to=50, textvariable=self.padding_var, width=5)
        padding_spinbox.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(pad_row1, text="Margin (px):", foreground=self.label_fg).pack(side=tk.LEFT)
        self.margin_var = tk.IntVar(value=5)
        margin_spinbox = ttk.Spinbox(pad_row1, from_=0, to=50, textvariable=self.margin_var, width=5)
        margin_spinbox.pack(side=tk.LEFT, padx=(5, 10))
        
        # Scrollbar settings
        scrollbar_frame = ttk.LabelFrame(main_frame, text="Scrollbar Settings", padding=10)
        scrollbar_frame.pack(fill=tk.X, pady=5)
        
        scroll_row1 = ttk.Frame(scrollbar_frame)
        scroll_row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(scroll_row1, text="Scrollbar Width:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.scroll_width_var = tk.IntVar(value=15)
        scroll_width_spinbox = ttk.Spinbox(scroll_row1, from_=5, to=50, textvariable=self.scroll_width_var, width=5)
        scroll_width_spinbox.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(scroll_row1, text="Scrollbar Style:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.scroll_style_var = tk.StringVar(value="auto")
        scroll_styles = ["auto", "always", "hidden"]
        scroll_combo = ttk.Combobox(scroll_row1, textvariable=self.scroll_style_var, values=scroll_styles, state="readonly", width=10)
        scroll_combo.pack(side=tk.LEFT, padx=(5, 10))
        
        # Position settings
        pos_frame = ttk.LabelFrame(main_frame, text="Position & Mode", padding=10)
        pos_frame.pack(fill=tk.X, pady=5)
        
        pos_row1 = ttk.Frame(pos_frame)
        pos_row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(pos_row1, text="Terminal Position:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.term_pos_var = tk.StringVar(value="center")
        pos_options = [("Center", "center"), ("Left", "left"), ("Right", "right")]
        
        for text, value in pos_options:
            ttk.Radiobutton(pos_row1, text=text, variable=self.term_pos_var, value=value).pack(side=tk.LEFT, padx=5)
        
        pos_row2 = ttk.Frame(pos_frame)
        pos_row2.pack(fill=tk.X, pady=2)
        
        self.fullscreen_var = tk.BooleanVar()
        ttk.Checkbutton(pos_row2, text="Fullscreen Mode", variable=self.fullscreen_var).pack(side=tk.LEFT, padx=5)
        
        self.compact_mode_var = tk.BooleanVar()
        ttk.Checkbutton(pos_row2, text="Compact Mode", variable=self.compact_mode_var).pack(side=tk.LEFT, padx=5)
        
        # Apply settings button
        ttk.Button(main_frame, text="Apply Layout Settings", command=self.apply_layout_settings,
                  style='Custom.TButton').pack(pady=10)
    
    def choose_cursor_color(self):
        color = tk.colorchooser.askcolor(title="Choose Cursor Color")[1]
        if color:
            self.cursor_color_var.set(color)
    
    def choose_selection_color(self):
        color = tk.colorchooser.askcolor(title="Choose Selection Color")[1]
        if color:
            self.selection_color_var.set(color)
    
    def choose_error_color(self):
        color = tk.colorchooser.askcolor(title="Choose Error Color")[1]
        if color:
            self.error_color_var.set(color)
    
    def choose_success_color(self):
        color = tk.colorchooser.askcolor(title="Choose Success Color")[1]
        if color:
            self.success_color_var.set(color)
    
    def choose_warning_color(self):
        color = tk.colorchooser.askcolor(title="Choose Warning Color")[1]
        if color:
            self.warning_color_var.set(color)
    
    def choose_info_color(self):
        color = tk.colorchooser.askcolor(title="Choose Info Color")[1]
        if color:
            self.info_color_var.set(color)
    
    def choose_solid_bg_color(self):
        color = tk.colorchooser.askcolor(title="Choose Solid Background Color")[1]
        if color:
            self.solid_bg_color_var.set(color)
    
    def choose_grad_start_color(self):
        color = tk.colorchooser.askcolor(title="Choose Gradient Start Color")[1]
        if color:
            self.grad_start_color_var.set(color)
    
    def choose_grad_end_color(self):
        color = tk.colorchooser.askcolor(title="Choose Gradient End Color")[1]
        if color:
            self.grad_end_color_var.set(color)
    
    def browse_bg_image(self):
        file_path = filedialog.askopenfilename(
            title="Select Background Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp")]
        )
        if file_path:
            self.bg_image_path_var.set(file_path)
    
    def apply_font_settings(self):
        # This would apply font settings to the terminal in a real application
        messagebox.showinfo("Info", "Font settings applied!")
    
    def apply_color_settings(self):
        # This would apply color settings to the terminal in a real application
        messagebox.showinfo("Info", "Color settings applied!")
    
    def apply_bg_settings(self):
        # This would apply background settings to the terminal in a real application
        messagebox.showinfo("Info", "Background settings applied!")
    
    def apply_effect_settings(self):
        # This would apply effect settings to the terminal in a real application
        messagebox.showinfo("Info", "Effect settings applied!")
    
    def apply_layout_settings(self):
        # This would apply layout settings to the terminal in a real application
        messagebox.showinfo("Info", "Layout settings applied!")
    
    def create_color_tools_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="🎨 Color Tools")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Notebook for color tools sub-tabs
        color_notebook = ttk.Notebook(main_frame)
        color_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Color Picker tab
        self.create_color_picker_tab(color_notebook)
        
        # Color Codes tab
        self.create_color_codes_tab(color_notebook)
        
        # Color Mixer tab
        self.create_color_mixer_tab(color_notebook)
        
        # Palette Generator tab
        self.create_palette_generator_tab(color_notebook)
        
        # Color Utilities tab
        self.create_color_utilities_tab(color_notebook)
    
    def create_color_picker_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="🔍 Color Picker")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Color picker section
        picker_frame = ttk.LabelFrame(main_frame, text="Visual Color Picker", padding=10)
        picker_frame.pack(fill=tk.X, pady=5)
        
        picker_row = ttk.Frame(picker_frame)
        picker_row.pack(fill=tk.X, pady=5)
        
        ttk.Label(picker_row, text="Selected Color:", foreground=self.label_fg).pack(side=tk.LEFT)
        self.selected_color_var = tk.StringVar(value="#FFFFFF")
        self.color_display = tk.Label(picker_row, textvariable=self.selected_color_var, width=10, 
                                     bg=self.selected_color_var.get(), relief="solid", borderwidth=1)
        self.color_display.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Button(picker_row, text="Pick Color", command=self.pick_color,
                  style='Custom.TButton').pack(side=tk.LEFT)
        
        # RGB sliders
        rgb_frame = ttk.LabelFrame(main_frame, text="RGB Sliders", padding=10)
        rgb_frame.pack(fill=tk.X, pady=5)
        
        # Red slider
        ttk.Label(rgb_frame, text="Red:", foreground=self.label_fg).pack(anchor=tk.W)
        self.red_var = tk.IntVar()
        red_scale = ttk.Scale(rgb_frame, from_=0, to=255, variable=self.red_var, 
                             command=lambda v: self.update_rgb_color())
        red_scale.pack(fill=tk.X, pady=2)
        
        # Green slider
        ttk.Label(rgb_frame, text="Green:", foreground=self.label_fg).pack(anchor=tk.W)
        self.green_var = tk.IntVar()
        green_scale = ttk.Scale(rgb_frame, from_=0, to=255, variable=self.green_var, 
                               command=lambda v: self.update_rgb_color())
        green_scale.pack(fill=tk.X, pady=2)
        
        # Blue slider
        ttk.Label(rgb_frame, text="Blue:", foreground=self.label_fg).pack(anchor=tk.W)
        self.blue_var = tk.IntVar()
        blue_scale = ttk.Scale(rgb_frame, from_=0, to=255, variable=self.blue_var, 
                              command=lambda v: self.update_rgb_color())
        blue_scale.pack(fill=tk.X, pady=2)
    
    def create_color_codes_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="🎨 Color Codes")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Color codes display
        codes_frame = ttk.LabelFrame(main_frame, text="Color Code Formats", padding=10)
        codes_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.color_codes_text = tk.Text(codes_frame, height=15, bg=self.text_bg, fg=self.text_fg)
        color_codes_scrollbar = ttk.Scrollbar(codes_frame, orient=tk.VERTICAL, command=self.color_codes_text.yview)
        self.color_codes_text.configure(yscrollcommand=color_codes_scrollbar.set)
        
        codes_text_frame = ttk.Frame(codes_frame)
        codes_text_frame.pack(fill=tk.BOTH, expand=True)
        self.color_codes_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        color_codes_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Button to generate codes
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Generate Color Codes", command=self.generate_color_codes,
                  style='Custom.TButton').pack(side=tk.LEFT)
    
    def create_color_mixer_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="🔄 Color Mixer")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Color 1 selection
        color1_frame = ttk.LabelFrame(main_frame, text="Color 1", padding=10)
        color1_frame.pack(fill=tk.X, pady=5)
        
        color1_row = ttk.Frame(color1_frame)
        color1_row.pack(fill=tk.X, pady=5)
        
        self.color1_var = tk.StringVar(value="#FF0000")
        color1_display = tk.Label(color1_row, textvariable=self.color1_var, width=10, 
                                 bg=self.color1_var.get(), relief="solid", borderwidth=1)
        color1_display.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(color1_row, text="Choose Color 1", command=lambda: self.choose_color_for_var(self.color1_var, color1_display),
                  style='Custom.TButton').pack(side=tk.LEFT)
        
        # Color 2 selection
        color2_frame = ttk.LabelFrame(main_frame, text="Color 2", padding=10)
        color2_frame.pack(fill=tk.X, pady=5)
        
        color2_row = ttk.Frame(color2_frame)
        color2_row.pack(fill=tk.X, pady=5)
        
        self.color2_var = tk.StringVar(value="#0000FF")
        color2_display = tk.Label(color2_row, textvariable=self.color2_var, width=10, 
                                 bg=self.color2_var.get(), relief="solid", borderwidth=1)
        color2_display.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(color2_row, text="Choose Color 2", command=lambda: self.choose_color_for_var(self.color2_var, color2_display),
                  style='Custom.TButton').pack(side=tk.LEFT)
        
        # Mix ratio
        mix_frame = ttk.LabelFrame(main_frame, text="Mix Ratio", padding=10)
        mix_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(mix_frame, text="Ratio (Color 1 : Color 2):", foreground=self.label_fg).pack(anchor=tk.W)
        self.mix_ratio_var = tk.DoubleVar(value=50.0)
        ratio_scale = ttk.Scale(mix_frame, from_=0, to=100, variable=self.mix_ratio_var, 
                               command=lambda v: self.mix_colors(),
                               length=300)
        ratio_scale.pack(fill=tk.X, pady=5)
        
        ttk.Label(mix_frame, textvariable=self.mix_ratio_var, width=10).pack()
        
        # Mixed color display
        mixed_frame = ttk.LabelFrame(main_frame, text="Mixed Color", padding=10)
        mixed_frame.pack(fill=tk.X, pady=5)
        
        self.mixed_color_var = tk.StringVar(value="#808080")
        self.mixed_color_display = tk.Label(mixed_frame, textvariable=self.mixed_color_var, width=20, 
                                           bg=self.mixed_color_var.get(), relief="solid", borderwidth=2, height=3)
        self.mixed_color_display.pack(pady=5)
        
        # Mix button
        ttk.Button(main_frame, text="Mix Colors", command=self.mix_colors,
                  style='Custom.TButton').pack(pady=10)
    
    def create_palette_generator_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="🌈 Palette Generator")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Palette type selection
        type_frame = ttk.LabelFrame(main_frame, text="Palette Type", padding=10)
        type_frame.pack(fill=tk.X, pady=5)
        
        self.palette_type_var = tk.StringVar(value="complementary")
        palette_types = [
            ("Complementary", "complementary"),
            ("Analogous", "analogous"),
            ("Triadic", "triadic"),
            ("Split-Complementary", "split_complementary"),
            ("Tetradic", "tetradic"),
            ("Monochromatic", "monochromatic"),
            ("Random", "random")
        ]
        
        for text, value in palette_types:
            ttk.Radiobutton(type_frame, text=text, variable=self.palette_type_var, 
                           value=value).pack(side=tk.LEFT, padx=5)
        
        # Base color selection
        base_frame = ttk.LabelFrame(main_frame, text="Base Color", padding=10)
        base_frame.pack(fill=tk.X, pady=5)
        
        base_row = ttk.Frame(base_frame)
        base_row.pack(fill=tk.X, pady=5)
        
        self.base_color_var = tk.StringVar(value="#FF0000")
        self.base_color_display = tk.Label(base_row, textvariable=self.base_color_var, width=10, 
                                          bg=self.base_color_var.get(), relief="solid", borderwidth=1)
        self.base_color_display.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(base_row, text="Choose Base Color", command=lambda: self.choose_color_for_var(self.base_color_var, self.base_color_display),
                  style='Custom.TButton').pack(side=tk.LEFT)
        
        # Generate palette button
        ttk.Button(main_frame, text="Generate Palette", command=self.generate_palette,
                  style='Custom.TButton').pack(pady=10)
        
        # Palette display
        palette_frame = ttk.LabelFrame(main_frame, text="Generated Palette", padding=10)
        palette_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.palette_canvas = tk.Canvas(palette_frame, height=100, bg=self.text_bg)
        self.palette_scrollbar = ttk.Scrollbar(palette_frame, orient=tk.HORIZONTAL, command=self.palette_canvas.xview)
        self.palette_canvas.configure(xscrollcommand=self.palette_scrollbar.set)
        
        canvas_frame = ttk.Frame(palette_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        self.palette_canvas.pack(side=tk.TOP, fill=tk.X)
        self.palette_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_color_utilities_tab(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, text="🔧 Color Utilities")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Color utilities
        utils_frame = ttk.LabelFrame(main_frame, text="Color Utilities", padding=10)
        utils_frame.pack(fill=tk.X, pady=5)
        
        utils_buttons_frame = ttk.Frame(utils_frame)
        utils_buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(utils_buttons_frame, text="Contrast Checker", command=self.contrast_checker,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(utils_buttons_frame, text="Lighten Color", command=self.lighten_color,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(utils_buttons_frame, text="Darken Color", command=self.darken_color,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(utils_buttons_frame, text="Invert Color", command=self.invert_color,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=2)
        
        # Input color
        input_frame = ttk.LabelFrame(main_frame, text="Input Color", padding=10)
        input_frame.pack(fill=tk.X, pady=5)
        
        input_row = ttk.Frame(input_frame)
        input_row.pack(fill=tk.X, pady=5)
        
        self.input_color_var = tk.StringVar(value="#808080")
        self.input_color_display = tk.Label(input_row, textvariable=self.input_color_var, width=10, 
                                           bg=self.input_color_var.get(), relief="solid", borderwidth=1)
        self.input_color_display.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(input_row, text="Choose Input Color", command=lambda: self.choose_color_for_var(self.input_color_var, self.input_color_display),
                  style='Custom.TButton').pack(side=tk.LEFT)
        
        # Result color
        result_frame = ttk.LabelFrame(main_frame, text="Result Color", padding=10)
        result_frame.pack(fill=tk.X, pady=5)
        
        self.result_color_var = tk.StringVar(value="#808080")
        self.result_color_display = tk.Label(result_frame, textvariable=self.result_color_var, width=20, 
                                            bg=self.result_color_var.get(), relief="solid", borderwidth=2, height=2)
        self.result_color_display.pack(pady=5)
    
    def update_rgb_color(self):
        r = int(self.red_var.get())
        g = int(self.green_var.get())
        b = int(self.blue_var.get())
        hex_color = f"#{r:02x}{g:02x}{b:02x}"
        self.selected_color_var.set(hex_color)
        self.color_display.config(bg=hex_color)
        self.generate_color_codes()
    
    def generate_color_codes(self):
        color = self.selected_color_var.get()
        if color.startswith('#') and len(color) == 7:
            # Convert hex to RGB
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            
            # Clear the text area
            self.color_codes_text.delete(1.0, tk.END)
            
            # Generate various color formats
            codes = [
                f"HEX: {color}",
                f"RGB: rgb({r}, {g}, {b})",
                f"RGBA: rgba({r}, {g}, {b}, 1)",
                f"RGBA (50% opacity): rgba({r}, {g}, {b}, 0.5)",
                f"HSL: hsl(0, 0%, {(r+g+b)//3}%)",  # Simplified HSL
                f"CMYK: ({100-(r/255)*100:.0f}%, {100-(g/255)*100:.0f}%, {100-(b/255)*100:.0f}%, {100-max(r,g,b)/255*100:.0f}%)",
                f"HSV: hsv(0°, 0%, {(r+g+b)//3}%)",  # Simplified HSV
                f"Name: Color({r},{g},{b})"
            ]
            
            for code in codes:
                self.color_codes_text.insert(tk.END, code + "\n")
    
    def choose_color_for_var(self, var, display_widget):
        color = tk.colorchooser.askcolor(title="Choose Color")[1]
        if color:
            var.set(color)
            display_widget.config(bg=color)
    
    def mix_colors(self):
        color1_hex = self.color1_var.get()
        color2_hex = self.color2_var.get()
        ratio = self.mix_ratio_var.get() / 100.0  # Convert to 0-1 range
        
        # Convert hex to RGB
        r1, g1, b1 = tuple(int(color1_hex[i:i+2], 16) for i in (1, 3, 5))
        r2, g2, b2 = tuple(int(color2_hex[i:i+2], 16) for i in (1, 3, 5))
        
        # Mix the colors
        r = int(r1 * ratio + r2 * (1 - ratio))
        g = int(g1 * ratio + g2 * (1 - ratio))
        b = int(b1 * ratio + b2 * (1 - ratio))
        
        # Convert back to hex
        mixed_color = f"#{r:02x}{g:02x}{b:02x}"
        self.mixed_color_var.set(mixed_color)
        self.mixed_color_display.config(bg=mixed_color)
    
    def generate_palette(self):
        base_color = self.base_color_var.get()
        palette_type = self.palette_type_var.get()
        
        # Clear the canvas
        self.palette_canvas.delete("all")
        
        # Convert base hex to RGB
        base_r, base_g, base_b = tuple(int(base_color[i:i+2], 16) for i in (1, 3, 5))
        
        # Generate palette based on type
        colors = []
        if palette_type == "complementary":
            # Complementary: opposite on color wheel (add 180 degrees)
            h, s, v = self.rgb_to_hsv(base_r, base_g, base_b)
            h_comp = (h + 180) % 360
            comp_r, comp_g, comp_b = self.hsv_to_rgb(h_comp, s, v)
            colors = [base_color, f"#{comp_r:02x}{comp_g:02x}{comp_b:02x}"]
        elif palette_type == "analogous":
            # Analogous: colors adjacent on color wheel
            h, s, v = self.rgb_to_hsv(base_r, base_g, base_b)
            h1 = (h + 30) % 360
            h2 = (h - 30) % 360
            r1, g1, b1 = self.hsv_to_rgb(h1, s, v)
            r2, g2, b2 = self.hsv_to_rgb(h2, s, v)
            colors = [f"#{base_r:02x}{base_g:02x}{base_b:02x}", 
                     f"#{r1:02x}{g1:02x}{b1:02x}", 
                     f"#{r2:02x}{g2:02x}{b2:02x}"]
        elif palette_type == "triadic":
            # Triadic: colors 120 degrees apart
            h, s, v = self.rgb_to_hsv(base_r, base_g, base_b)
            h1 = (h + 120) % 360
            h2 = (h + 240) % 360
            r1, g1, b1 = self.hsv_to_rgb(h1, s, v)
            r2, g2, b2 = self.hsv_to_rgb(h2, s, v)
            colors = [f"#{base_r:02x}{base_g:02x}{base_b:02x}", 
                     f"#{r1:02x}{g1:02x}{b1:02x}", 
                     f"#{r2:02x}{g2:02x}{b2:02x}"]
        elif palette_type == "monochromatic":
            # Monochromatic: variations of same hue
            h, s, v = self.rgb_to_hsv(base_r, base_g, base_b)
            s1 = max(0, s - 30)
            s2 = min(100, s + 30)
            v1 = max(0, v - 30)
            v2 = min(100, v + 30)
            r1, g1, b1 = self.hsv_to_rgb(h, s1, v)
            r2, g2, b2 = self.hsv_to_rgb(h, s2, v)
            r3, g3, b3 = self.hsv_to_rgb(h, s, v1)
            r4, g4, b4 = self.hsv_to_rgb(h, s, v2)
            colors = [f"#{base_r:02x}{base_g:02x}{base_b:02x}", 
                     f"#{r1:02x}{g1:02x}{b1:02x}", 
                     f"#{r2:02x}{g2:02x}{b2:02x}",
                     f"#{r3:02x}{g3:02x}{b3:02x}",
                     f"#{r4:02x}{g4:02x}{b4:02x}"]
        elif palette_type == "random":
            import random
            colors = [f"#{random.randint(0, 255):02x}{random.randint(0, 255):02x}{random.randint(0, 255):02x}" 
                     for _ in range(5)]
        else:  # Default to complementary
            h, s, v = self.rgb_to_hsv(base_r, base_g, base_b)
            h_comp = (h + 180) % 360
            comp_r, comp_g, comp_b = self.hsv_to_rgb(h_comp, s, v)
            colors = [base_color, f"#{comp_r:02x}{comp_g:02x}{comp_b:02x}"]
        
        # Draw the palette on canvas
        canvas_width = len(colors) * 100
        self.palette_canvas.config(scrollregion=(0, 0, canvas_width, 100))
        
        for i, color in enumerate(colors):
            x_start = i * 100
            x_end = (i + 1) * 100
            self.palette_canvas.create_rectangle(x_start, 0, x_end, 100, fill=color, outline="black")
            self.palette_canvas.create_text(x_start + 50, 50, text=color, fill="white" if self.is_dark_color(color) else "black")
    
    def is_dark_color(self, hex_color):
        # Convert hex to RGB
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (1, 3, 5))
        # Calculate luminance
        luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
        return luminance < 0.5
    
    def rgb_to_hsv(self, r, g, b):
        r, g, b = r / 255.0, g / 255.0, b / 255.0
        mx = max(r, g, b)
        mn = min(r, g, b)
        df = mx - mn
        
        if mx == mn:
            h = 0
        elif mx == r:
            h = (60 * ((g - b) / df) + 360) % 360
        elif mx == g:
            h = (60 * ((b - r) / df) + 120) % 360
        elif mx == b:
            h = (60 * ((r - g) / df) + 240) % 360
        
        if mx == 0:
            s = 0
        else:
            s = (df / mx) * 100
        
        v = mx * 100
        return int(h), int(s), int(v)
    
    def hsv_to_rgb(self, h, s, v):
        h = float(h)
        s = float(s) / 100
        v = float(v) / 100
        
        i = int(h // 60) % 6
        f = (h / 60) - i
        p = v * (1 - s)
        q = v * (1 - f * s)
        t = v * (1 - (1 - f) * s)
        
        if i == 0:
            r, g, b = v, t, p
        elif i == 1:
            r, g, b = q, v, p
        elif i == 2:
            r, g, b = p, v, t
        elif i == 3:
            r, g, b = p, q, v
        elif i == 4:
            r, g, b = t, p, v
        elif i == 5:
            r, g, b = v, p, q
        
        return int(r * 255), int(g * 255), int(b * 255)
    
    def contrast_checker(self):
        # For simplicity, just invert the input color as an example
        input_color = self.input_color_var.get()
        if input_color.startswith('#') and len(input_color) == 7:
            r, g, b = tuple(int(input_color[i:i+2], 16) for i in (1, 3, 5))
            # Simple inversion for demonstration
            inv_r, inv_g, inv_b = 255 - r, 255 - g, 255 - b
            result_color = f"#{inv_r:02x}{inv_g:02x}{inv_b:02x}"
            self.result_color_var.set(result_color)
            self.result_color_display.config(bg=result_color)
    
    def lighten_color(self):
        input_color = self.input_color_var.get()
        if input_color.startswith('#') and len(input_color) == 7:
            r, g, b = tuple(int(input_color[i:i+2], 16) for i in (1, 3, 5))
            # Increase each component by 25%, capped at 255
            r = min(255, int(r * 1.25))
            g = min(255, int(g * 1.25))
            b = min(255, int(b * 1.25))
            result_color = f"#{r:02x}{g:02x}{b:02x}"
            self.result_color_var.set(result_color)
            self.result_color_display.config(bg=result_color)
    
    def darken_color(self):
        input_color = self.input_color_var.get()
        if input_color.startswith('#') and len(input_color) == 7:
            r, g, b = tuple(int(input_color[i:i+2], 16) for i in (1, 3, 5))
            # Decrease each component by 25%
            r = max(0, int(r * 0.75))
            g = max(0, int(g * 0.75))
            b = max(0, int(b * 0.75))
            result_color = f"#{r:02x}{g:02x}{b:02x}"
            self.result_color_var.set(result_color)
            self.result_color_display.config(bg=result_color)
    
    def invert_color(self):
        input_color = self.input_color_var.get()
        if input_color.startswith('#') and len(input_color) == 7:
            r, g, b = tuple(int(input_color[i:i+2], 16) for i in (1, 3, 5))
            # Invert colors
            r, g, b = 255 - r, 255 - g, 255 - b
            result_color = f"#{r:02x}{g:02x}{b:02x}"
            self.result_color_var.set(result_color)
            self.result_color_display.config(bg=result_color)
    
    def browse_avatar(self):
        file_path = filedialog.askopenfilename(
            title="Select Profile Avatar",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp")]
        )
        if file_path:
            self.avatar_path_var.set(file_path)
    
    def save_profile(self):
        # In a real application, this would save to a file/database
        messagebox.showinfo("Info", "Profile saved successfully!")
    
    def load_profile(self):
        # In a real application, this would load from a file/database
        messagebox.showinfo("Info", "Profile loaded successfully!")
    
    def reset_profile(self):
        self.display_name_var.set("Sudhir Kumar")
        self.username_var.set("SudhirDevOps1")
        self.bio_text.delete(1.0, tk.END)
        self.bio_text.insert(tk.END, "System Administrator & Developer")
        self.avatar_path_var.set("")
        self.commands_run_var.set(0)
        messagebox.showinfo("Info", "Profile reset to defaults!")
    
    def choose_text_color(self):
        color = tk.colorchooser.askcolor(title="Choose Text Color")[1]
        if color:
            self.text_color_var.set(color)
    
    def choose_bg_color(self):
        color = tk.colorchooser.askcolor(title="Choose Background Color")[1]
        if color:
            self.bg_color_var.set(color)
    
    def apply_terminal_settings(self):
        # This would apply the settings to the terminal in a real application
        messagebox.showinfo("Info", "Terminal settings applied!")
        
        # Update the theme colors
        self.text_fg = self.text_color_var.get()
        self.bg_color = self.bg_color_var.get()
        
        # Update UI elements
        self.apply_theme(self.current_theme)
    
    def pick_color(self):
        color = tk.colorchooser.askcolor(title="Pick a Color")[1]
        if color:
            self.selected_color_var.set(color)
            # Update the color display
            for widget in self.root.winfo_children():
                if hasattr(widget, 'selected_color_var') and hasattr(widget, 'configure'):
                    try:
                        widget.configure(bg=color)
                    except:
                        pass
            self.update_color_codes_display(color)
    
    def update_color_codes_display(self, color):
        # Clear the text area
        self.color_codes_text.delete(1.0, tk.END)
        
        # Convert hex to RGB
        rgb = tuple(int(color[i:i+2], 16) for i in (1, 3, 5))
        
        # Generate various color formats
        codes = [
            f"HEX: {color}",
            f"RGB: rgb({rgb[0]}, {rgb[1]}, {rgb[2]})",
            f"RGBA: rgba({rgb[0]}, {rgb[1]}, {rgb[2]}, 1)",
            f"HSL: hsl(0, 0%, {(rgb[0]+rgb[1]+rgb[2])//3}%)",  # Simplified HSL
            f"HSV: hsv(0, 0%, {(rgb[0]+rgb[1]+rgb[2])//3}%)",  # Simplified HSV
            f"CMS: #{color[1:3]}{color[5:7]}{color[3:5]}"  # Rearranged for demo
        ]
        
        for code in codes:
            self.color_codes_text.insert(tk.END, code + "\n")
        
    def create_duplicate_finder_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Duplicate Finder")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Directory selection
        dir_frame = ttk.LabelFrame(main_frame, text="Directory Selection", padding=10)
        dir_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(dir_frame, text="Directory to scan for duplicates:", foreground=self.label_fg).pack(pady=5)
        
        dup_dir_frame = ttk.Frame(dir_frame)
        dup_dir_frame.pack(fill=tk.X, pady=5)
        
        self.dup_dir_var = tk.StringVar()
        ttk.Entry(dup_dir_frame, textvariable=self.dup_dir_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(dup_dir_frame, text="Browse", command=self.browse_dup_directory, 
                  style='Custom.TButton').pack(side=tk.RIGHT)
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Find Duplicates", command=self.start_find_duplicates, 
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Results", command=lambda: self.dup_result_text.delete(1.0, tk.END),
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        
        # Results display
        result_frame = ttk.LabelFrame(main_frame, text="Results", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.dup_result_text = tk.Text(result_frame, height=15, bg=self.text_bg, fg=self.text_fg)
        dup_scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.dup_result_text.yview)
        self.dup_result_text.configure(yscrollcommand=dup_scrollbar.set)
        
        text_frame = ttk.Frame(result_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        self.dup_result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dup_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_file_searcher_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="File Searcher")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Search criteria
        search_frame = ttk.LabelFrame(main_frame, text="Search Criteria", padding=10)
        search_frame.pack(fill=tk.X, pady=5)
        
        # File name input
        ttk.Label(search_frame, text="File name to search:", foreground=self.label_fg).pack(pady=5)
        self.search_name_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.search_name_var, width=50).pack(pady=5)
        
        # Directory input
        ttk.Label(search_frame, text="Directory to search in:", foreground=self.label_fg).pack(pady=5)
        
        search_dir_frame = ttk.Frame(search_frame)
        search_dir_frame.pack(fill=tk.X, pady=5)
        
        self.search_dir_var = tk.StringVar()
        ttk.Entry(search_dir_frame, textvariable=self.search_dir_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(search_dir_frame, text="Browse", command=self.browse_search_directory,
                  style='Custom.TButton').pack(side=tk.RIGHT)
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Search Files", command=self.start_search_files,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Search by Extension", command=self.start_search_by_extension,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Results", command=lambda: self.search_result_text.delete(1.0, tk.END),
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        
        # Results display
        result_frame = ttk.LabelFrame(main_frame, text="Search Results", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.search_result_text = tk.Text(result_frame, height=15, bg=self.text_bg, fg=self.text_fg)
        search_scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.search_result_text.yview)
        self.search_result_text.configure(yscrollcommand=search_scrollbar.set)
        
        text_frame = ttk.Frame(result_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        self.search_result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        search_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_privacy_cleaner_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Privacy Cleaner")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Privacy cleaning options
        options_frame = ttk.LabelFrame(main_frame, text="Privacy Cleaning Options", padding=10)
        options_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(options_frame, text="Select cleaning options:", font=("Arial", 10), 
                 foreground=self.label_fg).pack(pady=5)
        
        # Buttons for cleaning options
        btn_frame1 = ttk.Frame(options_frame)
        btn_frame1.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame1, text="Clean Temporary Files", command=self.start_clean_temp_files,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(btn_frame1, text="Clean Recent Documents", command=self.start_clean_recent_docs,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        btn_frame2 = ttk.Frame(options_frame)
        btn_frame2.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame2, text="Clean Browser Cache", command=self.start_clean_browser_cache,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(btn_frame2, text="Clean All Privacy Data", command=self.start_clean_all_privacy,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        # Additional privacy tools
        tools_frame = ttk.LabelFrame(main_frame, text="Additional Privacy Tools", padding=10)
        tools_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(tools_frame, text="Clean Clipboard", command=self.clean_clipboard,
                  style='Custom.TButton').pack(pady=5)
        
        # Results display
        result_frame = ttk.LabelFrame(main_frame, text="Operation Results", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.privacy_result_text = tk.Text(result_frame, height=15, bg=self.text_bg, fg=self.text_fg)
        privacy_scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.privacy_result_text.yview)
        self.privacy_result_text.configure(yscrollcommand=privacy_scrollbar.set)
        
        text_frame = ttk.Frame(result_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        self.privacy_result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        privacy_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def clean_clipboard(self):
        try:
            import pyperclip
            pyperclip.copy("")  # Clear clipboard
            self.privacy_result_text.insert(tk.END, "Clipboard cleared.\n")
        except ImportError:
            self.privacy_result_text.insert(tk.END, "pyperclip not installed. Install with: pip install pyperclip\n")
        except Exception as e:
            self.privacy_result_text.insert(tk.END, f"Error clearing clipboard: {str(e)}\n")
    
    def execute_command(self):
        command = self.command_var.get().strip()
        if not command:
            return
        
        # Add command to history
        if command not in self.command_history:
            self.command_history.append(command)
        self.history_index = len(self.command_history)  # Reset index to end of history
        
        shell_type = self.shell_var.get()
        
        try:
            # Add command to output
            self.terminal_output.insert(tk.END, f"$ {command}\n")
            
            # Execute command based on shell type
            if shell_type == "powershell":
                # For PowerShell, we need to handle directory changes specially
                if command.lower().startswith('cd ') or command.lower() == 'cd':
                    # Handle directory change for PowerShell
                    try:
                        # Extract directory from command
                        if command.lower() == 'cd':
                            new_dir = os.path.expanduser('~')  # Go to home directory
                        else:
                            new_dir = command[3:].strip().strip('"\'')  # Get directory after 'cd '
                            if not os.path.isabs(new_dir):
                                new_dir = os.path.abspath(os.path.join(os.getcwd(), new_dir))
                        
                        os.chdir(new_dir)
                        self.terminal_output.insert(tk.END, f"Changed directory to: {os.getcwd()}\n")
                    except Exception as e:
                        self.terminal_output.insert(tk.END, f"ERROR: {str(e)}\n")
                else:
                    # Regular PowerShell command
                    result = subprocess.run(["powershell", "-Command", command], 
                                          capture_output=True, text=True, 
                                          cwd=os.getcwd())
                    
                    # Display output
                    if result.stdout:
                        self.terminal_output.insert(tk.END, result.stdout)
                    if result.stderr:
                        self.terminal_output.insert(tk.END, f"ERROR: {result.stderr}")
            else:  # cmd
                # For CMD, handle directory changes specially
                if command.lower().startswith('cd ') or command.lower() == 'cd':
                    try:
                        # Extract directory from command
                        if command.lower() == 'cd':
                            new_dir = os.path.expanduser('~')  # Go to home directory
                        else:
                            new_dir = command[3:].strip().strip('"\'')  # Get directory after 'cd '
                            if not os.path.isabs(new_dir):
                                new_dir = os.path.abspath(os.path.join(os.getcwd(), new_dir))
                        
                        os.chdir(new_dir)
                        self.terminal_output.insert(tk.END, f"Changed directory to: {os.getcwd()}\n")
                    except Exception as e:
                        self.terminal_output.insert(tk.END, f"ERROR: {str(e)}\n")
                else:
                    # Regular CMD command
                    result = subprocess.run(command, shell=True, 
                                          capture_output=True, text=True,
                                          cwd=os.getcwd())
                    
                    # Display output
                    if result.stdout:
                        self.terminal_output.insert(tk.END, result.stdout)
                    if result.stderr:
                        self.terminal_output.insert(tk.END, f"ERROR: {result.stderr}")
            
            # Add new prompt
            self.terminal_output.insert(tk.END, "$ ")
            
            # Scroll to the end
            self.terminal_output.see(tk.END)
            
            # Clear command input
            self.command_var.set("")
            
        except Exception as e:
            self.terminal_output.insert(tk.END, f"Exception occurred: {str(e)}\n")
            self.terminal_output.insert(tk.END, "$ ")
            self.terminal_output.see(tk.END)
        
    def create_package_manager_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Package Manager")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Package list section
        list_frame = ttk.LabelFrame(main_frame, text="Installed Packages", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.pkg_listbox = tk.Listbox(list_frame, height=8, bg=self.text_bg, fg=self.text_fg)
        pkg_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.pkg_listbox.yview)
        self.pkg_listbox.configure(yscrollcommand=pkg_scrollbar.set)
        
        pkg_list_frame = ttk.Frame(list_frame)
        pkg_list_frame.pack(fill=tk.BOTH, expand=True)
        self.pkg_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        pkg_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons for package management
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Refresh List", command=self.refresh_packages,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Install Package", command=self.install_package_dialog,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Uninstall Package", command=self.uninstall_package_dialog,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Upgrade Package", command=self.upgrade_package_dialog,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Upgrade Pip", command=self.start_upgrade_pip,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Export Packages", command=self.export_packages,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        
        # Package operation results
        result_frame = ttk.LabelFrame(main_frame, text="Operation Results", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.pkg_result_text = tk.Text(result_frame, height=10, bg=self.text_bg, fg=self.text_fg)
        pkg_result_scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.pkg_result_text.yview)
        self.pkg_result_text.configure(yscrollcommand=pkg_result_scrollbar.set)
        
        pkg_result_frame = ttk.Frame(result_frame)
        pkg_result_frame.pack(fill=tk.BOTH, expand=True)
        self.pkg_result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        pkg_result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load initial package list after GUI is fully loaded
        self.root.after(100, self.refresh_packages)
    
    def export_packages(self):
        try:
            import subprocess
            import sys
            result = subprocess.run([sys.executable, '-m', 'pip', 'freeze'], 
                                  capture_output=True, text=True, check=True)
            
            # Ask user for file location to save
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save package list to file"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(result.stdout)
                self.pkg_result_text.insert(tk.END, f"Package list exported to {file_path}\n")
            else:
                self.pkg_result_text.insert(tk.END, "Export cancelled.\n")
        except Exception as e:
            self.pkg_result_text.insert(tk.END, f"Error exporting packages: {str(e)}\n")
        
    def create_system_cleaner_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="System Cleaner")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # System cleaning options
        options_frame = ttk.LabelFrame(main_frame, text="System Cleaning Options", padding=10)
        options_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(options_frame, text="Select cleaning options:", font=("Arial", 10),
                 foreground=self.label_fg).pack(pady=5)
        
        # Cleaning buttons
        btn_frame1 = ttk.Frame(options_frame)
        btn_frame1.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame1, text="Run Full System Cleanup", command=self.start_full_cleanup,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(btn_frame1, text="Show Disk Usage", command=self.show_disk_usage,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        # Additional system tools
        tools_frame = ttk.LabelFrame(main_frame, text="System Tools", padding=10)
        tools_frame.pack(fill=tk.X, pady=5)
        
        btn_frame2 = ttk.Frame(tools_frame)
        btn_frame2.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame2, text="Empty Recycle Bin", command=self.empty_recycle_bin,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(btn_frame2, text="Optimize Drive (Coming Soon)", command=self.optimize_drive_disabled,
                  style='Custom.TButton').pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        # Results display
        result_frame = ttk.LabelFrame(main_frame, text="System Information & Results", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.system_result_text = tk.Text(result_frame, height=20, bg=self.text_bg, fg=self.text_fg)
        system_scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.system_result_text.yview)
        self.system_result_text.configure(yscrollcommand=system_scrollbar.set)
        
        text_frame = ttk.Frame(result_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        self.system_result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        system_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Show initial disk usage
        self.show_disk_usage()
    
    def empty_recycle_bin(self):
        try:
            import winshell
            winshell.recycle_bin().empty(confirm=False, show_progress=False)
            self.system_result_text.insert(tk.END, "Recycle bin emptied successfully.\n")
        except ImportError:
            self.system_result_text.insert(tk.END, "winshell not installed. Install with: pip install winshell\n")
        except Exception as e:
            self.system_result_text.insert(tk.END, f"Error emptying recycle bin: {str(e)}\n")
    
    def optimize_drive_disabled(self):
        messagebox.showinfo("Feature Coming Soon", "Drive optimization feature will be available in a future update.")
    
    def create_terminal_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Terminal")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Terminal control panel
        control_frame = ttk.LabelFrame(main_frame, text="Terminal Control", padding=10)
        control_frame.pack(fill=tk.X, pady=5)
        
        # Shell selection and other controls
        top_control_frame = ttk.Frame(control_frame)
        top_control_frame.pack(fill=tk.X, pady=5)
        
        # Shell selection
        shell_frame = ttk.Frame(top_control_frame)
        shell_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(shell_frame, text="Select Shell:", foreground=self.label_fg).pack(side=tk.LEFT, padx=(0, 10))
        
        self.shell_var = tk.StringVar(value="cmd")
        cmd_radio = ttk.Radiobutton(shell_frame, text="CMD", variable=self.shell_var, value="cmd")
        powershell_radio = ttk.Radiobutton(shell_frame, text="PowerShell", variable=self.shell_var, value="powershell")
        
        cmd_radio.pack(side=tk.LEFT, padx=5)
        powershell_radio.pack(side=tk.LEFT, padx=5)
        
        # Terminal settings
        settings_frame = ttk.Frame(top_control_frame)
        settings_frame.pack(side=tk.RIGHT, fill=tk.X)
        
        ttk.Button(settings_frame, text="Clear History", command=self.clear_command_history, 
                  style='Custom.TButton').pack(side=tk.RIGHT, padx=2)
        ttk.Button(settings_frame, text="Reset Terminal", command=self.reset_terminal, 
                  style='Custom.TButton').pack(side=tk.RIGHT, padx=2)
        
        # Command input
        cmd_frame = ttk.Frame(control_frame)
        cmd_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(cmd_frame, text="Command:", foreground=self.label_fg).pack(side=tk.LEFT, padx=(0, 5))
        self.command_var = tk.StringVar()
        self.cmd_entry = ttk.Entry(cmd_frame, textvariable=self.command_var, width=50)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        # Bind Enter key to execute command
        self.cmd_entry.bind('<Return>', lambda event: self.execute_command())
        # Bind Up/Down arrows for command history
        self.cmd_entry.bind('<Up>', self.previous_command)
        self.cmd_entry.bind('<Down>', self.next_command)
        
        execute_btn = ttk.Button(cmd_frame, text="Execute", command=self.execute_command, 
                               style='Custom.TButton')
        execute_btn.pack(side=tk.RIGHT)
        
        clear_btn = ttk.Button(cmd_frame, text="Clear Output", command=lambda: self.terminal_output.delete(1.0, tk.END), 
                             style='Custom.TButton')
        clear_btn.pack(side=tk.RIGHT, padx=5)
        
        # Terminal output
        output_frame = ttk.LabelFrame(main_frame, text="Terminal Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.terminal_output = tk.Text(output_frame, height=20, bg=self.text_bg, fg=self.text_fg, 
                                     font=('Consolas', 9), wrap=tk.NONE)
        terminal_vscrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, 
                                          command=self.terminal_output.yview)
        terminal_hscrollbar = ttk.Scrollbar(output_frame, orient=tk.HORIZONTAL, 
                                          command=self.terminal_output.xview)
        self.terminal_output.configure(yscrollcommand=terminal_vscrollbar.set,
                                      xscrollcommand=terminal_hscrollbar.set)
        
        text_frame = ttk.Frame(output_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        self.terminal_output.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        terminal_vscrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        terminal_hscrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Initialize command history
        self.command_history = []
        self.history_index = -1
        
        # Initial prompt
        self.terminal_output.insert(tk.END, f"Terminal ready. Using {self.shell_var.get().upper()}.\n")
        self.terminal_output.insert(tk.END, f"Current directory: {os.getcwd()}\n")
        self.terminal_output.insert(tk.END, "$ ")
    
    def reset_terminal(self):
        self.terminal_output.delete(1.0, tk.END)
        self.terminal_output.insert(tk.END, f"Terminal reset. Using {self.shell_var.get().upper()}.\n")
        self.terminal_output.insert(tk.END, f"Current directory: {os.getcwd()}\n")
        self.terminal_output.insert(tk.END, "$ ")
    
    def clear_command_history(self):
        self.command_history = []
        self.history_index = -1
        self.terminal_output.insert(tk.END, "Command history cleared.\n")
        self.terminal_output.insert(tk.END, "$ ")
    
    def previous_command(self, event):
        if self.command_history:
            if self.history_index == -1:
                self.history_index = len(self.command_history) - 1
            elif self.history_index > 0:
                self.history_index -= 1
            
            if self.history_index >= 0:
                self.command_var.set(self.command_history[self.history_index])
                self.cmd_entry.icursor(tk.END)  # Move cursor to end
        return "break"  # Prevent default behavior
    
    def next_command(self, event):
        if self.command_history:
            if self.history_index < len(self.command_history) - 1:
                self.history_index += 1
                self.command_var.set(self.command_history[self.history_index])
            else:
                self.history_index = len(self.command_history)  # Position after last command
                self.command_var.set("")
            self.cmd_entry.icursor(tk.END)  # Move cursor to end
        return "break"  # Prevent default behavior
    
    def create_additional_features_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Additional Features")
        
        # Create a main frame with padding
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # System Info Section
        info_frame = ttk.LabelFrame(main_frame, text="System Information", padding=10)
        info_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(info_frame, text="Show System Info", 
                  command=self.show_system_info, 
                  style='Custom.TButton').pack(pady=5)
        
        # Disk Analysis Section
        analysis_frame = ttk.LabelFrame(main_frame, text="Disk Analysis", padding=10)
        analysis_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(analysis_frame, text="Analyze Disk Usage", 
                  command=self.analyze_disk_usage, 
                  style='Custom.TButton').pack(pady=5)
        
        ttk.Button(analysis_frame, text="Find Large Files", 
                  command=self.find_large_files, 
                  style='Custom.TButton').pack(pady=5)
        
        # Startup Manager Section
        startup_frame = ttk.LabelFrame(main_frame, text="Startup Manager", padding=10)
        startup_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(startup_frame, text="View Startup Programs", 
                  command=self.view_startup_programs, 
                  style='Custom.TButton').pack(pady=5)
        
        # Security Tools Section
        security_frame = ttk.LabelFrame(main_frame, text="Security Tools", padding=10)
        security_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(security_frame, text="Check Running Processes", 
                  command=self.check_running_processes, 
                  style='Custom.TButton').pack(pady=5)
        
        # Results text area
        self.additional_result_text = tk.Text(main_frame, height=15, 
                                             bg=self.text_bg, fg=self.text_fg)
        additional_scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, 
                                           command=self.additional_result_text.yview)
        self.additional_result_text.configure(yscrollcommand=additional_scrollbar.set)
        
        result_frame = ttk.Frame(main_frame)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.additional_result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        additional_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def show_system_info(self):
        self.additional_result_text.delete(1.0, tk.END)
        self.additional_result_text.insert(tk.END, "System Information:\n")
        self.additional_result_text.insert(tk.END, "="*50 + "\n")
        
        try:
            import platform
            self.additional_result_text.insert(tk.END, f"System: {platform.system()}\n")
            self.additional_result_text.insert(tk.END, f"Node Name: {platform.node()}\n")
            self.additional_result_text.insert(tk.END, f"Release: {platform.release()}\n")
            self.additional_result_text.insert(tk.END, f"Version: {platform.version()}\n")
            self.additional_result_text.insert(tk.END, f"Machine: {platform.machine()}\n")
            self.additional_result_text.insert(tk.END, f"Processor: {platform.processor()}\n")
            
            # CPU info
            self.additional_result_text.insert(tk.END, f"\nCPU Count: {psutil.cpu_count()} cores\n")
            self.additional_result_text.insert(tk.END, f"CPU Usage: {psutil.cpu_percent(interval=1)}%\n")
            
            # Memory info
            memory = psutil.virtual_memory()
            self.additional_result_text.insert(tk.END, f"\nTotal Memory: {memory.total / (1024**3):.2f} GB\n")
            self.additional_result_text.insert(tk.END, f"Available Memory: {memory.available / (1024**3):.2f} GB\n")
            self.additional_result_text.insert(tk.END, f"Memory Usage: {memory.percent}%\n")
            
        except Exception as e:
            self.additional_result_text.insert(tk.END, f"Error getting system info: {str(e)}\n")
    
    def analyze_disk_usage(self):
        self.additional_result_text.delete(1.0, tk.END)
        self.additional_result_text.insert(tk.END, "Analyzing Disk Usage...\n")
        self.additional_result_text.insert(tk.END, "="*50 + "\n")
        
        try:
            # Get disk usage for main drive
            disk_usage = psutil.disk_usage('/')
            total = disk_usage.total / (1024**3)  # Convert to GB
            used = disk_usage.used / (1024**3)
            free = disk_usage.free / (1024**3)
            percent = (used / total) * 100
            
            self.additional_result_text.insert(tk.END, f"Total Space: {total:.2f} GB\n")
            self.additional_result_text.insert(tk.END, f"Used Space: {used:.2f} GB ({percent:.1f}%)\n")
            self.additional_result_text.insert(tk.END, f"Free Space: {free:.2f} GB\n")
            
            # Analyze a specific directory if provided
            directory = filedialog.askdirectory(title="Select Directory to Analyze")
            if directory:
                self.additional_result_text.insert(tk.END, f"\nAnalyzing directory: {directory}\n")
                self.analyze_directory_size(directory)
                
        except Exception as e:
            self.additional_result_text.insert(tk.END, f"Error analyzing disk usage: {str(e)}\n")
    
    def analyze_directory_size(self, directory):
        total_size = 0
        file_count = 0
        dir_count = 0
        
        try:
            for dirpath, dirnames, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                        file_count += 1
                    except OSError:
                        continue
                dir_count += len(dirnames)
        except Exception:
            pass
        
        size_mb = total_size / (1024 * 1024)
        self.additional_result_text.insert(tk.END, f"Size: {size_mb:.2f} MB\n")
        self.additional_result_text.insert(tk.END, f"Files: {file_count}\n")
        self.additional_result_text.insert(tk.END, f"Folders: {dir_count}\n")
    
    def find_large_files(self):
        self.additional_result_text.delete(1.0, tk.END)
        self.additional_result_text.insert(tk.END, "Finding Large Files (>100MB)...\n")
        self.additional_result_text.insert(tk.END, "="*50 + "\n")
        
        try:
            directory = filedialog.askdirectory(title="Select Directory to Scan")
            if not directory:
                return
                
            large_files = []
            threshold = 100 * 1024 * 1024  # 100MB in bytes
            
            for dirpath, dirnames, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        size = os.path.getsize(filepath)
                        if size > threshold:
                            large_files.append((filepath, size))
                    except OSError:
                        continue
            
            # Sort by size (largest first)
            large_files.sort(key=lambda x: x[1], reverse=True)
            
            if large_files:
                for filepath, size in large_files[:20]:  # Show top 20
                    size_mb = size / (1024 * 1024)
                    self.additional_result_text.insert(tk.END, 
                                                      f"{filepath} - {size_mb:.2f} MB\n")
            else:
                self.additional_result_text.insert(tk.END, "No files larger than 100MB found.\n")
                
        except Exception as e:
            self.additional_result_text.insert(tk.END, f"Error finding large files: {str(e)}\n")
    
    def view_startup_programs(self):
        self.additional_result_text.delete(1.0, tk.END)
        self.additional_result_text.insert(tk.END, "Startup Programs:\n")
        self.additional_result_text.insert(tk.END, "="*50 + "\n")
        
        # This is a simplified version - actual implementation would vary by OS
        try:
            if os.name == 'nt':  # Windows
                startup_locations = [
                    os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                    os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                ]
                
                for location in startup_locations:
                    if os.path.exists(location):
                        self.additional_result_text.insert(tk.END, f"\nLocation: {location}\n")
                        for item in os.listdir(location):
                            item_path = os.path.join(location, item)
                            if os.path.isfile(item_path):
                                self.additional_result_text.insert(tk.END, f"  {item}\n")
                            else:
                                self.additional_result_text.insert(tk.END, f"  [DIR] {item}\n")
            else:
                self.additional_result_text.insert(tk.END, "Startup program detection is Windows-specific.\n")
        except Exception as e:
            self.additional_result_text.insert(tk.END, f"Error viewing startup programs: {str(e)}\n")
    
    def check_running_processes(self):
        self.additional_result_text.delete(1.0, tk.END)
        self.additional_result_text.insert(tk.END, "Running Processes:\n")
        self.additional_result_text.insert(tk.END, "="*50 + "\n")
        
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by memory usage
            processes.sort(key=lambda x: x['memory_info'].rss if x['memory_info'] else 0, reverse=True)
            
            self.additional_result_text.insert(tk.END, f"{'PID':<8} {'Name':<25} {'Memory (MB)':<12} {'CPU %':<8}\n")
            self.additional_result_text.insert(tk.END, "-"*60 + "\n")
            
            for proc in processes[:20]:  # Show top 20 processes
                pid = proc['pid']
                name = proc['name'][:24]  # Truncate long names
                memory_mb = proc['memory_info'].rss / (1024 * 1024) if proc['memory_info'] else 0
                cpu_percent = proc['cpu_percent'] if proc['cpu_percent'] is not None else 0
                
                self.additional_result_text.insert(tk.END, 
                                                  f"{pid:<8} {name:<25} {memory_mb:<12.1f} {cpu_percent:<8.1f}\n")
        except Exception as e:
            self.additional_result_text.insert(tk.END, f"Error checking running processes: {str(e)}\n")
    
    def browse_dup_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dup_dir_var.set(directory)
    
    def browse_search_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.search_dir_var.set(directory)
    
    def start_find_duplicates(self):
        directory = self.dup_dir_var.get()
        if not directory:
            messagebox.showwarning("Warning", "Please select a directory to scan.")
            return
        
        # Run in a separate thread to prevent UI freezing
        thread = threading.Thread(target=self.find_duplicates, args=(directory,))
        thread.daemon = True
        thread.start()
    
    def find_duplicates(self, directory):
        def update_ui(results):
            self.dup_result_text.delete(1.0, tk.END)
            if results:
                for duplicate_pair in results:
                    # Get file sizes and modification dates for both files
                    try:
                        stat1 = os.stat(duplicate_pair[0])
                        stat2 = os.stat(duplicate_pair[1])
                        size1 = stat1.st_size
                        size2 = stat2.st_size
                        mtime1 = datetime.datetime.fromtimestamp(stat1.st_mtime)
                        mtime2 = datetime.datetime.fromtimestamp(stat2.st_mtime)
                        
                        self.dup_result_text.insert(tk.END, f"DUP GROUP [{len(results)} total]\n")
                        self.dup_result_text.insert(tk.END, f"FILE 1: {duplicate_pair[0]}\n")
                        self.dup_result_text.insert(tk.END, f"  SIZE: {size1} bytes | MODIFIED: {mtime1.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        self.dup_result_text.insert(tk.END, f"FILE 2: {duplicate_pair[1]}\n")
                        self.dup_result_text.insert(tk.END, f"  SIZE: {size2} bytes | MODIFIED: {mtime2.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    except:
                        self.dup_result_text.insert(tk.END, f"Duplicate found:\n")
                        self.dup_result_text.insert(tk.END, f"  {duplicate_pair[0]}\n")
                        self.dup_result_text.insert(tk.END, f"  {duplicate_pair[1]}\n\n")
            else:
                self.dup_result_text.insert(tk.END, "No duplicates found.\n")
        
        def calculate_hash(file_path):
            hash_md5 = hashlib.md5()
            try:
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                return hash_md5.hexdigest()
            except Exception as e:
                print(f"Error reading file {file_path}: {str(e)}")
                return None
        
        self.dup_result_text.insert(tk.END, f"Scanning {directory} for duplicates...\n")
        
        duplicates = []
        hash_dict = {}
        
        # Walk through all subdirectories
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Calculate hash of the file
                file_hash = calculate_hash(file_path)
                
                if file_hash:
                    if file_hash in hash_dict:
                        # Found a duplicate
                        duplicates.append((file_path, hash_dict[file_hash]))
                    else:
                        # Store the hash and file path
                        hash_dict[file_hash] = file_path
        
        # Update UI in the main thread
        self.root.after(0, update_ui, duplicates)
    
    def start_search_files(self):
        filename = self.search_name_var.get()
        directory = self.search_dir_var.get()
        
        if not filename:
            messagebox.showwarning("Warning", "Please enter a filename to search.")
            return
        if not directory:
            messagebox.showwarning("Warning", "Please select a directory to search in.")
            return
        
        # Run in a separate thread to prevent UI freezing
        thread = threading.Thread(target=self.search_files, args=(filename, directory))
        thread.daemon = True
        thread.start()
    
    def start_search_by_extension(self):
        extension = tk_simpledialog.askstring("Search by Extension", "Enter file extension (without dot):")
        if not extension:
            return
            
        directory = self.search_dir_var.get()
        if not directory:
            messagebox.showwarning("Warning", "Please select a directory to search in.")
            return
        
        # Run in a separate thread to prevent UI freezing
        thread = threading.Thread(target=self.search_by_extension, args=(extension, directory))
        thread.daemon = True
        thread.start()
    
    def search_files(self, filename, directory):
        def update_ui(results):
            self.search_result_text.delete(1.0, tk.END)
            if results:
                for file_path in results:
                    # Get file size and modification date
                    try:
                        stat = os.stat(file_path)
                        size = stat.st_size
                        mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
                        self.search_result_text.insert(tk.END, f"PATH: {file_path}\nSIZE: {size} bytes | MODIFIED: {mtime.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    except:
                        self.search_result_text.insert(tk.END, f"PATH: {file_path}\nSIZE: Unknown | MODIFIED: Unknown\n\n")
                self.search_result_text.insert(tk.END, f"\nFound {len(results)} file(s).\n")
            else:
                self.search_result_text.insert(tk.END, f"No files containing '{filename}' found in '{directory}'.\n")
        
        results = []
        
        self.search_result_text.insert(tk.END, f"Searching for '{filename}' in '{directory}'...\n")
        
        # Walk through all subdirectories
        for root, dirs, files in os.walk(directory):
            for file in files:
                if filename.lower() in file.lower():  # Case-insensitive partial match
                    file_path = os.path.join(root, file)
                    results.append(file_path)
        
        # Update UI in the main thread
        self.root.after(0, update_ui, results)
    
    def search_by_extension(self, extension, directory):
        def update_ui(results):
            self.search_result_text.delete(1.0, tk.END)
            if results:
                for file_path in results:
                    # Get file size and modification date
                    try:
                        stat = os.stat(file_path)
                        size = stat.st_size
                        mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
                        self.search_result_text.insert(tk.END, f"PATH: {file_path}\nSIZE: {size} bytes | MODIFIED: {mtime.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    except:
                        self.search_result_text.insert(tk.END, f"PATH: {file_path}\nSIZE: Unknown | MODIFIED: Unknown\n\n")
                self.search_result_text.insert(tk.END, f"\nFound {len(results)} file(s).\n")
            else:
                self.search_result_text.insert(tk.END, f"No files with extension '.{extension}' found in '{directory}'.\n")
        
        results = []
        
        # Ensure extension doesn't start with a dot
        if extension.startswith('.'):
            extension = extension[1:]
        
        self.search_result_text.insert(tk.END, f"Searching for files with extension '.{extension}' in '{directory}'...\n")
        
        # Walk through all subdirectories
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.lower().endswith(f'.{extension.lower()}'):
                    file_path = os.path.join(root, file)
                    results.append(file_path)
        
        # Update UI in the main thread
        self.root.after(0, update_ui, results)
    
    def start_clean_temp_files(self):
        thread = threading.Thread(target=self.clean_temp_files)
        thread.daemon = True
        thread.start()
    
    def clean_temp_files(self):
        def update_ui(cleaned_count):
            self.privacy_result_text.insert(tk.END, f"\nCleaned {cleaned_count} temporary files.\n")
        
        self.privacy_result_text.insert(tk.END, "Cleaning temporary files...\n")
        
        temp_dirs = [
            tempfile.gettempdir(),  # System temp directory
            os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Temp'),  # Windows temp
            os.path.expanduser('~/.cache'),  # User cache (Linux/Mac)
        ]
        
        cleaned_count = 0
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                for root, dirs, files in os.walk(temp_dir, topdown=False):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            # Check if file is older than 1 day
                            file_time = os.path.getctime(file_path)
                            file_date = datetime.datetime.fromtimestamp(file_time)
                            if datetime.datetime.now() - file_date > datetime.timedelta(days=1):
                                os.remove(file_path)
                                cleaned_count += 1
                                self.privacy_result_text.insert(tk.END, f"Removed: {file_path}\n")
                        except Exception as e:
                            self.privacy_result_text.insert(tk.END, f"Could not remove {file_path}: {str(e)}\n")
                    
                    # Remove empty directories
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        try:
                            if not os.listdir(dir_path):  # Directory is empty
                                os.rmdir(dir_path)
                                self.privacy_result_text.insert(tk.END, f"Removed empty directory: {dir_path}\n")
                        except Exception as e:
                            self.privacy_result_text.insert(tk.END, f"Could not remove directory {dir_path}: {str(e)}\n")
        
        # Update UI in the main thread
        self.root.after(0, update_ui, cleaned_count)
    
    def start_clean_recent_docs(self):
        thread = threading.Thread(target=self.clean_recent_documents)
        thread.daemon = True
        thread.start()
    
    def clean_recent_documents(self):
        def clean_recent_worker():
            self.privacy_result_text.insert(tk.END, "Cleaning recent documents...\n")
            
            recent_docs_path = os.path.join(os.environ['USERPROFILE'], 'Recent')
            
            if os.path.exists(recent_docs_path):
                try:
                    for item in os.listdir(recent_docs_path):
                        item_path = os.path.join(recent_docs_path, item)
                        if os.path.isfile(item_path):
                            os.remove(item_path)
                            self.root.after(0, lambda msg=f"Removed recent document: {item_path}\n": self.privacy_result_text.insert(tk.END, msg))
                        elif os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                            self.root.after(0, lambda msg=f"Removed recent folder: {item_path}\n": self.privacy_result_text.insert(tk.END, msg))
                            
                    self.root.after(0, lambda: self.privacy_result_text.insert(tk.END, "Recent documents cleared.\n"))
                except Exception as e:
                    self.root.after(0, lambda msg=f"Error cleaning recent documents: {str(e)}\n": self.privacy_result_text.insert(tk.END, msg))
            else:
                self.root.after(0, lambda: self.privacy_result_text.insert(tk.END, "Recent documents folder not found.\n"))
        
        # Run in a separate thread to prevent UI freezing
        thread = threading.Thread(target=clean_recent_worker)
        thread.daemon = True
        thread.start()
    
    def start_clean_browser_cache(self):
        thread = threading.Thread(target=self.clean_browser_cache)
        thread.daemon = True
        thread.start()
    
    def clean_browser_cache(self):
        def clean_browser_worker():
            self.privacy_result_text.insert(tk.END, "Cleaning browser cache...\n")
            
            browser_cache_paths = [
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Cache'),
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'),
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles'),
            ]
            
            cleaned_size = 0
            for cache_path in browser_cache_paths:
                if os.path.exists(cache_path):
                    for root, dirs, files in os.walk(cache_path, topdown=False):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                size = os.path.getsize(file_path)
                                os.remove(file_path)
                                cleaned_size += size
                                self.root.after(0, lambda msg=f"Removed cache file: {file_path}\n": self.privacy_result_text.insert(tk.END, msg))
                            except Exception as e:
                                self.root.after(0, lambda msg=f"Could not remove {file_path}: {str(e)}\n": self.privacy_result_text.insert(tk.END, msg))
            
            self.root.after(0, lambda msg=f"Browser cache cleaned. Freed approximately {cleaned_size / (1024*1024):.2f} MB.\n": self.privacy_result_text.insert(tk.END, msg))
        
        # Run in a separate thread to prevent UI freezing
        thread = threading.Thread(target=clean_browser_worker)
        thread.daemon = True
        thread.start()
    
    def start_clean_all_privacy(self):
        thread = threading.Thread(target=self.clean_all_privacy)
        thread.daemon = True
        thread.start()
    
    def clean_all_privacy(self):
        def clean_all_worker():
            self.privacy_result_text.insert(tk.END, "Starting comprehensive privacy cleanup...\n")
            # Run all cleaning operations
            self.start_clean_temp_files()
            self.start_clean_recent_docs()
            self.start_clean_browser_cache()
        
        # Run in a separate thread to prevent UI freezing
        thread = threading.Thread(target=clean_all_worker)
        thread.daemon = True
        thread.start()
    
    def refresh_packages(self):
        def load_packages():
            try:
                packages_info = []
                installed_packages = list(distributions())
                for package in sorted(installed_packages, key=lambda x: x.metadata['Name'].lower()):
                    name = package.metadata['Name']
                    version = package.metadata['Version']
                    packages_info.append(f"{name} ({version})")
                
                # Update UI in the main thread
                self.root.after(0, update_pkg_list, packages_info)
            except Exception as e:
                # Update UI in the main thread
                self.root.after(0, show_error, str(e))
        
        def update_pkg_list(packages_info):
            self.pkg_listbox.delete(0, tk.END)
            for pkg_info in packages_info:
                self.pkg_listbox.insert(tk.END, pkg_info)
        
        def show_error(error_msg):
            self.pkg_result_text.insert(tk.END, f"Error loading packages: {error_msg}\n")
        
        # Run in a separate thread to prevent UI freezing
        thread = threading.Thread(target=load_packages)
        thread.daemon = True
        thread.start()
    
    def install_package_dialog(self):
        package_name = tk_simpledialog.askstring("Install Package", "Enter package name to install:")
        if package_name:
            thread = threading.Thread(target=self.install_package, args=(package_name,))
            thread.daemon = True
            thread.start()
    
    def install_package(self, package_name):
        self.pkg_result_text.insert(tk.END, f"Installing {package_name}...\n")
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "install", package_name],
                                   capture_output=True, text=True, check=True)
            self.pkg_result_text.insert(tk.END, f"Successfully installed {package_name}\n")
            # Refresh the package list after installation
            self.root.after(1000, self.refresh_packages)  # Wait a bit before refreshing
        except subprocess.CalledProcessError as e:
            self.pkg_result_text.insert(tk.END, f"Error installing {package_name}: {e.stderr}\n")
        except Exception as e:
            self.pkg_result_text.insert(tk.END, f"Unexpected error occurred: {str(e)}\n")
    
    def uninstall_package_dialog(self):
        package_name = tk_simpledialog.askstring("Uninstall Package", "Enter package name to uninstall:")
        if package_name:
            confirm = messagebox.askyesno("Confirm", f"Are you sure you want to uninstall {package_name}?")
            if confirm:
                thread = threading.Thread(target=self.uninstall_package, args=(package_name,))
                thread.daemon = True
                thread.start()
    
    def uninstall_package(self, package_name):
        self.pkg_result_text.insert(tk.END, f"Uninstalling {package_name}...\n")
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", package_name],
                                   capture_output=True, text=True, check=True)
            self.pkg_result_text.insert(tk.END, f"Successfully uninstalled {package_name}\n")
            # Refresh the package list after uninstallation
            self.root.after(1000, self.refresh_packages)  # Wait a bit before refreshing
        except subprocess.CalledProcessError as e:
            self.pkg_result_text.insert(tk.END, f"Error uninstalling {package_name}: {e.stderr}\n")
        except Exception as e:
            self.pkg_result_text.insert(tk.END, f"Unexpected error occurred: {str(e)}\n")
    
    def upgrade_package_dialog(self):
        package_name = tk_simpledialog.askstring("Upgrade Package", "Enter package name to upgrade:")
        if package_name:
            thread = threading.Thread(target=self.upgrade_package, args=(package_name,))
            thread.daemon = True
            thread.start()
    
    def upgrade_package(self, package_name):
        self.pkg_result_text.insert(tk.END, f"Upgrading {package_name}...\n")
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", package_name],
                                   capture_output=True, text=True, check=True)
            self.pkg_result_text.insert(tk.END, f"Successfully upgraded {package_name}\n")
            # Refresh the package list after upgrade
            self.root.after(1000, self.refresh_packages)  # Wait a bit before refreshing
        except subprocess.CalledProcessError as e:
            self.pkg_result_text.insert(tk.END, f"Error upgrading {package_name}: {e.stderr}\n")
        except Exception as e:
            self.pkg_result_text.insert(tk.END, f"Unexpected error occurred: {str(e)}\n")
    
    def start_upgrade_pip(self):
        thread = threading.Thread(target=self.upgrade_pip)
        thread.daemon = True
        thread.start()
    
    def upgrade_pip(self):
        self.pkg_result_text.insert(tk.END, "Upgrading pip...\n")
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
                                   capture_output=True, text=True, check=True)
            self.pkg_result_text.insert(tk.END, "Successfully upgraded pip\n")
        except subprocess.CalledProcessError as e:
            self.pkg_result_text.insert(tk.END, f"Error upgrading pip: {e.stderr}\n")
        except Exception as e:
            self.pkg_result_text.insert(tk.END, f"Unexpected error occurred: {str(e)}\n")
    
    def start_full_cleanup(self):
        thread = threading.Thread(target=self.full_system_cleanup)
        thread.daemon = True
        thread.start()
    
    def full_system_cleanup(self):
        def full_cleanup_worker():
            self.system_result_text.insert(tk.END, "Starting system cleanup...\n")
            
            # Clean temp files
            temp_cleaned = self._clean_temp_directories()
            
            # Clean log files
            logs_cleaned = self._clean_log_files()
            
            # Show disk usage after cleanup
            self.root.after(0, self.show_disk_usage)
            
            total_cleaned = temp_cleaned + logs_cleaned
            self.system_result_text.insert(tk.END, f"\nSystem cleanup completed. Total items cleaned: {total_cleaned}\n")
        
        # Run in a separate thread to prevent UI freezing
        thread = threading.Thread(target=full_cleanup_worker)
        thread.daemon = True
        thread.start()
    
    def _clean_temp_directories(self):
        def clean_temp_worker():
            self.system_result_text.insert(tk.END, "Cleaning temporary directories...\n")
            
            temp_dirs = [
                os.path.join(os.environ['WINDIR'], 'Temp'),  # Windows temp
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Temp'),  # User temp
                tempfile.gettempdir(),  # Python's temp dir
            ]
            
            cleaned_count = 0
            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    for root, dirs, files in os.walk(temp_dir, topdown=False):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                # Check if file is older than 7 days
                                file_time = os.path.getctime(file_path)
                                file_date = datetime.datetime.fromtimestamp(file_time)
                                if datetime.datetime.now() - file_date > datetime.timedelta(days=7):
                                    os.remove(file_path)
                                    cleaned_count += 1
                                    # Note: Since this is already called from the main thread in full_system_cleanup,
                                    # we don't need to use root.after here
                            except Exception:
                                # Skip files that can't be removed (in use, permissions, etc.)
                                continue
                        
                        # Remove empty directories
                        for dir_name in dirs:
                            dir_path = os.path.join(root, dir_name)
                            try:
                                if not os.listdir(dir_path):  # Directory is empty
                                    os.rmdir(dir_path)
                            except Exception:
                                # Skip directories that can't be removed
                                continue
            
            self.system_result_text.insert(tk.END, f"Cleaned {cleaned_count} temporary files.\n")
            return cleaned_count
        
        # Call the worker function directly since this is called from the main thread in full_system_cleanup
        return clean_temp_worker()
    
    def _clean_log_files(self):
        def clean_log_worker():
            self.system_result_text.insert(tk.END, "Cleaning log files...\n")
            
            log_extensions = ['.log', '.txt']
            log_locations = [
                os.path.join(os.environ['WINDIR'], 'Logs'),
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local'),
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming'),
            ]
            
            cleaned_count = 0
            for location in log_locations:
                if os.path.exists(location):
                    for root, dirs, files in os.walk(location):
                        for file in files:
                            if any(file.lower().endswith(ext) for ext in log_extensions):
                                file_path = os.path.join(root, file)
                                try:
                                    # Only remove logs older than 30 days
                                    file_time = os.path.getctime(file_path)
                                    file_date = datetime.datetime.fromtimestamp(file_time)
                                    if datetime.datetime.now() - file_date > datetime.timedelta(days=30):
                                        os.remove(file_path)
                                        cleaned_count += 1
                                except Exception:
                                    # Skip files that can't be removed
                                    continue
            
            self.system_result_text.insert(tk.END, f"Cleaned {cleaned_count} log files.\n")
            return cleaned_count
        
        # Call the worker function directly since this is called from the main thread in full_system_cleanup
        return clean_log_worker()
    
    def show_disk_usage(self):
        self.system_result_text.insert(tk.END, "\nDisk Usage Information:\n")
        self.system_result_text.insert(tk.END, "-" * 30 + "\n")
        
        # Get disk usage for the main drive
        try:
            disk_usage = psutil.disk_usage('/')
            total = disk_usage.total / (1024**3)  # Convert to GB
            used = disk_usage.used / (1024**3)
            free = disk_usage.free / (1024**3)
            
            self.system_result_text.insert(tk.END, f"Total space: {total:.2f} GB\n")
            self.system_result_text.insert(tk.END, f"Used space: {used:.2f} GB\n")
            self.system_result_text.insert(tk.END, f"Free space: {free:.2f} GB\n")
        except:
            self.system_result_text.insert(tk.END, "Could not retrieve disk usage information.\n")


def main():
    root = tk.Tk()
    app = SystemUtilityApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
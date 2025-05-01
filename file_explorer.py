import os
import math
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.font import Font
from datetime import datetime
import ctypes
from cryptography.fernet import Fernet
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import getpass
import shutil
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64

class FileMonitorEventHandler(FileSystemEventHandler):
    def __init__(self, gui):
        super().__init__()
        self.gui = gui
        self.log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "file_monitor_logs"))
        self.current_user = getpass.getuser()  # Get current username
    
    def should_ignore(self, path):
        """Check if the path should be ignored (in our log directory)"""
        abs_path = os.path.abspath(path)
        return abs_path.startswith(self.log_dir)
    
    def log_action(self, action, path, dest_path=None):
        """Centralized logging with user and timestamp"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        user = self.current_user
        if dest_path:
            message = f"[{timestamp}] User: {user} | {action}: {path} -> {dest_path}"
        else:
            message = f"[{timestamp}] User: {user} | {action}: {path}"
        self.gui.log_file_event(message, action.lower())
    
    def on_created(self, event):
        if not self.should_ignore(event.src_path):
            self.log_action("CREATED", event.src_path)
    
    def on_deleted(self, event):
        if not self.should_ignore(event.src_path):
            self.log_action("DELETED", event.src_path)
    
    def on_modified(self, event):
        if not self.should_ignore(event.src_path):
            self.log_action("MODIFIED", event.src_path)
    
    def on_moved(self, event):
        if not self.should_ignore(event.src_path) and (not hasattr(event, 'dest_path') or not self.should_ignore(event.dest_path)):
            self.log_action("MOVED", event.src_path, event.dest_path)

class FileExplorer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Explorer")
        self.geometry("1000x700")
        self.configure(bg="#f5f5f5")
        self.minsize(900, 600)

        # Custom color scheme
        self.bg_color = "#f5f5f5"
        self.primary_color = "#4b6eaf"
        self.secondary_color = "#3a5a8f"
        self.text_color = "#333333"
        self.light_text = "#777777"
        self.highlight_color = "#e1e8f0"

        # Security tools setup
        self.key_file = "encryption_key.key"
        self.key = self.load_or_generate_key()
        self.metadata_file = "folder_metadata.json"
        self.metadata = self.load_metadata()
        self.load_or_generate_metadata_keys()
        
        # Navigation history
        self.history = []
        self.history_index = -1
        
        # File monitoring variables
        self.monitoring = False
        self.observer = None
        self.monitor_path = os.path.expanduser("~")
        self.log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "file_monitor_logs")
        
        # Create log directory if it doesn't exist
        if not os.path.exists(self.log_file_path):
            os.makedirs(self.log_file_path)
        
        # Current log file
        self.current_log_file = os.path.join(
            self.log_file_path,
            f"file_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )

        # Custom fonts
        self.title_font = Font(family="Segoe UI", size=11, weight="bold")
        self.main_font = Font(family="Segoe UI", size=10)
        self.small_font = Font(family="Segoe UI", size=9)
        
        self.current_path = os.path.expanduser("~")

        # Initialize styles
        self.style = ttk.Style()
        self.style.theme_use('alt')
        self.configure_styles()

        # Path and status variables
        self.path_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="ALL")
        self.filter_action_var = tk.StringVar(value="ALL")
        self.filter_user_var = tk.StringVar()

        # Create widgets
        self.create_widgets()
        self.create_monitor_tab()
        self.load_files(self.current_path, add_to_history=True)

        # Keyboard shortcuts
        self.bind("<BackSpace>", lambda e: self.go_up())
        self.bind("<Control-b>", lambda e: self.go_back())
        self.bind("<Control-f>", lambda e: self.go_forward())
        self.bind("<Control-h>", lambda e: self.go_home())
        self.bind("<F5>", lambda e: self.refresh_directory())
        self.bind("<Control-d>", lambda e: self.show_drives())

    def load_or_generate_key(self):
        """Load encryption key from file or generate a new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            return key

    def load_or_generate_metadata_keys(self):
        """Load or generate RSA keys for metadata signing"""
        self.private_key_file = "private_key.pem"
        self.public_key_file = "public_key.pem"
        self.key_password = b"mysecurepassword"
        
        if os.path.exists(self.private_key_file) and os.path.exists(self.public_key_file):
            try:
                with open(self.private_key_file, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=self.key_password,
                        backend=default_backend()
                    )
                with open(self.public_key_file, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )
            except Exception as e:
                self.generate_metadata_keys()
        else:
            self.generate_metadata_keys()

    def generate_metadata_keys(self):
        """Generate new RSA key pair for metadata signing"""
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            # Save private key
            pem_private = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(self.key_password)
            )
            with open(self.private_key_file, "wb") as f:
                f.write(pem_private)
            
            # Save public key
            pem_public = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(self.public_key_file, "wb") as f:
                f.write(pem_public)
        except Exception as e:
            messagebox.showerror("Key Generation Error", f"Failed to generate keys: {str(e)}")

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file contents"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            return None

    def sign_file(self, file_path):
        """Create digital signature for a file"""
        file_hash = self.calculate_file_hash(file_path)
        if not file_hash:
            return None
            
        try:
            signature = self.private_key.sign(
                file_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return base64.b64encode(signature).decode()
        except Exception:
            return None

    def verify_signature(self, file_path, signature_b64):
        """Verify a file's digital signature"""
        file_hash = self.calculate_file_hash(file_path)
        if not file_hash:
            return False
            
        try:
            signature = base64.b64decode(signature_b64)
            self.public_key.verify(
                signature,
                file_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def load_metadata(self):
        """Load metadata from JSON file"""
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_metadata(self):
        """Save metadata to JSON file"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception:
            pass

    def batch_settings_popup(self):
        """Popup for batch metadata settings that supports folders"""
        selected_paths = self.get_selected_paths()
        if not selected_paths:
            messagebox.showwarning("No Selection", "Please select files or folders first")
            return
        
        # Get all files from selected paths (including files in selected folders)
        file_paths = []
        for path in selected_paths:
            if os.path.isfile(path):
                file_paths.append(path)
            elif os.path.isdir(path):
                # Recursively get all files in the directory
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_paths.append(file_path)
        
        if not file_paths:
            messagebox.showwarning("No Files", "No files found in selected items")
            return
        
        popup = tk.Toplevel(self)
        popup.title("Add Dataset")
        popup.geometry("500x600")  # Reduced height since we removed some fields
        
        # Main frame with scrollbar
        main_frame = ttk.Frame(popup)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Display selected items count
        ttk.Label(scrollable_frame, 
                text=f"Selected: {len(selected_paths)} items ({len(file_paths)} files)").pack(pady=(5, 10))
        
        # Dataset Name
        ttk.Label(scrollable_frame, text="Dataset Name:").pack(pady=(5, 0), anchor=tk.W)
        dataset_entry = ttk.Entry(scrollable_frame, width=50)
        dataset_entry.pack(anchor=tk.W)
        
        # Sensitivity Level
        ttk.Label(scrollable_frame, text="Sensitivity Level:").pack(pady=(5, 0), anchor=tk.W)
        sensitivity_var = tk.StringVar(value="Medium")
        ttk.OptionMenu(
            scrollable_frame, sensitivity_var, "Medium",
            "Low", "Medium", "High", "Critical"
        ).pack(anchor=tk.W)
        
        # Tags
        ttk.Label(scrollable_frame, text="Tags (comma separated):").pack(pady=(5, 0), anchor=tk.W)
        tags_entry = ttk.Entry(scrollable_frame, width=50)
        tags_entry.pack(anchor=tk.W)
        
        # Signing checkbox (checked by default)
        sign_var = tk.BooleanVar(value=True)  # Default to checked
        ttk.Checkbutton(
            scrollable_frame, 
            text="Digitally sign files", 
            variable=sign_var
        ).pack(pady=10, anchor=tk.W)
        
        # Encryption checkbox (checked by default)
        encrypt_var = tk.BooleanVar(value=True)  # Default to checked
        ttk.Checkbutton(
            scrollable_frame,
            text="Encrypt file contents",
            variable=encrypt_var
        ).pack(pady=5, anchor=tk.W)
        
        def apply_batch():
            """Apply batch settings to selected files"""
            if encrypt_var.get() and not self.key:
                messagebox.showerror("Error", "No encryption key available")
                return
            
            meta = {
                "dataset_name": dataset_entry.get(),
                "sensitivity": sensitivity_var.get(),
                "tags": [t.strip() for t in tags_entry.get().split(",") if t.strip()],
                "last_modified": datetime.now().isoformat(),
                "encrypted": encrypt_var.get()
            }
            
            count = 0
            success_count = 0
            for file_path in file_paths:
                try:
                    # Encrypt file if requested
                    if encrypt_var.get():
                        cipher = Fernet(self.key)
                        with open(file_path, "rb") as f:
                            data = f.read()
                        encrypted = cipher.encrypt(data)
                        with open(file_path, "wb") as f:
                            f.write(encrypted)
                    
                    if sign_var.get():
                        signature = self.sign_file(file_path)
                        if signature:
                            meta["signature"] = signature
                            meta["integrity_hash"] = self.calculate_file_hash(file_path)
                            meta["file_size"] = os.path.getsize(file_path)
                    
                    self.metadata[file_path] = meta.copy()
                    count += 1
                    success_count += 1
                except Exception as e:
                    print(f"Error processing {file_path}: {str(e)}")
                    continue
            
            self.save_metadata()
            self.refresh_directory()
            popup.destroy()
            messagebox.showinfo("Complete", 
                            f"Processed {success_count} of {len(file_paths)} files\n"
                            f"Encryption: {'Yes' if encrypt_var.get() else 'No'}\n"
                            f"Signing: {'Yes' if sign_var.get() else 'No'}")
        
        ttk.Button(
            scrollable_frame, 
            text="Apply", 
            command=apply_batch
        ).pack(pady=10)

    def configure_styles(self):
        """Configure ttk styles for a modern look"""
        # Main styles
        self.style.configure('.', background=self.bg_color, foreground=self.text_color)
        
        # Treeview styles
        self.style.configure('Treeview', 
                            font=self.main_font, 
                            rowheight=28,
                            background="#ffffff",
                            fieldbackground="#ffffff",
                            foreground=self.text_color,
                            bordercolor="#dddddd",
                            borderwidth=1)
        
        self.style.configure('Treeview.Heading', 
                            font=self.title_font,
                            background=self.primary_color,
                            foreground="white",
                            padding=8,
                            relief=tk.FLAT)
        
        self.style.map('Treeview.Heading',
                      background=[('active', self.secondary_color)])
        
        # Button styles
        self.style.configure('TButton', 
                            font=self.main_font,
                            padding=8,
                            relief=tk.FLAT,
                            background=self.primary_color,
                            foreground="white")
        
        self.style.map('TButton',
                      background=[('active', self.secondary_color)],
                      relief=[('pressed', 'sunken')])
        
        # Disabled button style
        self.style.configure('Disabled.TButton', 
                           background="#e0e0e0",
                           foreground="#999999")
        
        # Entry styles
        self.style.configure('TEntry',
                            font=self.main_font,
                            padding=5,
                            relief=tk.SOLID,
                            bordercolor="#cccccc",
                            lightcolor="#ffffff",
                            darkcolor="#ffffff")
        
        # Label styles
        self.style.configure('TLabel',
                            font=self.main_font,
                            background=self.bg_color,
                            foreground=self.text_color)
        
        # Status bar style
        self.style.configure('Status.TLabel',
                            font=self.small_font,
                            background="#e0e0e0",
                            foreground="#555555",
                            padding=5)
        
        # Alert button style
        self.style.configure('Alert.TButton', 
                           background="#ff6b6b",
                           foreground="white")
        self.style.map('Alert.TButton',
                      background=[('active', '#ff5252')])

    def create_widgets(self):
        """Create all GUI widgets with improved layout"""
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create main file explorer frame as first tab
        main_frame = ttk.Frame(self.notebook)
        self.notebook.add(main_frame, text="📁 File Explorer")
        
        # Top navigation bar
        nav_frame = tk.Frame(main_frame, bg=self.bg_color)
        nav_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Navigation buttons with improved spacing
        btn_frame = tk.Frame(nav_frame, bg=self.bg_color)
        btn_frame.pack(side=tk.LEFT, padx=(0, 10))
        
        self.back_btn = ttk.Button(btn_frame, text="←", command=self.go_back, 
                                 style='TButton', width=3)
        self.back_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.forward_btn = ttk.Button(btn_frame, text="→", command=self.go_forward,
                                    style='TButton', width=3)
        self.forward_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="↻", command=self.refresh_directory,
                  style='TButton', width=3).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="🏠", command=self.go_home,
                  style='TButton', width=3).pack(side=tk.LEFT, padx=5)
        
        # Drive selection button
        ttk.Button(btn_frame, text="💾", command=self.show_drives,
                  style='TButton', width=3).pack(side=tk.LEFT, padx=5)
        
        # Path entry with improved styling
        path_frame = tk.Frame(nav_frame, bg=self.bg_color)
        path_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(path_frame, text="Path:", style='TLabel').pack(side=tk.LEFT, padx=(0, 5))
        
        path_entry = ttk.Entry(path_frame, textvariable=self.path_var, 
                             font=self.main_font, style='TEntry')
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        path_entry.bind("<Return>", self.on_path_entered)
        
        # Search bar
        search_frame = tk.Frame(nav_frame, bg=self.bg_color)
        search_frame.pack(side=tk.RIGHT, padx=(10, 0))
        
        ttk.Label(search_frame, text="Search:", style='TLabel').pack(side=tk.LEFT, padx=(0, 5))
        
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, 
                               font=self.main_font, style='TEntry', width=20)
        search_entry.pack(side=tk.LEFT)
        search_entry.bind("<KeyRelease>", self.filter_files)
        
        # Treeview with improved scrollbars
        tree_frame = tk.Frame(main_frame, bg=self.bg_color)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Vertical scrollbar
        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Horizontal scrollbar
        x_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Treeview with improved columns
        self.tree = ttk.Treeview(tree_frame, 
                                columns=("Name", "Type", "Size", "Modified"), 
                                show='headings',
                                yscrollcommand=y_scroll.set,
                                xscrollcommand=x_scroll.set,
                                selectmode='browse')
        
        # Configure columns with better widths
        self.tree.heading("Name", text="📄 Name", anchor=tk.W)
        self.tree.heading("Type", text="📁 Type", anchor=tk.W)
        self.tree.heading("Size", text="📦 Size", anchor=tk.W)
        self.tree.heading("Modified", text="🕒 Modified", anchor=tk.W)
        
        self.tree.column("Name", width=400, anchor=tk.W)
        self.tree.column("Type", width=150, anchor=tk.W)
        self.tree.column("Size", width=120, anchor=tk.W)
        self.tree.column("Modified", width=200, anchor=tk.W)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.on_item_double_click)
        
        # Configure scrollbars
        y_scroll.config(command=self.tree.yview)
        x_scroll.config(command=self.tree.xview)
        
        # Add hover effect
        self.tree.bind("<Motion>", self.on_tree_hover)
        
        # Status bar with improved styling
        status_frame = tk.Frame(main_frame, bg="#e0e0e0", height=24)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var,
                                    style='Status.TLabel')
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Enhanced context menu with security options
        self.context_menu = tk.Menu(self, tearoff=0, 
                                   font=self.main_font,
                                   bg="white",
                                   fg=self.text_color,
                                   activebackground=self.highlight_color,
                                   activeforeground=self.text_color,
                                   bd=1)
        
        self.context_menu.add_command(label="Open", command=self.open_selected)
        self.context_menu.add_command(label="Open in File Explorer", 
                                    command=self.open_in_explorer)
        self.context_menu.add_separator()
        
        # Security submenu
        security_menu = tk.Menu(self.context_menu, tearoff=0)
        security_menu.add_command(label="🔒 Encrypt", command=self.encrypt_selected)
        security_menu.add_command(label="🔓 Decrypt", command=self.decrypt_selected)
        security_menu.add_command(label="🔄 Backup", command=self.backup)
        security_menu.add_command(label="🔍 Deep Scan", command=self.deep_scan_selected)
        security_menu.add_command(label="📁 Add Dataset", command=self.batch_settings_popup)
        self.context_menu.add_cascade(label="Security Tools", menu=security_menu)
        
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Path", 
                                    command=self.copy_path)
        self.context_menu.add_command(label="Refresh", 
                                    command=self.refresh_directory)
        
        self.tree.bind("<Button-3>", self.show_context_menu)

    def create_monitor_tab(self):
        """Create the file monitoring tab with directory selection"""
        monitor_tab = ttk.Frame(self.notebook)
        self.notebook.add(monitor_tab, text="🔍 File Monitor")
        
        # Path selection frame
        path_frame = ttk.LabelFrame(monitor_tab, text="Monitor Directory")
        path_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Label(path_frame, text="Directory:").pack(side="left", padx=5)
        
        self.monitor_path_entry = ttk.Entry(path_frame, width=50)
        self.monitor_path_entry.insert(0, self.monitor_path)
        self.monitor_path_entry.pack(side="left", expand=True, fill="x", padx=5)
        
        browse_btn = ttk.Button(path_frame, text="Browse", command=self.browse_monitor_dir)
        browse_btn.pack(side="left", padx=5)
        
        # Filter controls frame
        filter_frame = ttk.LabelFrame(monitor_tab, text="Log Filters")
        filter_frame.pack(pady=5, padx=10, fill="x")
        
        ttk.Label(filter_frame, text="Filter by action:").pack(side="left", padx=5)
        
        # Action filter dropdown
        self.filter_action_var = tk.StringVar()
        self.filter_action_var.set("ALL")  # Default show all
        filter_dropdown = ttk.Combobox(
            filter_frame,
            textvariable=self.filter_action_var,
            values=["ALL", "CREATED", "MODIFIED", "DELETED", "MOVED"],
            state="readonly",
            width=12
        )
        filter_dropdown.pack(side="left", padx=5)
        filter_dropdown.bind("<<ComboboxSelected>>", self.apply_log_filters)
        
        # User filter entry
        ttk.Label(filter_frame, text="Filter by user:").pack(side="left", padx=5)
        self.filter_user_var = tk.StringVar()
        user_entry = ttk.Entry(filter_frame, textvariable=self.filter_user_var, width=15)
        user_entry.pack(side="left", padx=5)
        
        # Apply filters button
        ttk.Button(filter_frame, text="Apply Filters", 
                  command=self.apply_log_filters).pack(side="left", padx=5)
        
        # Clear filters button
        ttk.Button(filter_frame, text="Clear Filters", 
                  command=self.clear_log_filters).pack(side="left", padx=5)
        
        # Log management frame
        log_manage_frame = ttk.Frame(monitor_tab)
        log_manage_frame.pack(pady=5, fill="x")
        
        ttk.Button(log_manage_frame, text="View Log History", 
                  command=self.view_log_history).pack(side="left", padx=5)
        ttk.Button(log_manage_frame, text="Open Current Log", 
                  command=self.open_current_log).pack(side="left", padx=5)
        
        # Control buttons frame
        control_frame = ttk.Frame(monitor_tab)
        control_frame.pack(pady=5, fill="x")
        
        self.start_monitor_btn = ttk.Button(control_frame, text="Start Monitoring", 
                                          command=self.start_file_monitoring)
        self.start_monitor_btn.pack(side="left", padx=5)
        
        self.stop_monitor_btn = ttk.Button(control_frame, text="Stop Monitoring", 
                                         command=self.stop_file_monitoring, state="disabled")
        self.stop_monitor_btn.pack(side="left", padx=5)
        
        # Log frame
        log_frame = ttk.LabelFrame(monitor_tab, text="File Activity Log")
        log_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.monitor_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=80, height=20)
        self.monitor_log.pack(pady=5, padx=5, fill="both", expand=True)
        
        # Configure tags for different message types
        self.monitor_log.tag_config("created", foreground="blue")
        self.monitor_log.tag_config("deleted", foreground="red")
        self.monitor_log.tag_config("modified", foreground="orange")
        self.monitor_log.tag_config("moved", foreground="green")
        
        self.monitor_log.insert(tk.END, "File monitoring log will appear here...\n")
        self.monitor_log.config(state=tk.DISABLED)

    def browse_monitor_dir(self):
        directory = filedialog.askdirectory(initialdir=self.monitor_path)
        if directory:
            self.monitor_path = directory
            self.monitor_path_entry.delete(0, tk.END)
            self.monitor_path_entry.insert(0, directory)
            # Restart monitoring with new directory
            self.stop_file_monitoring()
            self.start_file_monitoring()

    def apply_log_filters(self, event=None):
        """Apply the selected filters to the log display"""
        action_filter = self.filter_action_var.get()
        user_filter = self.filter_user_var.get().strip().lower()
        
        # Store the current scroll position
        scroll_position = self.monitor_log.yview()
        
        # Get all log content from the file, not just what's displayed
        try:
            with open(self.current_log_file, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
        except Exception as e:
            print(f"Error reading log file: {e}")
            return
        
        # Clear and repopulate with filtered content
        self.monitor_log.config(state=tk.NORMAL)  # Enable editing
        self.monitor_log.delete(1.0, tk.END)
        
        for line in all_lines:
            if not line.strip():
                continue
                
            include = True
            
            # Apply action filter
            if action_filter != "ALL":
                if not any([
                    f"| {action_filter}:" in line,
                    line.startswith('[') and action_filter == "ALL"
                ]):
                    include = False
            
            # Apply user filter
            if user_filter:
                if f"user: {user_filter}" not in line.lower():
                    include = False
            
            if include:
                # Determine the tag based on action type
                if "| created:" in line.lower():
                    tag = "created"
                elif "| deleted:" in line.lower():
                    tag = "deleted"
                elif "| modified:" in line.lower():
                    tag = "modified"
                elif "| moved:" in line.lower():
                    tag = "moved"
                else:
                    tag = ""
                
                self.monitor_log.insert(tk.END, line, tag)
        
        # Restore scroll position
        self.monitor_log.yview_moveto(scroll_position[0])
        self.monitor_log.config(state=tk.DISABLED)  # Disable editing

    def clear_log_filters(self):
        """Clear all filters and show full log"""
        self.filter_action_var.set("ALL")
        self.filter_user_var.set("")
        self.apply_log_filters()

    def log_file_event(self, message, event_type=""):
        """Log file event to both the GUI and the log file"""
        # Write to log file
        try:
            with open(self.current_log_file, "a", encoding="utf-8") as f:
                f.write(message + '\n')
        except Exception as e:
            print(f"Error writing to log file: {e}")
        
        # Apply current filters to determine if we should display
        action_filter = self.filter_action_var.get()
        user_filter = self.filter_user_var.get().strip().lower()
        
        include = True
        if action_filter != "ALL" and f"| {action_filter}:" not in message:
            include = False
        if user_filter and f"user: {user_filter}" not in message.lower():
            include = False
        
        if include:
            # Determine the tag based on action type
            if "| created:" in message.lower():
                tag = "created"
            elif "| deleted:" in message.lower():
                tag = "deleted"
            elif "| modified:" in message.lower():
                tag = "modified"
            elif "| moved:" in message.lower():
                tag = "moved"
            else:
                tag = ""
            
            self.monitor_log.config(state=tk.NORMAL)
            self.monitor_log.insert(tk.END, message + '\n', tag)
            self.monitor_log.see(tk.END)
            self.monitor_log.config(state=tk.DISABLED)
            self.monitor_log.update()

    def view_log_history(self):
        """Open a window showing available log files"""
        history_window = tk.Toplevel(self)
        history_window.title("File Monitor Log History")
        history_window.geometry("600x400")
        
        # List of log files
        log_files = []
        if os.path.exists(self.log_file_path):
            log_files = sorted(
                [f for f in os.listdir(self.log_file_path) if f.endswith(".log")],
                reverse=True
            )
        
        if not log_files:
            tk.Label(history_window, text="No log files found").pack(pady=20)
            return
        
        # Listbox with scrollbar
        frame = tk.Frame(history_window)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set)
        listbox.pack(fill=tk.BOTH, expand=True)
        
        scrollbar.config(command=listbox.yview)
        
        for log_file in log_files:
            listbox.insert(tk.END, log_file)
        
        # View button
        def view_selected_log():
            selection = listbox.curselection()
            if selection:
                selected_file = os.path.join(self.log_file_path, listbox.get(selection[0]))
                self.display_log_file(selected_file)
        
        button_frame = tk.Frame(history_window)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="View Selected Log", 
                 command=view_selected_log).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Delete Selected Log", 
                 command=lambda: self.delete_log_file(listbox)).pack(side=tk.LEFT, padx=5)

    def display_log_file(self, file_path):
        """Display the contents of a log file in a new window"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            log_window = tk.Toplevel(self)
            log_window.title(f"Log File: {os.path.basename(file_path)}")
            log_window.geometry("800x600")
            
            text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
            text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            text.insert(tk.END, content)
            text.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not read log file: {e}")

    def delete_log_file(self, listbox):
        """Delete the selected log file"""
        selection = listbox.curselection()
        if not selection:
            return
            
        file_name = listbox.get(selection[0])
        file_path = os.path.join(self.log_file_path, file_name)
        
        try:
            os.remove(file_path)
            listbox.delete(selection[0])
            messagebox.showinfo("Success", f"Deleted log file: {file_name}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete file: {e}")

    def open_current_log(self):
        """Open the current log file in the default text editor"""
        try:
            if os.path.exists(self.current_log_file):
                os.startfile(self.current_log_file)
            else:
                messagebox.showinfo("Info", "No log entries yet in current session")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open log file: {e}")

    def start_file_monitoring(self):
        path = self.monitor_path_entry.get().strip() if self.monitor_path_entry else self.monitor_path
        
        if not path:
            self.log_file_event("Error: No directory specified", "error")
            return
            
        if not os.path.isdir(path):
            self.log_file_event(f"Error: Directory not found - {path}", "error")
            return
            
        if self.monitoring:
            self.stop_file_monitoring()
        
        # Create new log file for this monitoring session
        self.current_log_file = os.path.join(
            self.log_file_path,
            f"file_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        
        self.event_handler = FileMonitorEventHandler(self)
        self.observer = Observer()
        
        try:
            self.observer.schedule(self.event_handler, path, recursive=True)
            self.observer.start()
            self.monitoring = True
            self.start_monitor_btn.config(state="disabled")
            self.stop_monitor_btn.config(state="normal")
            self.log_file_event(f"Started monitoring directory: {path}", "info")
            self.log_file_event("Watching for file changes...", "info")
        except Exception as e:
            self.log_file_event(f"Error starting monitor: {str(e)}", "error")

    def stop_file_monitoring(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join()
                self.log_file_event("Monitoring stopped", "info")
            except Exception as e:
                self.log_file_event(f"Error stopping monitor: {str(e)}", "error")
            finally:
                self.observer = None
                
        self.monitoring = False
        self.start_monitor_btn.config(state="normal")
        self.stop_monitor_btn.config(state="disabled")

    def get_available_drives(self):
        """Get all available drives on the system"""
        if os.name == 'nt':  # Windows
            drives = []
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                if bitmask & 1:
                    drives.append(f"{letter}:\\")
                bitmask >>= 1
            return drives
        else:  # Linux/Mac
            return ["/"]  # Just return root for non-Windows systems

    def show_drives(self):
        """Show available drives in a popup menu"""
        drives = self.get_available_drives()
        
        # Create drives menu
        drives_menu = tk.Menu(self, tearoff=0, 
                             font=self.main_font,
                             bg="white",
                             fg=self.text_color,
                             activebackground=self.highlight_color,
                             activeforeground=self.text_color)
        
        for drive in drives:
            # Get drive label if available
            try:
                if os.name == 'nt':
                    drive_name = f"Local Disk ({drive[:-1]})"
                else:
                    drive_name = os.path.basename(drive.rstrip(os.sep)) or drive
            except:
                drive_name = drive
            
            drives_menu.add_command(
                label=f"💾 {drive_name}",
                command=lambda d=drive: self.load_files(d, add_to_history=True)
            )
        
        # Show the menu below the drives button
        try:
            drives_menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())
        finally:
            drives_menu.grab_release()

    def on_tree_hover(self, event):
        """Add hover effect to treeview items"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.tk.call(self.tree, "tag", "remove", "hover")
            self.tree.tk.call(self.tree, "tag", "add", "hover", item)
            self.tree.tk.call(self.tree, "tag", "configure", "hover", 
                            "-background", self.highlight_color)

    def filter_files(self, event):
        """Filter files based on search text"""
        search_text = self.search_var.get().lower()
        if not search_text:
            for child in self.tree.get_children():
                self.tree.item(child, tags=())
            return
            
        for child in self.tree.get_children():
            values = self.tree.item(child)['values']
            if values and search_text in values[0].lower():
                self.tree.item(child, tags=('match',))
            else:
                self.tree.item(child, tags=('no-match',))
        
        self.tree.tag_configure('match', background='')
        self.tree.tag_configure('no-match', background='#f5f5f5')

    def refresh_directory(self):
        """Refresh the current directory view"""
        self.load_files(self.current_path)

    def load_files(self, path, add_to_history=False):
        """Load files from directory with history tracking"""
        path = os.path.normpath(path)
        
        # Don't reload the same directory
        if path == os.path.normpath(self.current_path):
            return
            
        # Add to history if requested
        if add_to_history:
            # If we're not at the end of history, truncate the future
            if self.history_index < len(self.history) - 1:
                self.history = self.history[:self.history_index+1]
            self.history.append(path)
            self.history_index = len(self.history) - 1
        
        self.current_path = path
        self.path_var.set(path)
        self.tree.delete(*self.tree.get_children())

        try:
            if not os.path.ismount(path):
                self.tree.insert("", "end", values=("..", "Parent Folder", "", ""),
                                tags=('parent',))
            
            entries = os.listdir(path)
            for entry in sorted(entries, key=lambda x: x.lower()):
                full_path = os.path.join(path, entry)
                try:
                    if os.path.isdir(full_path):
                        icon = "📁"
                        ftype = "Folder"
                        size = ""
                        tags = ('folder',)
                    else:
                        icon = "📄"
                        ext = os.path.splitext(entry)[1][1:].upper()
                        ftype = f"{ext} File" if ext else "File"
                        size = self.format_size(os.path.getsize(full_path))
                        tags = ('file',)
                    
                    modified = self.format_date(os.path.getmtime(full_path))
                    self.tree.insert("", "end", 
                                    values=(f"{icon} {entry}", ftype, size, modified),
                                    tags=tags)
                
                except Exception as e:
                    self.tree.insert("", "end", values=(entry, "Error", "", ""),
                                    tags=('error',))
            
            self.status_var.set(f"{len(entries)} items in {os.path.basename(path) or path}")
            self.update_nav_buttons()
            
            # Apply any existing search filter
            if self.search_var.get():
                self.filter_files(None)
                
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status_var.set("Error loading directory")

    def update_nav_buttons(self):
        """Update navigation buttons state"""
        self.back_btn.config(
            state=tk.NORMAL if self.history_index > 0 else tk.DISABLED,
            style='TButton' if self.history_index > 0 else 'Disabled.TButton'
        )
        self.forward_btn.config(
            state=tk.NORMAL if self.history_index < len(self.history) - 1 else tk.DISABLED,
            style='TButton' if self.history_index < len(self.history) - 1 else 'Disabled.TButton'
        )

    def format_size(self, size_bytes):
        """Convert size in bytes to human-readable format"""
        if size_bytes == 0:
            return "0 B"
        size_name = ("B", "KB", "MB", "GB", "TB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        return f"{round(size_bytes / p, 2)} {size_name[i]}"

    def format_date(self, timestamp):
        """Format timestamp to readable date"""
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')

    def on_item_double_click(self, event):
        """Handle double-click on items"""
        item = self.tree.focus()
        if not item:
            return
        selected = self.tree.item(item)["values"]
        name = selected[0].replace("📁 ", "").replace("📄 ", "")
        if name == "..":
            self.go_up()
            return
        new_path = os.path.join(self.current_path, name)
        if os.path.isdir(new_path):
            self.load_files(new_path, add_to_history=True)
        else:
            try:
                os.startfile(new_path)
            except Exception as e:
                messagebox.showerror("Error", f"Cannot open file: {e}")

    def browse_folder(self):
        """Open folder browser dialog"""
        folder = filedialog.askdirectory(initialdir=self.current_path)
        if folder:
            self.load_files(folder, add_to_history=True)

    def go_back(self):
        """Navigate back in history"""
        if self.history_index > 0:
            self.history_index -= 1
            self.load_files(self.history[self.history_index])

    def go_forward(self):
        """Navigate forward in history"""
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.load_files(self.history[self.history_index])

    def go_home(self):
        """Navigate to home directory"""
        home_path = os.path.expanduser("~")
        if os.path.normpath(home_path) != os.path.normpath(self.current_path):
            self.load_files(home_path, add_to_history=True)

    def go_up(self):
        """Navigate to parent directory"""
        parent = os.path.dirname(self.current_path)
        if parent and os.path.normpath(parent) != os.path.normpath(self.current_path):
            self.load_files(parent, add_to_history=True)

    def on_path_entered(self, event):
        """Handle path entered manually"""
        path = self.path_var.get()
        if os.path.exists(path):
            self.load_files(path, add_to_history=True)
        else:
            messagebox.showerror("Error", "Path does not exist")

    def show_context_menu(self, event):
        """Show context menu on right-click"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def open_selected(self):
        """Open selected item from context menu"""
        self.on_item_double_click(None)

    def open_in_explorer(self):
        """Open current directory in system file explorer"""
        os.startfile(self.current_path)

    def copy_path(self):
        """Copy current path to clipboard"""
        self.clipboard_clear()
        self.clipboard_append(self.current_path)
        self.status_var.set("Path copied to clipboard")

    def get_selected_paths(self):
        """Get paths of all selected items in treeview"""
        selected_items = self.tree.selection()
        if not selected_items:
            return []
        
        paths = []
        for item in selected_items:
            values = self.tree.item(item)['values']
            if values:
                name = values[0].replace("📁 ", "").replace("📄 ", "")
                if name == "..":
                    continue
                paths.append(os.path.join(self.current_path, name))
        
        return paths

    def encrypt_selected(self):
        """Encrypt selected files/folders"""
        selected_paths = self.get_selected_paths()
        if not selected_paths:
            messagebox.showwarning("No Selection", "Please select files or folders first")
            return
        
        cipher = Fernet(self.key)
        encrypted_count = 0
        
        for path in selected_paths:
            if os.path.isdir(path):
                # Encrypt all files in directory recursively
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, "rb") as f:
                                data = f.read()
                            encrypted = cipher.encrypt(data)
                            with open(file_path, "wb") as f:
                                f.write(encrypted)
                            encrypted_count += 1
                        except Exception as e:
                            print(f"Error encrypting {file_path}: {e}")
            else:
                # Encrypt single file
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    encrypted = cipher.encrypt(data)
                    with open(path, "wb") as f:
                        f.write(encrypted)
                    encrypted_count += 1
                except Exception as e:
                    print(f"Error encrypting {path}: {e}")
        
        messagebox.showinfo("Encryption Complete", 
                          f"Successfully encrypted {encrypted_count} files")
        self.refresh_directory()

    def decrypt_selected(self):
        """Decrypt selected files/folders"""
        selected_paths = self.get_selected_paths()
        if not selected_paths:
            messagebox.showwarning("No Selection", "Please select files or folders first")
            return
        
        cipher = Fernet(self.key)
        decrypted_count = 0
        
        for path in selected_paths:
            if os.path.isdir(path):
                # Decrypt all files in directory recursively
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, "rb") as f:
                                data = f.read()
                            decrypted = cipher.decrypt(data)
                            with open(file_path, "wb") as f:
                                f.write(decrypted)
                            decrypted_count += 1
                        except Exception as e:
                            print(f"Error decrypting {file_path}: {e}")
            else:
                # Decrypt single file
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    decrypted = cipher.decrypt(data)
                    with open(path, "wb") as f:
                        f.write(decrypted)
                    decrypted_count += 1
                except Exception as e:
                    print(f"Error decrypting {path}: {e}")
        
        messagebox.showinfo("Decryption Complete", 
                          f"Successfully decrypted {decrypted_count} files")
        self.refresh_directory()

    def backup(self):
        """Backup selected files/folders - copies contents for folders"""
        selected_paths = self.get_selected_paths()
        if not selected_paths:
            messagebox.showwarning("No Selection", "Please select files or folders first")
            return
        
        # Create a popup window for backup options
        backup_window = tk.Toplevel(self)
        backup_window.title("Backup Options")
        backup_window.geometry("400x250")
        
        # Backup name entry
        tk.Label(backup_window, text="Backup Name:").pack(pady=(10, 0))
        backup_name_entry = tk.Entry(backup_window, width=40)
        backup_name_entry.insert(0, f"Backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        backup_name_entry.pack()
        
        # Default backup directory
        default_backup_dir = os.path.join(os.path.expanduser("~"), "Backups")
        
        # Backup directory selection
        tk.Label(backup_window, text="Backup Location:").pack(pady=(10, 0))
        
        backup_dir_frame = tk.Frame(backup_window)
        backup_dir_frame.pack(fill=tk.X, padx=10)
        
        backup_dir_var = tk.StringVar(value=default_backup_dir)
        backup_dir_entry = tk.Entry(backup_dir_frame, textvariable=backup_dir_var, width=30)
        backup_dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        def browse_backup_dir():
            dir_path = filedialog.askdirectory(initialdir=default_backup_dir)
            if dir_path:
                backup_dir_var.set(dir_path)
        
        browse_btn = tk.Button(backup_dir_frame, text="Browse...", command=browse_backup_dir)
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Backup button
        def perform_backup():
            backup_name = backup_name_entry.get().strip()
            if not backup_name:
                messagebox.showerror("Error", "Backup name cannot be empty!")
                return
            
            backup_dir = backup_dir_var.get()
            if not backup_dir:
                messagebox.showerror("Error", "Please select a backup location!")
                return
            
            destination = os.path.join(backup_dir, backup_name)
            
            try:
                # Create destination directory if it doesn't exist
                os.makedirs(backup_dir, exist_ok=True)
                
                # Check if destination already exists
                if os.path.exists(destination):
                    if not messagebox.askyesno("Confirm Overwrite", 
                                            f"'{backup_name}' already exists at this location.\nOverwrite?"):
                        return
                
                # Create the backup directory
                os.makedirs(destination, exist_ok=True)
                
                for path in selected_paths:
                    if os.path.isdir(path):
                        # Copy contents of the folder (not the folder itself)
                        for item in os.listdir(path):
                            src_path = os.path.join(path, item)
                            dst_path = os.path.join(destination, item)
                            
                            if os.path.isdir(src_path):
                                if os.path.exists(dst_path):
                                    shutil.rmtree(dst_path)
                                shutil.copytree(src_path, dst_path)
                            else:
                                if os.path.exists(dst_path):
                                    os.remove(dst_path)
                                shutil.copy2(src_path, dst_path)
                    else:
                        # Copy individual files directly to destination
                        item_name = os.path.basename(path)
                        dst_path = os.path.join(destination, item_name)
                        if os.path.exists(dst_path):
                            os.remove(dst_path)
                        shutil.copy2(path, dst_path)

                messagebox.showinfo("Backup Complete", 
                                f"Backup created successfully at:\n{destination}")
                self.status_var.set("Backup completed successfully")
                backup_window.destroy()
                
            except Exception as e:
                messagebox.showerror("Backup Failed", f"Error during backup: {str(e)}")
                self.status_var.set("Backup failed")
        
        tk.Button(backup_window, text="Create Backup", 
                command=perform_backup, bg="lightblue").pack(pady=20)

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file contents"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            return None

    def verify_signature(self, file_path, signature_b64):
        """Verify a file's digital signature"""
        file_hash = self.calculate_file_hash(file_path)
        if not file_hash:
            return False
            
        try:
            signature = base64.b64decode(signature_b64)
            self.public_key.verify(
                signature,
                file_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def get_file_owner(self, file_path):
        """Get the owner of a file (cross-platform)"""
        try:
            if os.name == 'nt':  # Windows
                import win32security
                sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
                owner_sid = sd.GetSecurityDescriptorOwner()
                name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
                return f"{domain}\\{name}"
            else:  # Unix-like
                import pwd
                stat_info = os.stat(file_path)
                uid = stat_info.st_uid
                return pwd.getpwuid(uid).pw_name
        except Exception:
            return "Unknown"

    def is_suspicious_extension(self, file_path):
        """Check for potentially malicious file extensions"""
        suspicious_extensions = {
            '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', 
            '.jar', '.dll', '.scr', '.msi', '.pif', '.com'
        }
        return os.path.splitext(file_path)[1].lower() in suspicious_extensions

    def deep_scan_selected(self):
        """Perform deep security scan on selected files"""
        selected_paths = self.get_selected_paths()
        if not selected_paths:
            messagebox.showwarning("No Selection", "Please select files or folders first")
            return None

        verification_results = {
            'modified_files': [],
            'invalid_signatures': [],
            'unsigned_sensitive': [],
            'no_metadata': [],
            'expired_files': [],
            'suspicious_files': [],
            'valid_signatures': 0,
            'total_checked': 0,
            'encrypted_files': []
        }

        # Get all files from selected paths (including files in selected folders)
        file_paths = []
        for path in selected_paths:
            if os.path.isfile(path):
                file_paths.append(path)
            elif os.path.isdir(path):
                # Recursively get all files in the directory
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_paths.append(file_path)

        if not file_paths:
            messagebox.showwarning("No Files", "No files found in selected items")
            return

        for file_path in file_paths:
            # Get detailed file info
            try:
                file_stat = os.stat(file_path)
                mod_time = datetime.fromtimestamp(file_stat.st_mtime)
                mod_time_str = mod_time.strftime('%Y-%m-%d %H:%M:%S')
                file_size = file_stat.st_size
                file_owner = self.get_file_owner(file_path)
            except Exception:
                continue
            
            if file_path not in self.metadata:
                verification_results['no_metadata'].append(file_path)
                continue

            meta = self.metadata[file_path]
            verification_results['total_checked'] += 1
            
            # Check if file is encrypted
            is_encrypted = meta.get("encrypted", False)
            if is_encrypted:
                verification_results['encrypted_files'].append(file_path)
            
            # 1. Check file integrity (always in deep scan)
            if 'integrity_hash' in meta and not is_encrypted:
                current_hash = self.calculate_file_hash(file_path)
                if current_hash != meta['integrity_hash']:
                    verification_results['modified_files'].append(file_path)
                    
                    # Get modification details
                    original_mod_time = datetime.fromisoformat(meta.get("last_modified", mod_time_str))
                    time_diff = mod_time - original_mod_time
                    
                    # Check for suspicious patterns
                    if time_diff.total_seconds() < 1:
                        verification_results['suspicious_files'].append(file_path)
                    
                    if file_size == 0:
                        verification_results['suspicious_files'].append(file_path)
                    continue

            # 2. Verify digital signatures (skip if encrypted)
            if "signature" in meta and not is_encrypted:
                if self.verify_signature(file_path, meta["signature"]):
                    verification_results['valid_signatures'] += 1
                else:
                    verification_results['invalid_signatures'].append(file_path)

            # 3. Check for unsigned sensitive files (always in deep scan)
            elif meta.get("sensitivity") in ['High', 'Critical'] and not is_encrypted:
                verification_results['unsigned_sensitive'].append(file_path)
            
            # 4. Check for expired files (if expiry date exists in metadata)
            if 'expiry_date' in meta:
                try:
                    expiry_date = datetime.fromisoformat(meta['expiry_date'])
                    if datetime.now() > expiry_date:
                        verification_results['expired_files'].append(file_path)
                except ValueError:
                    pass
            
            # 5. Additional security checks in deep scan mode
            if not is_encrypted:
                # Check for suspicious file extensions
                if self.is_suspicious_extension(file_path):
                    verification_results['suspicious_files'].append(file_path)
                
                # Check for unusually large size changes
                if 'file_size' in meta and abs(file_size - meta['file_size']) > 1024*1024:  # 1MB change
                    verification_results['suspicious_files'].append(file_path)

        # Show scan summary
        self.show_scan_summary(verification_results)

    def show_scan_summary(self, results):
        """Show a summary of the scan results"""
        popup = tk.Toplevel(self)
        popup.title("Deep Scan Results")
        popup.geometry("600x400")
        
        # Create a scrolled text widget 
        text = scrolledtext.ScrolledText(popup, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Build the summary text
        summary = []
        summary.append("=== Scan Results ===")
        summary.append(f"\nFiles scanned: {results['total_checked']}")
        summary.append(f"Valid signatures: {results['valid_signatures']}")
        summary.append(f"\nModified files : {len(results['modified_files'])}")
        summary.append(f"Invalid signatures: {len(results['invalid_signatures'])}")
        summary.append(f"Unsigned sensitive files: {len(results['unsigned_sensitive'])}")
        summary.append(f"Files without metadata: {len(results['no_metadata'])}")
        summary.append(f"Suspicious files: {len(results['suspicious_files'])}")
        summary.append(f"Encrypted files: {len(results['encrypted_files'])}")
        
        summary.append("\n\n=== Details ===")
        
        if results['modified_files']:
            summary.append("\nModified files:")
            for file in results['modified_files'][:5]:  # Show first 5
                summary.append(f"- {file}")
            if len(results['modified_files']) > 5:
                summary.append(f"- ...and {len(results['modified_files']) - 5} more")
        
        if results['suspicious_files']:
            summary.append("\nSuspicious files:")
            for file in results['suspicious_files'][:5]:
                summary.append(f"- {file}")
            if len(results['suspicious_files']) > 5:
                summary.append(f"- ...and {len(results['suspicious_files']) - 5} more")
        
        text.insert(tk.END, "\n".join(summary))
        text.config(state=tk.DISABLED)
        
        ttk.Button(
            popup, 
            text="Close", 
            command=popup.destroy
        ).pack(pady=10)

    def on_closing(self):
        """Clean up when closing the application"""
        self.stop_file_monitoring()
        self.destroy()

if __name__ == "__main__":
    app = FileExplorer()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
"""
Enhanced Main Window for The Stealer GUI
Modern, responsive interface with advanced features.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import asyncio
import threading
from typing import Optional, Dict, Any
import logging
from datetime import datetime

class MainWindow:
    """
    Enhanced main window with modern design and advanced functionality.
    """
    
    def __init__(self, root: tk.Tk, app_instance):
        """
        Initialize the main window.
        
        Args:
            root: Tkinter root window
            app_instance: Stealer application instance
        """
        self.root = root
        self.app = app_instance
        self.logger = logging.getLogger(__name__)
        
        # Window state
        self.is_extracting = False
        self.is_encrypting = False
        self.is_transmitting = False
        
        # Setup window
        self._setup_window()
        self._create_menu()
        self._create_widgets()
        self._create_status_bar()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _setup_window(self):
        """Setup the main window properties."""
        self.root.title("The Stealer - Enhanced Edition v2.0")
        self.root.geometry("1400x900")
        self.root.minsize(1000, 700)
        
        # Configure window icon (if available)
        try:
            self.root.iconbitmap("assets/icon.ico")
        except:
            pass
        
        # Configure style
        self._configure_style()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _configure_style(self):
        """Configure the application style."""
        style = ttk.Style()
        
        # Configure themes
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', 
                       font=('Arial', 16, 'bold'),
                       foreground='#007acc')
        
        style.configure('Header.TLabel',
                       font=('Arial', 12, 'bold'),
                       foreground='#333333')
        
        style.configure('Status.TLabel',
                       font=('Arial', 9),
                       foreground='#666666')
        
        style.configure('Action.TButton',
                       font=('Arial', 10, 'bold'),
                       padding=(10, 5))
        
        style.configure('Success.TLabel',
                       foreground='#28a745')
        
        style.configure('Error.TLabel',
                       foreground='#dc3545')
        
        style.configure('Warning.TLabel',
                       foreground='#ffc107')
    
    def _create_menu(self):
        """Create the application menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Session", command=self._new_session)
        file_menu.add_command(label="Load Configuration", command=self._load_config)
        file_menu.add_command(label="Save Configuration", command=self._save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Export Data", command=self._export_data)
        file_menu.add_command(label="Import Data", command=self._import_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_closing)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Data Extraction", command=self._show_extraction_tool)
        tools_menu.add_command(label="Encryption Manager", command=self._show_encryption_tool)
        tools_menu.add_command(label="Communication Setup", command=self._show_communication_tool)
        tools_menu.add_separator()
        tools_menu.add_command(label="System Information", command=self._show_system_info)
        tools_menu.add_command(label="Security Scan", command=self._run_security_scan)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Log Viewer", command=self._show_log_viewer)
        view_menu.add_command(label="Data Viewer", command=self._show_data_viewer)
        view_menu.add_command(label="Status Monitor", command=self._show_status_monitor)
        view_menu.add_separator()
        view_menu.add_command(label="Dark Theme", command=lambda: self._change_theme('dark'))
        view_menu.add_command(label="Light Theme", command=lambda: self._change_theme('light'))
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Manual", command=self._show_manual)
        help_menu.add_command(label="Keyboard Shortcuts", command=self._show_shortcuts)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self._show_about)
    
    def _create_widgets(self):
        """Create the main window widgets."""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Title section
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill='x', pady=(0, 20))
        
        title_label = ttk.Label(title_frame, text="The Stealer - Enhanced Edition", 
                              style='Title.TLabel')
        title_label.pack()
        
        subtitle_label = ttk.Label(title_frame, text="Advanced Data Security Analysis Tool", 
                                 style='Status.TLabel')
        subtitle_label.pack()
        
        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="Control Panel", padding=10)
        control_frame.pack(fill='x', pady=(0, 20))
        
        # Action buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill='x')
        
        # Primary actions
        primary_frame = ttk.Frame(button_frame)
        primary_frame.pack(side='left', fill='x', expand=True)
        
        ttk.Button(primary_frame, text="🔍 Extract Data", 
                  command=self._extract_data, style='Action.TButton').pack(side='left', padx=(0, 10))
        ttk.Button(primary_frame, text="🔐 Encrypt Data", 
                  command=self._encrypt_data, style='Action.TButton').pack(side='left', padx=(0, 10))
        ttk.Button(primary_frame, text="🔓 Decrypt Data", 
                  command=self._decrypt_data, style='Action.TButton').pack(side='left', padx=(0, 10))
        ttk.Button(primary_frame, text="📡 Transmit Data", 
                  command=self._transmit_data, style='Action.TButton').pack(side='left', padx=(0, 10))
        
        # Secondary actions
        secondary_frame = ttk.Frame(button_frame)
        secondary_frame.pack(side='right')
        
        ttk.Button(secondary_frame, text="⚙️ Settings", 
                  command=self._show_settings).pack(side='right', padx=(10, 0))
        ttk.Button(secondary_frame, text="📊 Monitor", 
                  command=self._show_monitor).pack(side='right', padx=(10, 0))
        
        # Progress section
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding=10)
        progress_frame.pack(fill='x', pady=(0, 20))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, 
                                          maximum=100, length=400)
        self.progress_bar.pack(fill='x', pady=(0, 5))
        
        # Progress label
        self.progress_label = ttk.Label(progress_frame, text="Ready", style='Status.TLabel')
        self.progress_label.pack()
        
        # Main content area
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill='both', expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill='both', expand=True)
        
        # Log tab
        self._create_log_tab()
        
        # Data tab
        self._create_data_tab()
        
        # System tab
        self._create_system_tab()
    
    def _create_log_tab(self):
        """Create the log viewer tab."""
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="📋 Logs")
        
        # Log controls
        log_controls = ttk.Frame(log_frame)
        log_controls.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(log_controls, text="Clear", command=self._clear_logs).pack(side='left', padx=(0, 10))
        ttk.Button(log_controls, text="Save", command=self._save_logs).pack(side='left', padx=(0, 10))
        ttk.Button(log_controls, text="Refresh", command=self._refresh_logs).pack(side='left')
        
        # Log level filter
        ttk.Label(log_controls, text="Level:").pack(side='right', padx=(10, 5))
        self.log_level_var = tk.StringVar(value="ALL")
        log_level_combo = ttk.Combobox(log_controls, textvariable=self.log_level_var,
                                      values=["ALL", "DEBUG", "INFO", "WARNING", "ERROR"])
        log_level_combo.pack(side='right')
        
        # Log text area
        log_text_frame = ttk.Frame(log_frame)
        log_text_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.log_text = tk.Text(log_text_frame, wrap='word', font=('Consolas', 9),
                              bg='#1e1e1e', fg='#ffffff', insertbackground='white')
        self.log_text.pack(side='left', fill='both', expand=True)
        
        # Log scrollbar
        log_scrollbar = ttk.Scrollbar(log_text_frame, orient='vertical', 
                                     command=self.log_text.yview)
        log_scrollbar.pack(side='right', fill='y')
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
    
    def _create_data_tab(self):
        """Create the data viewer tab."""
        data_frame = ttk.Frame(self.notebook)
        self.notebook.add(data_frame, text="📊 Data")
        
        # Data controls
        data_controls = ttk.Frame(data_frame)
        data_controls.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(data_controls, text="Load Data", command=self._load_data).pack(side='left', padx=(0, 10))
        ttk.Button(data_controls, text="Export", command=self._export_data).pack(side='left', padx=(0, 10))
        ttk.Button(data_controls, text="Search", command=self._search_data).pack(side='left')
        
        # Data tree view
        tree_frame = ttk.Frame(data_frame)
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.data_tree = ttk.Treeview(tree_frame, columns=('Type', 'Size', 'Modified'), show='tree headings')
        self.data_tree.heading('#0', text='Name')
        self.data_tree.heading('Type', text='Type')
        self.data_tree.heading('Size', text='Size')
        self.data_tree.heading('Modified', text='Modified')
        
        self.data_tree.pack(side='left', fill='both', expand=True)
        
        # Tree scrollbar
        tree_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', 
                                      command=self.data_tree.yview)
        tree_scrollbar.pack(side='right', fill='y')
        self.data_tree.configure(yscrollcommand=tree_scrollbar.set)
    
    def _create_system_tab(self):
        """Create the system information tab."""
        system_frame = ttk.Frame(self.notebook)
        self.notebook.add(system_frame, text="💻 System")
        
        # System info text
        self.system_text = tk.Text(system_frame, wrap='word', font=('Consolas', 9),
                                  bg='#1e1e1e', fg='#ffffff')
        self.system_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Load system information
        self._load_system_info()
    
    def _create_status_bar(self):
        """Create the status bar."""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(side='bottom', fill='x')
        
        # Status label
        self.status_label = ttk.Label(self.status_bar, text="Ready", style='Status.TLabel')
        self.status_label.pack(side='left', padx=5)
        
        # Connection status
        self.connection_label = ttk.Label(self.status_bar, text="🔴 Offline", style='Status.TLabel')
        self.connection_label.pack(side='right', padx=5)
        
        # Memory usage
        self.memory_label = ttk.Label(self.status_bar, text="Memory: 0MB", style='Status.TLabel')
        self.memory_label.pack(side='right', padx=5)
    
    def _start_background_tasks(self):
        """Start background monitoring tasks."""
        # Update status every second
        self._update_status()
        
        # Update memory usage every 5 seconds
        self._update_memory_usage()
    
    def _update_status(self):
        """Update status information."""
        try:
            # Update connection status
            if hasattr(self.app, 'communication_handler') and self.app.communication_handler:
                # Check connection status
                pass
            
            # Schedule next update
            self.root.after(1000, self._update_status)
        except Exception as e:
            self.logger.error(f"Status update failed: {e}")
    
    def _update_memory_usage(self):
        """Update memory usage display."""
        try:
            import psutil
            memory = psutil.virtual_memory()
            self.memory_label.config(text=f"Memory: {memory.percent}%")
            
            # Schedule next update
            self.root.after(5000, self._update_memory_usage)
        except Exception as e:
            self.logger.error(f"Memory update failed: {e}")
    
    def _log_message(self, message: str, level: str = "INFO"):
        """Log message to the GUI."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # Color code based on level
        if level == "ERROR":
            self.log_text.tag_add("error", f"end-{len(log_entry)}c", "end-1c")
            self.log_text.tag_config("error", foreground="#ff6b6b")
        elif level == "WARNING":
            self.log_text.tag_add("warning", f"end-{len(log_entry)}c", "end-1c")
            self.log_text.tag_config("warning", foreground="#ffd93d")
        elif level == "SUCCESS":
            self.log_text.tag_add("success", f"end-{len(log_entry)}c", "end-1c")
            self.log_text.tag_config("success", foreground="#6bcf7f")
    
    def _update_progress(self, value: int, text: str = ""):
        """Update progress bar and label."""
        self.progress_var.set(value)
        if text:
            self.progress_label.config(text=text)
    
    # Action handlers
    def _extract_data(self):
        """Handle data extraction."""
        try:
            target_path = filedialog.askdirectory(title="Select extraction target directory")
            if target_path:
                self._log_message(f"Starting data extraction to: {target_path}")
                self._update_progress(0, "Extracting data...")
                
                # Run extraction in background
                threading.Thread(target=self._run_extraction, args=(target_path,), daemon=True).start()
        except Exception as e:
            self._log_message(f"Extraction failed: {e}", "ERROR")
            messagebox.showerror("Error", f"Extraction failed: {e}")
    
    def _run_extraction(self, target_path: str):
        """Run extraction in background thread."""
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Run extraction
            result = loop.run_until_complete(self.app.run_extraction(target_path))
            
            if result['success']:
                self._log_message("Data extraction completed successfully", "SUCCESS")
                self._update_progress(100, "Extraction completed")
            else:
                self._log_message(f"Extraction failed: {result['error']}", "ERROR")
                self._update_progress(0, "Extraction failed")
                
        except Exception as e:
            self._log_message(f"Extraction error: {e}", "ERROR")
            self._update_progress(0, "Extraction error")
        finally:
            loop.close()
    
    def _encrypt_data(self):
        """Handle data encryption."""
        try:
            data_path = filedialog.askdirectory(title="Select data directory to encrypt")
            if data_path:
                password = tk.simpledialog.askstring("Password", "Enter encryption password:", show='*')
                if password:
                    self._log_message(f"Encrypting data at: {data_path}")
                    self._update_progress(0, "Encrypting data...")
                    
                    # Run encryption in background
                    threading.Thread(target=self._run_encryption, args=(data_path, password), daemon=True).start()
        except Exception as e:
            self._log_message(f"Encryption failed: {e}", "ERROR")
            messagebox.showerror("Error", f"Encryption failed: {e}")
    
    def _run_encryption(self, data_path: str, password: str):
        """Run encryption in background thread."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            success = loop.run_until_complete(self.app.encrypt_data(data_path, password))
            
            if success:
                self._log_message("Data encryption completed successfully", "SUCCESS")
                self._update_progress(100, "Encryption completed")
            else:
                self._log_message("Data encryption failed", "ERROR")
                self._update_progress(0, "Encryption failed")
                
        except Exception as e:
            self._log_message(f"Encryption error: {e}", "ERROR")
            self._update_progress(0, "Encryption error")
        finally:
            loop.close()
    
    def _decrypt_data(self):
        """Handle data decryption."""
        try:
            data_path = filedialog.askdirectory(title="Select encrypted data directory")
            if data_path:
                password = tk.simpledialog.askstring("Password", "Enter decryption password:", show='*')
                if password:
                    self._log_message(f"Decrypting data at: {data_path}")
                    self._update_progress(0, "Decrypting data...")
                    
                    # Run decryption in background
                    threading.Thread(target=self._run_decryption, args=(data_path, password), daemon=True).start()
        except Exception as e:
            self._log_message(f"Decryption failed: {e}", "ERROR")
            messagebox.showerror("Error", f"Decryption failed: {e}")
    
    def _run_decryption(self, data_path: str, password: str):
        """Run decryption in background thread."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            success = loop.run_until_complete(self.app.decrypt_data(data_path, password))
            
            if success:
                self._log_message("Data decryption completed successfully", "SUCCESS")
                self._update_progress(100, "Decryption completed")
            else:
                self._log_message("Data decryption failed", "ERROR")
                self._update_progress(0, "Decryption failed")
                
        except Exception as e:
            self._log_message(f"Decryption error: {e}", "ERROR")
            self._update_progress(0, "Decryption error")
        finally:
            loop.close()
    
    def _transmit_data(self):
        """Handle data transmission."""
        try:
            data_path = filedialog.askdirectory(title="Select data directory to transmit")
            if data_path:
                endpoint = tk.simpledialog.askstring("Endpoint", "Enter server endpoint:")
                if endpoint:
                    self._log_message(f"Transmitting data to: {endpoint}")
                    self._update_progress(0, "Transmitting data...")
                    
                    # Run transmission in background
                    threading.Thread(target=self._run_transmission, args=(data_path, endpoint), daemon=True).start()
        except Exception as e:
            self._log_message(f"Transmission failed: {e}", "ERROR")
            messagebox.showerror("Error", f"Transmission failed: {e}")
    
    def _run_transmission(self, data_path: str, endpoint: str):
        """Run transmission in background thread."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            success = loop.run_until_complete(self.app.transmit_data(data_path, endpoint))
            
            if success:
                self._log_message("Data transmission completed successfully", "SUCCESS")
                self._update_progress(100, "Transmission completed")
            else:
                self._log_message("Data transmission failed", "ERROR")
                self._update_progress(0, "Transmission failed")
                
        except Exception as e:
            self._log_message(f"Transmission error: {e}", "ERROR")
            self._update_progress(0, "Transmission error")
        finally:
            loop.close()
    
    # Menu handlers
    def _new_session(self):
        """Start a new session."""
        self._log_message("Starting new session")
        self._update_progress(0, "Ready")
    
    def _load_config(self):
        """Load configuration file."""
        try:
            config_file = filedialog.askopenfilename(
                title="Load Configuration",
                filetypes=[("YAML files", "*.yaml"), ("JSON files", "*.json"), ("All files", "*.*")]
            )
            if config_file:
                self._log_message(f"Loading configuration from: {config_file}")
                # Load configuration logic here
        except Exception as e:
            self._log_message(f"Configuration loading failed: {e}", "ERROR")
    
    def _save_config(self):
        """Save configuration file."""
        try:
            config_file = filedialog.asksaveasfilename(
                title="Save Configuration",
                defaultextension=".yaml",
                filetypes=[("YAML files", "*.yaml"), ("JSON files", "*.json")]
            )
            if config_file:
                self._log_message(f"Saving configuration to: {config_file}")
                # Save configuration logic here
        except Exception as e:
            self._log_message(f"Configuration saving failed: {e}", "ERROR")
    
    def _export_data(self):
        """Export data."""
        try:
            export_file = filedialog.asksaveasfilename(
                title="Export Data",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if export_file:
                self._log_message(f"Exporting data to: {export_file}")
                # Export logic here
        except Exception as e:
            self._log_message(f"Data export failed: {e}", "ERROR")
    
    def _import_data(self):
        """Import data."""
        try:
            import_file = filedialog.askopenfilename(
                title="Import Data",
                filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if import_file:
                self._log_message(f"Importing data from: {import_file}")
                # Import logic here
        except Exception as e:
            self._log_message(f"Data import failed: {e}", "ERROR")
    
    def _show_extraction_tool(self):
        """Show extraction tool dialog."""
        self._log_message("Opening extraction tool")
        # Extraction tool dialog logic here
    
    def _show_encryption_tool(self):
        """Show encryption tool dialog."""
        self._log_message("Opening encryption tool")
        # Encryption tool dialog logic here
    
    def _show_communication_tool(self):
        """Show communication tool dialog."""
        self._log_message("Opening communication tool")
        # Communication tool dialog logic here
    
    def _show_system_info(self):
        """Show system information."""
        self._log_message("Displaying system information")
        # Switch to system tab
        self.notebook.select(2)
    
    def _run_security_scan(self):
        """Run security scan."""
        self._log_message("Running security scan")
        self._update_progress(0, "Running security scan...")
        # Security scan logic here
    
    def _show_log_viewer(self):
        """Show log viewer."""
        self.notebook.select(0)
    
    def _show_data_viewer(self):
        """Show data viewer."""
        self.notebook.select(1)
    
    def _show_status_monitor(self):
        """Show status monitor."""
        self._log_message("Opening status monitor")
        # Status monitor dialog logic here
    
    def _change_theme(self, theme: str):
        """Change application theme."""
        self._log_message(f"Changing theme to: {theme}")
        # Theme change logic here
    
    def _show_manual(self):
        """Show user manual."""
        self._log_message("Opening user manual")
        # Manual dialog logic here
    
    def _show_shortcuts(self):
        """Show keyboard shortcuts."""
        shortcuts = """
Keyboard Shortcuts:
Ctrl+N - New Session
Ctrl+O - Load Configuration
Ctrl+S - Save Configuration
Ctrl+E - Extract Data
Ctrl+R - Encrypt Data
Ctrl+D - Decrypt Data
Ctrl+T - Transmit Data
F1 - Help
F5 - Refresh
Ctrl+Q - Quit
        """
        messagebox.showinfo("Keyboard Shortcuts", shortcuts)
    
    def _show_about(self):
        """Show about dialog."""
        about_text = """
The Stealer - Enhanced Edition v2.0

Advanced Data Security Analysis Tool

Developed by: Akki (Akhand Raj)
Version: 2.0.0
License: MIT

This tool is designed for educational purposes only.
Use responsibly and in accordance with applicable laws.
        """
        messagebox.showinfo("About", about_text)
    
    def _show_settings(self):
        """Show settings dialog."""
        self._log_message("Opening settings")
        # Settings dialog logic here
    
    def _show_monitor(self):
        """Show system monitor."""
        self._log_message("Opening system monitor")
        # Monitor dialog logic here
    
    # Tab-specific handlers
    def _clear_logs(self):
        """Clear log text."""
        self.log_text.delete(1.0, tk.END)
        self._log_message("Logs cleared")
    
    def _save_logs(self):
        """Save logs to file."""
        try:
            log_file = filedialog.asksaveasfilename(
                title="Save Logs",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if log_file:
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                self._log_message(f"Logs saved to: {log_file}")
        except Exception as e:
            self._log_message(f"Log saving failed: {e}", "ERROR")
    
    def _refresh_logs(self):
        """Refresh log display."""
        self._log_message("Logs refreshed")
    
    def _load_data(self):
        """Load data into tree view."""
        try:
            data_file = filedialog.askopenfilename(
                title="Load Data",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if data_file:
                self._log_message(f"Loading data from: {data_file}")
                # Load data logic here
        except Exception as e:
            self._log_message(f"Data loading failed: {e}", "ERROR")
    
    def _search_data(self):
        """Search data in tree view."""
        search_term = tk.simpledialog.askstring("Search", "Enter search term:")
        if search_term:
            self._log_message(f"Searching for: {search_term}")
            # Search logic here
    
    def _load_system_info(self):
        """Load system information."""
        try:
            import platform
            import psutil
            
            info = f"""
System Information:
==================

Platform: {platform.platform()}
System: {platform.system()}
Architecture: {platform.architecture()[0]}
Machine: {platform.machine()}
Processor: {platform.processor()}
Python Version: {platform.python_version()}

Memory:
-------
Total: {psutil.virtual_memory().total // (1024**3)} GB
Available: {psutil.virtual_memory().available // (1024**3)} GB
Used: {psutil.virtual_memory().percent}%

CPU:
----
Cores: {psutil.cpu_count()}
Usage: {psutil.cpu_percent()}%

Disk:
-----
Total: {psutil.disk_usage('/').total // (1024**3)} GB
Used: {psutil.disk_usage('/').used // (1024**3)} GB
Free: {psutil.disk_usage('/').free // (1024**3)} GB
            """
            
            self.system_text.insert(tk.END, info)
            
        except Exception as e:
            self.system_text.insert(tk.END, f"Error loading system info: {e}")
    
    def _on_closing(self):
        """Handle window closing."""
        if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
            self._log_message("Application closing")
            self.root.destroy()
    
    def run(self):
        """Run the main window."""
        self._log_message("Application started")
        self.root.mainloop()
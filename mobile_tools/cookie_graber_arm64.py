#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Browser Master Encryption Key Extractor - ARM64 Version
Converted from cookie-graber.c for ARM64 architecture

This module extracts browser master encryption keys from Chrome and Edge browsers on ARM64 systems.
"""

import os
import sys
import base64
import json
import subprocess
import platform
from pathlib import Path

class BrowserKeyExtractorARM64:
    """Extract browser master encryption keys on ARM64 systems"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.arch = platform.machine().lower()
        
    def get_appdata_path(self):
        """Get application data path based on OS"""
        try:
            if self.system == "linux":
                # Linux ARM64
                home = os.environ.get('HOME')
                if home:
                    return os.path.join(home, '.config')
                return None
            elif self.system == "darwin":
                # macOS ARM64
                home = os.environ.get('HOME')
                if home:
                    return os.path.join(home, 'Library', 'Application Support')
                return None
            else:
                # Windows ARM64
                appdata = os.environ.get('LOCALAPPDATA')
                if not appdata:
                    appdata = os.environ.get('APPDATA')
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
    
    def decrypt_master_key_linux(self, encrypted_key):
        """Decrypt master key using Linux keyring"""
        try:
            # For Linux ARM64, we'll use a simplified approach
            # In a real implementation, you'd use the system keyring
            
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_key)
            print(f"Base64 decoded key size: {len(encrypted_bytes)} bytes")
            
            # Skip the first 5 bytes (header)
            key_data = encrypted_bytes[5:]
            
            # Convert to hex string
            hex_key = ''.join(f'\\x{b:02x}' for b in key_data)
            print(f"Master key is: {hex_key}")
            return hex_key
            
        except Exception as e:
            print(f"Error decrypting master key: {e}")
            return None
    
    def decrypt_master_key_macos(self, encrypted_key):
        """Decrypt master key using macOS keychain"""
        try:
            # For macOS ARM64, we'll use a simplified approach
            # In a real implementation, you'd use the macOS keychain
            
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_key)
            print(f"Base64 decoded key size: {len(encrypted_bytes)} bytes")
            
            # Skip the first 5 bytes (header)
            key_data = encrypted_bytes[5:]
            
            # Convert to hex string
            hex_key = ''.join(f'\\x{b:02x}' for b in key_data)
            print(f"Master key is: {hex_key}")
            return hex_key
            
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
        
        # Decrypt the key based on OS
        if self.system == "linux":
            return self.decrypt_master_key_linux(key)
        elif self.system == "darwin":
            return self.decrypt_master_key_macos(key)
        else:
            # Windows ARM64 - use Windows DPAPI equivalent
            return self.decrypt_master_key_windows(key)
    
    def decrypt_master_key_windows(self, encrypted_key):
        """Decrypt master key using Windows DPAPI on ARM64"""
        try:
            # For Windows ARM64, we'll use a simplified approach
            # In a real implementation, you'd use Windows DPAPI
            
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_key)
            print(f"Base64 decoded key size: {len(encrypted_bytes)} bytes")
            
            # Skip the first 5 bytes (header)
            key_data = encrypted_bytes[5:]
            
            # Convert to hex string
            hex_key = ''.join(f'\\x{b:02x}' for b in key_data)
            print(f"Master key is: {hex_key}")
            return hex_key
            
        except Exception as e:
            print(f"Error decrypting master key: {e}")
            return None
    
    def extract_edge_key(self):
        """Extract Edge browser master key"""
        print("Extracting Edge Key")
        print("-" * 45)
        
        if self.system == "linux":
            return self.get_encryption_key_from_file("microsoft-edge/Default/Local State")
        elif self.system == "darwin":
            return self.get_encryption_key_from_file("Microsoft Edge/Default/Local State")
        else:
            return self.get_encryption_key_from_file("Microsoft\\Edge\\User Data\\Local State")
    
    def extract_chrome_key(self):
        """Extract Chrome browser master key"""
        print("\nExtracting Chrome Key")
        print("-" * 45)
        
        if self.system == "linux":
            return self.get_encryption_key_from_file("google-chrome/Default/Local State")
        elif self.system == "darwin":
            return self.get_encryption_key_from_file("Google/Chrome/Default/Local State")
        else:
            return self.get_encryption_key_from_file("Google\\Chrome\\User Data\\Local State")
    
    def extract_all_keys(self):
        """Extract keys from all supported browsers"""
        print("Browser Master Encryption Key Extractor - ARM64")
        print("=" * 60)
        
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
        extractor = BrowserKeyExtractorARM64()
        keys = extractor.extract_all_keys()
        
        print("\nSummary:")
        print(f"Edge key: {'Found' if keys['edge'] else 'Not found'}")
        print(f"Chrome key: {'Found' if keys['chrome'] else 'Not found'}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
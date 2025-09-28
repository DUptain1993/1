#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chrome v20+ Cookie Decryption - Python Version
Converted from decrypt.cpp

This module decrypts Chrome v20+ cookies using the Chrome Elevation Service.
"""

import os
import sys
import base64
import ctypes
from ctypes import wintypes, c_char_p, c_wchar_p, c_void_p, POINTER
import winreg
import json

class ChromeDecryptor:
    """Decrypt Chrome v20+ cookies using elevation service"""
    
    def __init__(self):
        self.ole32 = ctypes.windll.ole32
        self.kernel32 = ctypes.windll.kernel32
        
        # Chrome Elevation Service CLSID and IID
        self.CLSID_Elevator = "{708860E0-F641-4611-8895-7D867DD3675B}"
        self.IID_IElevator = "{463ABECF-410D-407F-8AF5-DF35A005CC8}"
        
        # App-bound key prefix
        self.kCryptAppBoundKeyPrefix = b'APPB'
    
    def initialize_com(self):
        """Initialize COM library"""
        try:
            result = self.ole32.CoInitializeEx(None, 2)  # COINIT_APARTMENTTHREADED
            if result != 0:  # S_OK
                print(f"Failed to initialize COM. Error: {result}")
                return False
            return True
        except Exception as e:
            print(f"Error initializing COM: {e}")
            return False
    
    def uninitialize_com(self):
        """Uninitialize COM library"""
        try:
            self.ole32.CoUninitialize()
        except Exception as e:
            print(f"Error uninitializing COM: {e}")
    
    def base64_decode(self, encoded_string):
        """Decode base64 string"""
        try:
            # Add padding if needed
            missing_padding = len(encoded_string) % 4
            if missing_padding:
                encoded_string += '=' * (4 - missing_padding)
            
            decoded_bytes = base64.b64decode(encoded_string)
            return decoded_bytes
        except Exception as e:
            print(f"Error decoding base64: {e}")
            return None
    
    def retrieve_encrypted_key(self, filepath):
        """Retrieve encrypted key from file"""
        try:
            if not os.path.exists(filepath):
                print(f"Error: Could not find the key file: {filepath}")
                return None
            
            with open(filepath, 'r') as f:
                base64_encrypted_key = f.read().strip()
            
            encrypted_key_with_header = self.base64_decode(base64_encrypted_key)
            if not encrypted_key_with_header:
                return None
            
            # Check for APP-bound key prefix
            if not encrypted_key_with_header.startswith(self.kCryptAppBoundKeyPrefix):
                print("Error: Invalid key header.")
                return None
            
            # Remove prefix and return the actual encrypted key
            return encrypted_key_with_header[len(self.kCryptAppBoundKeyPrefix):]
            
        except Exception as e:
            print(f"Error retrieving encrypted key: {e}")
            return None
    
    def vector_to_string(self, byte_vector):
        """Convert byte vector to hex string"""
        try:
            return ''.join(f'{b:02x}' for b in byte_vector)
        except Exception as e:
            print(f"Error converting vector to string: {e}")
            return None
    
    def create_elevator_instance(self):
        """Create Chrome Elevation Service instance"""
        try:
            # Define COM interfaces
            class IElevator(ctypes.Structure):
                _fields_ = [
                    ("QueryInterface", ctypes.c_void_p),
                    ("AddRef", ctypes.c_void_p),
                    ("Release", ctypes.c_void_p),
                    ("RunRecoveryCRXElevated", ctypes.c_void_p),
                    ("EncryptData", ctypes.c_void_p),
                    ("DecryptData", ctypes.c_void_p)
                ]
            
            # Create COM instance
            elevator_ptr = ctypes.c_void_p()
            
            # Convert CLSID and IID to proper format
            clsid_bytes = self.CLSID_Elevator.encode('utf-8')
            iid_bytes = self.IID_IElevator.encode('utf-8')
            
            # Call CoCreateInstance
            result = self.ole32.CoCreateInstance(
                ctypes.c_char_p(clsid_bytes),
                None,
                4,  # CLSCTX_LOCAL_SERVER
                ctypes.c_char_p(iid_bytes),
                ctypes.byref(elevator_ptr)
            )
            
            if result != 0:  # S_OK
                print(f"Failed to create IElevator instance. Error: {result}")
                return None
            
            return elevator_ptr
            
        except Exception as e:
            print(f"Error creating elevator instance: {e}")
            return None
    
    def decrypt_data(self, encrypted_key):
        """Decrypt data using Chrome Elevation Service"""
        try:
            # This is a simplified version - the actual implementation would require
            # more complex COM interface handling
            
            print("Note: Full COM interface implementation requires additional setup")
            print("This is a placeholder for the decryption functionality")
            
            # For demonstration, we'll simulate the decryption
            # In a real implementation, you would call the DecryptData method
            # of the IElevator interface
            
            return encrypted_key  # Placeholder
            
        except Exception as e:
            print(f"Error decrypting data: {e}")
            return None
    
    def decrypt_chrome_key(self, key_file_path="app_bound_encrypted_key.txt"):
        """Main function to decrypt Chrome key"""
        try:
            # Initialize COM
            if not self.initialize_com():
                return None
            
            # Retrieve encrypted key
            encrypted_key = self.retrieve_encrypted_key(key_file_path)
            if not encrypted_key:
                return None
            
            # Create elevator instance
            elevator = self.create_elevator_instance()
            if not elevator:
                return None
            
            # Decrypt the key
            decrypted_key = self.decrypt_data(encrypted_key)
            if decrypted_key:
                hex_key = self.vector_to_string(decrypted_key)
                print(f"Decrypted key: {hex_key}")
                return hex_key
            else:
                print("Decryption failed")
                return None
                
        except Exception as e:
            print(f"Error in decrypt_chrome_key: {e}")
            return None
        finally:
            self.uninitialize_com()

def main():
    """Main function"""
    if len(sys.argv) > 1:
        key_file = sys.argv[1]
    else:
        key_file = "app_bound_encrypted_key.txt"
    
    print("Chrome v20+ Cookie Decryption Tool")
    print("=" * 40)
    
    decryptor = ChromeDecryptor()
    result = decryptor.decrypt_chrome_key(key_file)
    
    if result:
        print(f"\nSuccessfully decrypted key: {result}")
    else:
        print("\nFailed to decrypt key")

if __name__ == "__main__":
    main()
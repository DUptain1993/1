#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cookie Processor - ARM64 Version
Converted from CookieProcessor.cs for ARM64 architecture

This module decrypts browser cookies using master encryption keys on ARM64 systems.
"""

import sqlite3
import sys
import base64
import platform
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CookieProcessorARM64:
    """Process and decrypt browser cookies on ARM64 systems"""
    
    def __init__(self):
        self.backend = default_backend()
        self.system = platform.system().lower()
        self.arch = platform.machine().lower()
    
    def string_to_byte_array(self, hex_string):
        """Convert hex string to byte array"""
        try:
            # Remove any spaces or newlines
            hex_string = hex_string.replace(' ', '').replace('\n', '')
            
            # Convert hex string to bytes
            byte_array = bytes.fromhex(hex_string)
            return byte_array
        except ValueError as e:
            print(f"Error converting hex string to bytes: {e}")
            return None
    
    def decrypt_cookie_linux(self, master_key, encrypted_data):
        """Decrypt cookie data using AES-GCM on Linux ARM64"""
        try:
            # Convert master key from base64
            master_key_bytes = base64.b64decode(master_key)
            
            # Convert encrypted data from hex string
            cookie_bytes = self.string_to_byte_array(encrypted_data)
            if not cookie_bytes:
                return None
            
            # Extract components
            nonce = cookie_bytes[3:15]  # 12 bytes for nonce
            ciphertext = cookie_bytes[15:-16]  # Everything except nonce and tag
            tag = cookie_bytes[-16:]  # Last 16 bytes for authentication tag
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(master_key_bytes),
                modes.GCM(nonce, tag),
                backend=self.backend
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            print(f"Error decrypting cookie: {e}")
            return None
    
    def decrypt_cookie_macos(self, master_key, encrypted_data):
        """Decrypt cookie data using AES-GCM on macOS ARM64"""
        try:
            # Convert master key from base64
            master_key_bytes = base64.b64decode(master_key)
            
            # Convert encrypted data from hex string
            cookie_bytes = self.string_to_byte_array(encrypted_data)
            if not cookie_bytes:
                return None
            
            # Extract components
            nonce = cookie_bytes[3:15]  # 12 bytes for nonce
            ciphertext = cookie_bytes[15:-16]  # Everything except nonce and tag
            tag = cookie_bytes[-16:]  # Last 16 bytes for authentication tag
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(master_key_bytes),
                modes.GCM(nonce, tag),
                backend=self.backend
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            print(f"Error decrypting cookie: {e}")
            return None
    
    def decrypt_cookie_windows(self, master_key, encrypted_data):
        """Decrypt cookie data using AES-GCM on Windows ARM64"""
        try:
            # Convert master key from base64
            master_key_bytes = base64.b64decode(master_key)
            
            # Convert encrypted data from hex string
            cookie_bytes = self.string_to_byte_array(encrypted_data)
            if not cookie_bytes:
                return None
            
            # Extract components
            nonce = cookie_bytes[3:15]  # 12 bytes for nonce
            ciphertext = cookie_bytes[15:-16]  # Everything except nonce and tag
            tag = cookie_bytes[-16:]  # Last 16 bytes for authentication tag
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(master_key_bytes),
                modes.GCM(nonce, tag),
                backend=self.backend
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            print(f"Error decrypting cookie: {e}")
            return None
    
    def decrypt_cookie(self, master_key, encrypted_data):
        """Decrypt cookie data based on OS"""
        if self.system == "linux":
            return self.decrypt_cookie_linux(master_key, encrypted_data)
        elif self.system == "darwin":
            return self.decrypt_cookie_macos(master_key, encrypted_data)
        else:
            return self.decrypt_cookie_windows(master_key, encrypted_data)
    
    def process_cookies(self, db_path, master_key, host_filter=None):
        """Process cookies from SQLite database"""
        try:
            # Connect to database
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Build query
            query = "SELECT host_key, name, hex(encrypted_value) FROM cookies"
            if host_filter:
                query += f" WHERE host_key LIKE '%{host_filter}%'"
            query += ";"
            
            # Execute query
            cursor.execute(query)
            
            # Process results
            cookies = []
            for row in cursor.fetchall():
                host_key, name, encrypted_value = row
                
                # Decrypt the cookie value
                decrypted_value = self.decrypt_cookie(master_key, encrypted_value)
                
                if decrypted_value:
                    cookie_string = f"{host_key}:{name}={decrypted_value};"
                    print(cookie_string)
                    cookies.append({
                        'host': host_key,
                        'name': name,
                        'value': decrypted_value,
                        'cookie_string': cookie_string
                    })
                else:
                    print(f"Failed to decrypt cookie: {host_key}:{name}")
            
            conn.close()
            return cookies
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return []
        except Exception as e:
            print(f"Error processing cookies: {e}")
            return []
    
    def process_cookies_from_file(self, db_path, master_key_file, host_filter=None):
        """Process cookies using master key from file"""
        try:
            # Read master key from file
            with open(master_key_file, 'r') as f:
                master_key = f.read().strip()
            
            return self.process_cookies(db_path, master_key, host_filter)
            
        except FileNotFoundError:
            print(f"Master key file not found: {master_key_file}")
            return []
        except Exception as e:
            print(f"Error reading master key file: {e}")
            return []

def main():
    """Main function for command line usage"""
    if len(sys.argv) < 3:
        print("Usage: python cookie_processor_arm64.py <db_path> <master_key> [host_filter]")
        print("Example: python cookie_processor_arm64.py cookies.db 'base64_key' 'google.com'")
        return
    
    db_path = sys.argv[1]
    master_key = sys.argv[2]
    host_filter = sys.argv[3] if len(sys.argv) > 3 else None
    
    if not os.path.exists(db_path):
        print(f"Database file not found: {db_path}")
        return
    
    processor = CookieProcessorARM64()
    cookies = processor.process_cookies(db_path, master_key, host_filter)
    
    print(f"\nProcessed {len(cookies)} cookies successfully")

if __name__ == "__main__":
    main()
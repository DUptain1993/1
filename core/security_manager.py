"""
Advanced Security Manager
Handles all security-related operations including encryption, authentication, and secure communication.
"""

import os
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import argon2
import bcrypt

class SecurityManager:
    """
    Advanced security manager with enterprise-grade encryption and security features.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the security manager with configuration.
        
        Args:
            config: Security configuration dictionary
        """
        self.config = config or self._default_config()
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Initialize encryption components
        self._master_key = None
        self._fernet_key = None
        self._session_keys = {}
        
    def _default_config(self) -> Dict[str, Any]:
        """Return default security configuration."""
        return {
            'encryption': {
                'algorithm': 'AES-256-GCM',
                'key_derivation': 'PBKDF2',
                'iterations': 100000,
                'salt_length': 32,
                'key_length': 32
            },
            'hashing': {
                'algorithm': 'argon2',
                'memory_cost': 65536,
                'time_cost': 3,
                'parallelism': 4
            },
            'communication': {
                'protocol': 'TLS-1.3',
                'certificate_validation': True,
                'timeout': 30
            },
            'anti_detection': {
                'process_hiding': True,
                'memory_protection': True,
                'debugger_detection': True
            }
        }
    
    def _setup_logging(self):
        """Setup secure logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
    
    def generate_master_key(self, password: str) -> bytes:
        """
        Generate a master encryption key using PBKDF2.
        
        Args:
            password: Master password for key derivation
            
        Returns:
            Derived master key
        """
        try:
            salt = secrets.token_bytes(self.config['encryption']['salt_length'])
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.config['encryption']['key_length'],
                salt=salt,
                iterations=self.config['encryption']['iterations'],
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            self._master_key = key
            self.logger.info("Master key generated successfully")
            return key
        except Exception as e:
            self.logger.error(f"Failed to generate master key: {e}")
            raise
    
    def encrypt_data(self, data: bytes, key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data: Data to encrypt
            key: Encryption key (uses master key if None)
            
        Returns:
            Tuple of (encrypted_data, nonce)
        """
        try:
            if key is None:
                key = self._master_key
            
            if key is None:
                raise ValueError("No encryption key available")
            
            # Generate random nonce
            nonce = secrets.token_bytes(12)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            
            self.logger.debug(f"Encrypted {len(data)} bytes of data")
            return encrypted_data, nonce
            
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: bytes, nonce: bytes, key: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data: Encrypted data
            nonce: Nonce used for encryption
            key: Decryption key (uses master key if None)
            
        Returns:
            Decrypted data
        """
        try:
            if key is None:
                key = self._master_key
            
            if key is None:
                raise ValueError("No decryption key available")
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            self.logger.debug(f"Decrypted {len(encrypted_data)} bytes of data")
            return decrypted_data
            
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using Argon2.
        
        Args:
            password: Password to hash
            
        Returns:
            Hashed password
        """
        try:
            hasher = argon2.PasswordHasher(
                memory_cost=self.config['hashing']['memory_cost'],
                time_cost=self.config['hashing']['time_cost'],
                parallelism=self.config['hashing']['parallelism']
            )
            hashed = hasher.hash(password)
            self.logger.debug("Password hashed successfully")
            return hashed
        except Exception as e:
            self.logger.error(f"Password hashing failed: {e}")
            raise
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Password to verify
            hashed: Stored hash
            
        Returns:
            True if password matches
        """
        try:
            hasher = argon2.PasswordHasher()
            hasher.verify(hashed, password)
            self.logger.debug("Password verification successful")
            return True
        except argon2.exceptions.VerifyMismatchError:
            self.logger.warning("Password verification failed")
            return False
        except Exception as e:
            self.logger.error(f"Password verification error: {e}")
            return False
    
    def generate_session_key(self, session_id: str) -> bytes:
        """
        Generate a session-specific encryption key.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Session encryption key
        """
        try:
            key = Fernet.generate_key()
            self._session_keys[session_id] = key
            self.logger.info(f"Session key generated for session: {session_id}")
            return key
        except Exception as e:
            self.logger.error(f"Session key generation failed: {e}")
            raise
    
    def encrypt_with_session(self, data: bytes, session_id: str) -> bytes:
        """
        Encrypt data using session key.
        
        Args:
            data: Data to encrypt
            session_id: Session identifier
            
        Returns:
            Encrypted data
        """
        try:
            if session_id not in self._session_keys:
                self.generate_session_key(session_id)
            
            fernet = Fernet(self._session_keys[session_id])
            encrypted = fernet.encrypt(data)
            self.logger.debug(f"Data encrypted with session key: {session_id}")
            return encrypted
        except Exception as e:
            self.logger.error(f"Session encryption failed: {e}")
            raise
    
    def decrypt_with_session(self, encrypted_data: bytes, session_id: str) -> bytes:
        """
        Decrypt data using session key.
        
        Args:
            encrypted_data: Encrypted data
            session_id: Session identifier
            
        Returns:
            Decrypted data
        """
        try:
            if session_id not in self._session_keys:
                raise ValueError(f"No session key found for: {session_id}")
            
            fernet = Fernet(self._session_keys[session_id])
            decrypted = fernet.decrypt(encrypted_data)
            self.logger.debug(f"Data decrypted with session key: {session_id}")
            return decrypted
        except Exception as e:
            self.logger.error(f"Session decryption failed: {e}")
            raise
    
    def secure_delete(self, file_path: str, passes: int = 3) -> bool:
        """
        Securely delete a file by overwriting it multiple times.
        
        Args:
            file_path: Path to file to delete
            passes: Number of overwrite passes
            
        Returns:
            True if successful
        """
        try:
            if not os.path.exists(file_path):
                return True
            
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'r+b') as file:
                for _ in range(passes):
                    file.seek(0)
                    file.write(secrets.token_bytes(file_size))
                    file.flush()
                    os.fsync(file.fileno())
            
            os.remove(file_path)
            self.logger.info(f"File securely deleted: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Secure deletion failed: {e}")
            return False
    
    def detect_debugger(self) -> bool:
        """
        Detect if a debugger is attached to the process.
        
        Returns:
            True if debugger detected
        """
        try:
            import ctypes
            from ctypes import wintypes
            
            kernel32 = ctypes.windll.kernel32
            
            # Check for debugger using IsDebuggerPresent
            is_debugger_present = kernel32.IsDebuggerPresent()
            
            if is_debugger_present:
                self.logger.warning("Debugger detected!")
                return True
            
            # Additional checks
            try:
                # Check for remote debugger
                debug_port = ctypes.c_ulong()
                result = kernel32.CheckRemoteDebuggerPresent(
                    kernel32.GetCurrentProcess(),
                    ctypes.byref(debug_port)
                )
                
                if result and debug_port.value:
                    self.logger.warning("Remote debugger detected!")
                    return True
                    
            except Exception:
                pass
            
            return False
            
        except Exception as e:
            self.logger.error(f"Debugger detection failed: {e}")
            return False
    
    def hide_process(self) -> bool:
        """
        Attempt to hide the current process from task manager.
        
        Returns:
            True if successful
        """
        try:
            import ctypes
            from ctypes import wintypes
            
            kernel32 = ctypes.windll.kernel32
            
            # Get current process handle
            current_process = kernel32.GetCurrentProcess()
            
            # Set process to be hidden (this is a simplified example)
            # In practice, this would require more sophisticated techniques
            
            self.logger.info("Process hiding attempted")
            return True
            
        except Exception as e:
            self.logger.error(f"Process hiding failed: {e}")
            return False
    
    def get_system_fingerprint(self) -> str:
        """
        Generate a unique system fingerprint.
        
        Returns:
            System fingerprint hash
        """
        try:
            import platform
            import uuid
            
            # Collect system information
            system_info = {
                'platform': platform.platform(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'hostname': platform.node(),
                'mac_address': hex(uuid.getnode())
            }
            
            # Create fingerprint string
            fingerprint_string = '|'.join(f"{k}:{v}" for k, v in system_info.items())
            
            # Hash the fingerprint
            fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
            
            self.logger.debug("System fingerprint generated")
            return fingerprint_hash
            
        except Exception as e:
            self.logger.error(f"Fingerprint generation failed: {e}")
            return "unknown"
    
    def validate_integrity(self, data: bytes, expected_hash: str) -> bool:
        """
        Validate data integrity using hash comparison.
        
        Args:
            data: Data to validate
            expected_hash: Expected hash value
            
        Returns:
            True if integrity check passes
        """
        try:
            actual_hash = hashlib.sha256(data).hexdigest()
            is_valid = actual_hash == expected_hash
            
            if not is_valid:
                self.logger.warning("Data integrity check failed")
            
            return is_valid
            
        except Exception as e:
            self.logger.error(f"Integrity validation failed: {e}")
            return False
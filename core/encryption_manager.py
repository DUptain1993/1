"""
Advanced Encryption Manager
Handles all encryption operations with multiple algorithms and secure key management.
"""

import os
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, Tuple, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import argon2
import bcrypt

class EncryptionManager:
    """
    Advanced encryption manager supporting multiple algorithms and secure key management.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the encryption manager.
        
        Args:
            config: Encryption configuration dictionary
        """
        self.config = config or self._default_config()
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Initialize encryption components
        self._master_key = None
        self._rsa_key_pair = None
        self._session_keys = {}
        self._key_cache = {}
        
    def _default_config(self) -> Dict[str, Any]:
        """Return default encryption configuration."""
        return {
            'algorithms': {
                'symmetric': 'AES-256-GCM',
                'asymmetric': 'RSA-4096',
                'hashing': 'SHA-256',
                'key_derivation': 'PBKDF2'
            },
            'key_management': {
                'key_length': 32,
                'salt_length': 32,
                'nonce_length': 12,
                'iterations': 100000,
                'memory_cost': 65536,
                'time_cost': 3,
                'parallelism': 4
            },
            'security': {
                'secure_delete': True,
                'key_rotation': True,
                'session_timeout': 3600,
                'max_key_age': 86400
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def generate_master_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Generate a master encryption key using PBKDF2.
        
        Args:
            password: Master password for key derivation
            salt: Salt for key derivation (generated if None)
            
        Returns:
            Tuple of (derived_key, salt)
        """
        try:
            if salt is None:
                salt = secrets.token_bytes(self.config['key_management']['salt_length'])
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.config['key_management']['key_length'],
                salt=salt,
                iterations=self.config['key_management']['iterations'],
                backend=default_backend()
            )
            
            key = kdf.derive(password.encode())
            self._master_key = key
            
            self.logger.info("Master key generated successfully")
            return key, salt
            
        except Exception as e:
            self.logger.error(f"Failed to generate master key: {e}")
            raise
    
    def generate_rsa_keypair(self, key_size: int = 4096) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair for asymmetric encryption.
        
        Args:
            key_size: RSA key size in bits
            
        Returns:
            Tuple of (private_key, public_key) in PEM format
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            public_key = private_key.public_key()
            
            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            self._rsa_key_pair = (private_key, public_key)
            
            self.logger.info(f"RSA key pair generated (key size: {key_size})")
            return private_pem, public_pem
            
        except Exception as e:
            self.logger.error(f"Failed to generate RSA key pair: {e}")
            raise
    
    def encrypt_aes_gcm(self, data: bytes, key: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data: Data to encrypt
            key: Encryption key (uses master key if None)
            
        Returns:
            Tuple of (encrypted_data, nonce, tag)
        """
        try:
            if key is None:
                key = self._master_key
            
            if key is None:
                raise ValueError("No encryption key available")
            
            # Generate random nonce
            nonce = secrets.token_bytes(self.config['key_management']['nonce_length'])
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            
            self.logger.debug(f"AES-GCM encrypted {len(data)} bytes")
            return encrypted_data, nonce, encryptor.tag
            
        except Exception as e:
            self.logger.error(f"AES-GCM encryption failed: {e}")
            raise
    
    def decrypt_aes_gcm(self, encrypted_data: bytes, nonce: bytes, tag: bytes, 
                       key: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data: Encrypted data
            nonce: Nonce used for encryption
            tag: Authentication tag
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
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            self.logger.debug(f"AES-GCM decrypted {len(encrypted_data)} bytes")
            return decrypted_data
            
        except Exception as e:
            self.logger.error(f"AES-GCM decryption failed: {e}")
            raise
    
    def encrypt_chacha20_poly1305(self, data: bytes, key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using ChaCha20-Poly1305.
        
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
            nonce = get_random_bytes(12)
            
            # Create cipher
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            encrypted_data, tag = cipher.encrypt_and_digest(data)
            
            # Combine encrypted data and tag
            result = encrypted_data + tag
            
            self.logger.debug(f"ChaCha20-Poly1305 encrypted {len(data)} bytes")
            return result, nonce
            
        except Exception as e:
            self.logger.error(f"ChaCha20-Poly1305 encryption failed: {e}")
            raise
    
    def decrypt_chacha20_poly1305(self, encrypted_data: bytes, nonce: bytes, 
                                 key: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using ChaCha20-Poly1305.
        
        Args:
            encrypted_data: Encrypted data with tag
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
            
            # Split encrypted data and tag
            ciphertext = encrypted_data[:-16]
            tag = encrypted_data[-16:]
            
            # Create cipher
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            
            self.logger.debug(f"ChaCha20-Poly1305 decrypted {len(encrypted_data)} bytes")
            return decrypted_data
            
        except Exception as e:
            self.logger.error(f"ChaCha20-Poly1305 decryption failed: {e}")
            raise
    
    def encrypt_rsa(self, data: bytes, public_key_pem: bytes) -> bytes:
        """
        Encrypt data using RSA public key.
        
        Args:
            data: Data to encrypt
            public_key_pem: RSA public key in PEM format
            
        Returns:
            Encrypted data
        """
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            # Encrypt data
            encrypted_data = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self.logger.debug(f"RSA encrypted {len(data)} bytes")
            return encrypted_data
            
        except Exception as e:
            self.logger.error(f"RSA encryption failed: {e}")
            raise
    
    def decrypt_rsa(self, encrypted_data: bytes, private_key_pem: bytes) -> bytes:
        """
        Decrypt data using RSA private key.
        
        Args:
            encrypted_data: Encrypted data
            private_key_pem: RSA private key in PEM format
            
        Returns:
            Decrypted data
        """
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            # Decrypt data
            decrypted_data = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self.logger.debug(f"RSA decrypted {len(encrypted_data)} bytes")
            return decrypted_data
            
        except Exception as e:
            self.logger.error(f"RSA decryption failed: {e}")
            raise
    
    def encrypt_file(self, file_path: str, output_path: str, 
                    key: Optional[bytes] = None, algorithm: str = 'AES-GCM') -> bool:
        """
        Encrypt a file using specified algorithm.
        
        Args:
            file_path: Path to file to encrypt
            output_path: Path for encrypted file
            key: Encryption key (uses master key if None)
            algorithm: Encryption algorithm to use
            
        Returns:
            True if successful
        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Read file data
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Encrypt data
            if algorithm == 'AES-GCM':
                encrypted_data, nonce, tag = self.encrypt_aes_gcm(data, key)
                # Save encrypted data with metadata
                with open(output_path, 'wb') as f:
                    f.write(b'AES-GCM')  # Algorithm identifier
                    f.write(nonce)
                    f.write(tag)
                    f.write(encrypted_data)
                    
            elif algorithm == 'ChaCha20-Poly1305':
                encrypted_data, nonce = self.encrypt_chacha20_poly1305(data, key)
                # Save encrypted data with metadata
                with open(output_path, 'wb') as f:
                    f.write(b'CHACHA20')  # Algorithm identifier
                    f.write(nonce)
                    f.write(encrypted_data)
                    
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            self.logger.info(f"File encrypted successfully: {file_path} -> {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"File encryption failed: {e}")
            return False
    
    def decrypt_file(self, encrypted_file_path: str, output_path: str, 
                    key: Optional[bytes] = None) -> bool:
        """
        Decrypt a file.
        
        Args:
            encrypted_file_path: Path to encrypted file
            output_path: Path for decrypted file
            key: Decryption key (uses master key if None)
            
        Returns:
            True if successful
        """
        try:
            if not os.path.exists(encrypted_file_path):
                raise FileNotFoundError(f"Encrypted file not found: {encrypted_file_path}")
            
            # Read encrypted file
            with open(encrypted_file_path, 'rb') as f:
                algorithm_id = f.read(8)
                
                if algorithm_id == b'AES-GCM':
                    nonce = f.read(12)
                    tag = f.read(16)
                    encrypted_data = f.read()
                    decrypted_data = self.decrypt_aes_gcm(encrypted_data, nonce, tag, key)
                    
                elif algorithm_id == b'CHACHA20':
                    nonce = f.read(12)
                    encrypted_data = f.read()
                    decrypted_data = self.decrypt_chacha20_poly1305(encrypted_data, nonce, key)
                    
                else:
                    raise ValueError(f"Unknown algorithm: {algorithm_id}")
            
            # Save decrypted data
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.logger.info(f"File decrypted successfully: {encrypted_file_path} -> {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"File decryption failed: {e}")
            return False
    
    def hash_data(self, data: bytes, algorithm: str = 'SHA-256') -> str:
        """
        Hash data using specified algorithm.
        
        Args:
            data: Data to hash
            algorithm: Hashing algorithm
            
        Returns:
            Hexadecimal hash string
        """
        try:
            if algorithm == 'SHA-256':
                hash_obj = hashes.SHA256()
            elif algorithm == 'SHA-512':
                hash_obj = hashes.SHA512()
            elif algorithm == 'BLAKE2b':
                hash_obj = hashes.BLAKE2b(64)
            elif algorithm == 'BLAKE2s':
                hash_obj = hashes.BLAKE2s(32)
            else:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
            digest = hashes.Hash(hash_obj, backend=default_backend())
            digest.update(data)
            hash_value = digest.finalize()
            
            return hash_value.hex()
            
        except Exception as e:
            self.logger.error(f"Hashing failed: {e}")
            raise
    
    def generate_secure_random(self, length: int) -> bytes:
        """
        Generate cryptographically secure random bytes.
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Random bytes
        """
        try:
            return secrets.token_bytes(length)
        except Exception as e:
            self.logger.error(f"Random generation failed: {e}")
            raise
    
    def derive_key_from_password(self, password: str, salt: bytes, 
                               algorithm: str = 'PBKDF2') -> bytes:
        """
        Derive encryption key from password.
        
        Args:
            password: Password string
            salt: Salt for key derivation
            algorithm: Key derivation algorithm
            
        Returns:
            Derived key
        """
        try:
            if algorithm == 'PBKDF2':
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=self.config['key_management']['key_length'],
                    salt=salt,
                    iterations=self.config['key_management']['iterations'],
                    backend=default_backend()
                )
                return kdf.derive(password.encode())
                
            elif algorithm == 'Scrypt':
                kdf = Scrypt(
                    algorithm=hashes.SHA256(),
                    length=self.config['key_management']['key_length'],
                    salt=salt,
                    n=2**14,  # CPU/memory cost parameter
                    r=8,      # Block size parameter
                    p=1,      # Parallelization parameter
                    backend=default_backend()
                )
                return kdf.derive(password.encode())
                
            else:
                raise ValueError(f"Unsupported KDF algorithm: {algorithm}")
                
        except Exception as e:
            self.logger.error(f"Key derivation failed: {e}")
            raise
    
    def secure_delete_file(self, file_path: str, passes: int = 3) -> bool:
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
    
    def create_encrypted_container(self, container_path: str, password: str, 
                                 size_mb: int = 100) -> bool:
        """
        Create an encrypted container file.
        
        Args:
            container_path: Path for container file
            password: Password for container
            size_mb: Container size in MB
            
        Returns:
            True if successful
        """
        try:
            # Generate salt and key
            salt = secrets.token_bytes(32)
            key = self.derive_key_from_password(password, salt)
            
            # Create container file
            container_size = size_mb * 1024 * 1024
            
            with open(container_path, 'wb') as f:
                # Write header
                f.write(b'STEALER_CONTAINER_V1')
                f.write(salt)
                
                # Write encrypted random data
                random_data = secrets.token_bytes(container_size - 64)  # Reserve space for header
                encrypted_data, nonce, tag = self.encrypt_aes_gcm(random_data, key)
                
                f.write(nonce)
                f.write(tag)
                f.write(encrypted_data)
            
            self.logger.info(f"Encrypted container created: {container_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Container creation failed: {e}")
            return False
    
    def mount_encrypted_container(self, container_path: str, password: str, 
                               mount_path: str) -> bool:
        """
        Mount an encrypted container (simplified implementation).
        
        Args:
            container_path: Path to container file
            password: Container password
            mount_path: Mount point path
            
        Returns:
            True if successful
        """
        try:
            if not os.path.exists(container_path):
                raise FileNotFoundError(f"Container not found: {container_path}")
            
            # Read container header
            with open(container_path, 'rb') as f:
                header = f.read(21)  # 'STEALER_CONTAINER_V1'
                if header != b'STEALER_CONTAINER_V1':
                    raise ValueError("Invalid container format")
                
                salt = f.read(32)
                nonce = f.read(12)
                tag = f.read(16)
                encrypted_data = f.read()
            
            # Derive key and decrypt
            key = self.derive_key_from_password(password, salt)
            decrypted_data = self.decrypt_aes_gcm(encrypted_data, nonce, tag, key)
            
            # Create mount point (simplified - just save decrypted data)
            os.makedirs(mount_path, exist_ok=True)
            with open(os.path.join(mount_path, 'data.bin'), 'wb') as f:
                f.write(decrypted_data)
            
            self.logger.info(f"Container mounted: {container_path} -> {mount_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Container mounting failed: {e}")
            return False
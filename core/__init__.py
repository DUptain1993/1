"""
The Stealer - Core Module
Advanced Data Security Analysis Tool

This module contains the core functionality for the enhanced stealer tool.
"""

__version__ = "2.0.0"
__author__ = "Akki (Akhand Raj)"
__license__ = "MIT"

from .security_manager import SecurityManager
from .extraction_engine import ExtractionEngine
from .encryption_manager import EncryptionManager
from .communication_handler import CommunicationHandler

__all__ = [
    'SecurityManager',
    'ExtractionEngine', 
    'EncryptionManager',
    'CommunicationHandler'
]
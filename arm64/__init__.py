"""
Android ARM64 String Encoder and Injection System
Advanced string encryption and injection capabilities for Android applications.
"""

__version__ = "2.0.0"
__author__ = "Akki (Akhand Raj)"
__license__ = "MIT"

from .string_encoder import StringEncoder
from .injection_engine import InjectionEngine
from .obfuscation_manager import ObfuscationManager
from .repackaging_tool import RepackagingTool
from .reflection_engine import ReflectionEngine
from .vulnerability_exploiter import VulnerabilityExploiter

__all__ = [
    'StringEncoder',
    'InjectionEngine', 
    'ObfuscationManager',
    'RepackagingTool',
    'ReflectionEngine',
    'VulnerabilityExploiter'
]
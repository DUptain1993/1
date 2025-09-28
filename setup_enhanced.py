"""
Enhanced Setup Script for The Stealer
Advanced installation and configuration management.
"""

import os
import sys
import json
import yaml
import shutil
import subprocess
import platform
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import argparse
import requests
from datetime import datetime

class StealerSetup:
    """
    Enhanced setup manager for The Stealer application.
    """
    
    def __init__(self):
        """Initialize the setup manager."""
        self.logger = self._setup_logging()
        self.system_info = self._get_system_info()
        self.requirements = self._load_requirements()
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for setup process."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('setup.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        return {
            'platform': platform.platform(),
            'system': platform.system(),
            'architecture': platform.architecture(),
            'python_version': platform.python_version(),
            'python_executable': sys.executable,
            'user_home': os.path.expanduser('~'),
            'current_directory': os.getcwd()
        }
    
    def _load_requirements(self) -> List[str]:
        """Load requirements from requirements.txt."""
        requirements = []
        try:
            with open('requirements.txt', 'r') as f:
                requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            self.logger.warning("requirements.txt not found")
        return requirements
    
    def check_prerequisites(self) -> bool:
        """Check system prerequisites."""
        self.logger.info("Checking system prerequisites...")
        
        issues = []
        
        # Check Python version
        if sys.version_info < (3, 9):
            issues.append(f"Python 3.9+ required, found {sys.version}")
        
        # Check platform
        if platform.system() not in ['Windows', 'Linux', 'Darwin']:
            issues.append(f"Unsupported platform: {platform.system()}")
        
        # Check write permissions
        try:
            test_file = 'test_write_permission.tmp'
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except Exception as e:
            issues.append(f"No write permission in current directory: {e}")
        
        # Check internet connectivity
        try:
            response = requests.get('https://pypi.org', timeout=5)
            if response.status_code != 200:
                issues.append("Internet connectivity issues")
        except Exception:
            issues.append("No internet connectivity")
        
        if issues:
            self.logger.error("Prerequisites check failed:")
            for issue in issues:
                self.logger.error(f"  - {issue}")
            return False
        
        self.logger.info("Prerequisites check passed")
        return True
    
    def create_directory_structure(self):
        """Create application directory structure."""
        self.logger.info("Creating directory structure...")
        
        directories = [
            'config',
            'data',
            'logs',
            'temp',
            'core',
            'gui',
            'api',
            'utils',
            'tests',
            'docs',
            'scripts'
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            self.logger.debug(f"Created directory: {directory}")
        
        self.logger.info("Directory structure created successfully")
    
    def install_dependencies(self, upgrade: bool = False) -> bool:
        """Install Python dependencies."""
        self.logger.info("Installing Python dependencies...")
        
        try:
            # Upgrade pip first
            subprocess.run([
                sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'
            ], check=True, capture_output=True)
            
            # Install requirements
            cmd = [sys.executable, '-m', 'pip', 'install']
            if upgrade:
                cmd.append('--upgrade')
            cmd.extend(self.requirements)
            
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info("Dependencies installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install dependencies: {e}")
            self.logger.error(f"Error output: {e.stderr}")
            return False
    
    def create_configuration_files(self):
        """Create default configuration files."""
        self.logger.info("Creating configuration files...")
        
        # Main configuration
        config = {
            'application': {
                'name': 'The Stealer - Enhanced',
                'version': '2.0.0',
                'debug_mode': False,
                'log_level': 'INFO',
                'data_directory': 'data',
                'temp_directory': 'temp'
            },
            'security': {
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
                'anti_detection': {
                    'process_hiding': True,
                    'memory_protection': True,
                    'debugger_detection': True
                }
            },
            'extraction': {
                'max_threads': 8,
                'timeout': 30,
                'chunk_size': 8192,
                'retry_attempts': 3,
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
            },
            'communication': {
                'server_url': '',
                'api_key': '',
                'timeout': 30,
                'retry_attempts': 3,
                'verify_ssl': True,
                'encryption_enabled': True,
                'compression_enabled': True
            }
        }
        
        # Save main configuration
        with open('config/settings.yaml', 'w') as f:
            yaml.dump(config, f, default_flow_style=False, indent=2)
        
        # Create logging configuration
        logging_config = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'standard': {
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                },
                'detailed': {
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s'
                }
            },
            'handlers': {
                'file': {
                    'class': 'logging.FileHandler',
                    'level': 'INFO',
                    'formatter': 'standard',
                    'filename': 'logs/stealer.log',
                    'mode': 'a',
                    'encoding': 'utf-8'
                },
                'console': {
                    'class': 'logging.StreamHandler',
                    'level': 'INFO',
                    'formatter': 'standard',
                    'stream': 'ext://sys.stdout'
                }
            },
            'loggers': {
                '': {
                    'handlers': ['file', 'console'],
                    'level': 'INFO',
                    'propagate': False
                }
            }
        }
        
        with open('config/logging.yaml', 'w') as f:
            yaml.dump(logging_config, f, default_flow_style=False, indent=2)
        
        self.logger.info("Configuration files created successfully")
    
    def create_startup_scripts(self):
        """Create startup scripts for different platforms."""
        self.logger.info("Creating startup scripts...")
        
        # Windows batch script
        windows_script = """@echo off
title The Stealer - Enhanced Edition
echo Starting The Stealer...
python main_enhanced.py --gui
pause
"""
        
        with open('start_stealer.bat', 'w') as f:
            f.write(windows_script)
        
        # Linux/Mac shell script
        unix_script = """#!/bin/bash
echo "Starting The Stealer - Enhanced Edition..."
python3 main_enhanced.py --gui
"""
        
        with open('start_stealer.sh', 'w') as f:
            f.write(unix_script)
        
        # Make shell script executable
        if platform.system() != 'Windows':
            os.chmod('start_stealer.sh', 0o755)
        
        self.logger.info("Startup scripts created successfully")
    
    def create_documentation(self):
        """Create documentation files."""
        self.logger.info("Creating documentation...")
        
        # README content
        readme_content = """# The Stealer - Enhanced Edition

## Quick Start

1. Run the setup script:
   ```bash
   python setup_enhanced.py
   ```

2. Start the application:
   ```bash
   python main_enhanced.py --gui
   ```

## Configuration

Edit `config/settings.yaml` to customize the application settings.

## Security Notice

This tool is for educational purposes only. Use responsibly and legally.

## Support

For issues and questions, please check the documentation or contact support.
"""
        
        with open('README_SETUP.md', 'w') as f:
            f.write(readme_content)
        
        # User manual
        manual_content = """# User Manual

## Features

- Advanced data extraction
- Multiple encryption algorithms
- Secure communication
- Modern GUI interface
- Command-line interface

## Usage

### GUI Mode
```bash
python main_enhanced.py --gui
```

### Command Line Mode
```bash
# Extract data
python main_enhanced.py --extract /path/to/output

# Encrypt data
python main_enhanced.py --encrypt /path/to/data --password your_password

# Decrypt data
python main_enhanced.py --decrypt /path/to/data --password your_password
```

## Configuration

All settings can be modified in `config/settings.yaml`.
"""
        
        with open('docs/USER_MANUAL.md', 'w') as f:
            f.write(manual_content)
        
        self.logger.info("Documentation created successfully")
    
    def run_tests(self) -> bool:
        """Run basic tests to verify installation."""
        self.logger.info("Running installation tests...")
        
        tests_passed = 0
        total_tests = 0
        
        # Test 1: Import core modules
        total_tests += 1
        try:
            from core.security_manager import SecurityManager
            from core.extraction_engine import ExtractionEngine
            from core.encryption_manager import EncryptionManager
            self.logger.info("✓ Core modules import test passed")
            tests_passed += 1
        except ImportError as e:
            self.logger.error(f"✗ Core modules import test failed: {e}")
        
        # Test 2: Create security manager
        total_tests += 1
        try:
            sm = SecurityManager()
            self.logger.info("✓ Security manager creation test passed")
            tests_passed += 1
        except Exception as e:
            self.logger.error(f"✗ Security manager creation test failed: {e}")
        
        # Test 3: Test encryption
        total_tests += 1
        try:
            em = EncryptionManager()
            key, salt = em.generate_master_key("test_password")
            test_data = b"test data"
            encrypted, nonce, tag = em.encrypt_aes_gcm(test_data, key)
            decrypted = em.decrypt_aes_gcm(encrypted, nonce, tag, key)
            if decrypted == test_data:
                self.logger.info("✓ Encryption test passed")
                tests_passed += 1
            else:
                self.logger.error("✗ Encryption test failed: data mismatch")
        except Exception as e:
            self.logger.error(f"✗ Encryption test failed: {e}")
        
        # Test 4: Check GUI availability
        total_tests += 1
        try:
            import tkinter
            self.logger.info("✓ GUI availability test passed")
            tests_passed += 1
        except ImportError:
            self.logger.warning("✗ GUI not available (tkinter not installed)")
        
        success_rate = (tests_passed / total_tests) * 100
        self.logger.info(f"Tests completed: {tests_passed}/{total_tests} passed ({success_rate:.1f}%)")
        
        return success_rate >= 75
    
    def create_uninstall_script(self):
        """Create uninstall script."""
        self.logger.info("Creating uninstall script...")
        
        uninstall_content = """#!/usr/bin/env python3
\"\"\"
Uninstall script for The Stealer - Enhanced Edition
\"\"\"

import os
import shutil
import sys

def uninstall():
    print("Uninstalling The Stealer - Enhanced Edition...")
    
    # Directories to remove
    directories_to_remove = [
        'config',
        'data',
        'logs',
        'temp',
        'core',
        'gui',
        'api',
        'utils',
        'tests',
        'docs',
        'scripts'
    ]
    
    # Files to remove
    files_to_remove = [
        'main_enhanced.py',
        'setup_enhanced.py',
        'requirements.txt',
        'start_stealer.bat',
        'start_stealer.sh',
        'README_SETUP.md',
        'setup.log'
    ]
    
    # Remove directories
    for directory in directories_to_remove:
        if os.path.exists(directory):
            try:
                shutil.rmtree(directory)
                print(f"Removed directory: {directory}")
            except Exception as e:
                print(f"Failed to remove directory {directory}: {e}")
    
    # Remove files
    for file in files_to_remove:
        if os.path.exists(file):
            try:
                os.remove(file)
                print(f"Removed file: {file}")
            except Exception as e:
                print(f"Failed to remove file {file}: {e}")
    
    print("Uninstallation completed.")
    print("Note: Python packages installed via pip are not removed.")
    print("To remove them, run: pip uninstall -r requirements.txt")

if __name__ == "__main__":
    uninstall()
"""
        
        with open('uninstall.py', 'w') as f:
            f.write(uninstall_content)
        
        # Make executable on Unix systems
        if platform.system() != 'Windows':
            os.chmod('uninstall.py', 0o755)
        
        self.logger.info("Uninstall script created successfully")
    
    def generate_system_report(self) -> Dict[str, Any]:
        """Generate system report."""
        self.logger.info("Generating system report...")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'system_info': self.system_info,
            'python_packages': self._get_installed_packages(),
            'directories_created': self._get_created_directories(),
            'files_created': self._get_created_files(),
            'setup_status': 'completed'
        }
        
        # Save report
        with open('setup_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info("System report generated successfully")
        return report
    
    def _get_installed_packages(self) -> List[str]:
        """Get list of installed packages."""
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'list', '--format=json'
            ], capture_output=True, text=True, check=True)
            
            packages = json.loads(result.stdout)
            return [pkg['name'] for pkg in packages]
        except Exception:
            return []
    
    def _get_created_directories(self) -> List[str]:
        """Get list of created directories."""
        directories = []
        for item in os.listdir('.'):
            if os.path.isdir(item) and item not in ['.', '..', '__pycache__']:
                directories.append(item)
        return directories
    
    def _get_created_files(self) -> List[str]:
        """Get list of created files."""
        files = []
        for item in os.listdir('.'):
            if os.path.isfile(item) and not item.startswith('.'):
                files.append(item)
        return files
    
    def run_setup(self, upgrade_deps: bool = False) -> bool:
        """Run complete setup process."""
        self.logger.info("Starting enhanced setup process...")
        
        try:
            # Step 1: Check prerequisites
            if not self.check_prerequisites():
                self.logger.error("Prerequisites check failed")
                return False
            
            # Step 2: Create directory structure
            self.create_directory_structure()
            
            # Step 3: Install dependencies
            if not self.install_dependencies(upgrade_deps):
                self.logger.error("Dependency installation failed")
                return False
            
            # Step 4: Create configuration files
            self.create_configuration_files()
            
            # Step 5: Create startup scripts
            self.create_startup_scripts()
            
            # Step 6: Create documentation
            self.create_documentation()
            
            # Step 7: Create uninstall script
            self.create_uninstall_script()
            
            # Step 8: Run tests
            if not self.run_tests():
                self.logger.warning("Some tests failed, but setup may still work")
            
            # Step 9: Generate system report
            self.generate_system_report()
            
            self.logger.info("Setup completed successfully!")
            self._print_success_message()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Setup failed: {e}")
            return False
    
    def _print_success_message(self):
        """Print success message with next steps."""
        print("\n" + "="*60)
        print("🎉 The Stealer - Enhanced Edition Setup Complete!")
        print("="*60)
        print("\nNext Steps:")
        print("1. Review configuration: config/settings.yaml")
        print("2. Start the application:")
        print("   - GUI Mode: python main_enhanced.py --gui")
        print("   - CLI Mode: python main_enhanced.py --help")
        print("3. Read documentation: docs/USER_MANUAL.md")
        print("\nSecurity Notice:")
        print("⚠️  This tool is for educational purposes only.")
        print("   Use responsibly and in accordance with applicable laws.")
        print("\nSupport:")
        print("📧 For issues: Check logs/stealer.log")
        print("📖 Documentation: docs/")
        print("="*60)

def main():
    """Main setup function."""
    parser = argparse.ArgumentParser(description="Enhanced Setup for The Stealer")
    parser.add_argument('--upgrade', action='store_true', 
                       help='Upgrade existing dependencies')
    parser.add_argument('--test-only', action='store_true',
                       help='Run tests only')
    parser.add_argument('--report', action='store_true',
                       help='Generate system report only')
    
    args = parser.parse_args()
    
    setup = StealerSetup()
    
    if args.test_only:
        success = setup.run_tests()
        sys.exit(0 if success else 1)
    
    elif args.report:
        report = setup.generate_system_report()
        print(json.dumps(report, indent=2))
        sys.exit(0)
    
    else:
        success = setup.run_setup(args.upgrade)
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
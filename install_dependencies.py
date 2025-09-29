#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dependency Installer for VirusBuilder
Automatically installs required dependencies based on platform
"""

import os
import sys
import platform
import subprocess
import importlib.util

def check_package(package_name):
    """Check if package is installed"""
    try:
        spec = importlib.util.find_spec(package_name)
        return spec is not None
    except ImportError:
        return False

def install_package(package):
    """Install package using pip"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        return True
    except subprocess.CalledProcessError:
        return False

def install_packages(packages):
    """Install multiple packages"""
    failed_packages = []
    for package in packages:
        if not check_package(package.split('>=')[0].split('==')[0]):
            print(f"Installing {package}...")
            if not install_package(package):
                failed_packages.append(package)
                print(f"Failed to install {package}")
            else:
                print(f"Successfully installed {package}")
        else:
            print(f"{package} already installed")
    return failed_packages

def get_platform_requirements():
    """Get platform-specific requirements"""
    system = platform.system().lower()
    
    if system == "windows":
        return [
            "cryptography>=41.0.0",
            "pycryptodome>=3.19.0",
            "requests>=2.31.0",
            "psutil>=5.9.0",
            "argon2-cffi>=21.3.0",
            "pywin32>=306",
            "impacket>=0.11.0",
            "donpapi>=1.0.0",
            "dploot>=1.0.0",
            "pyasn1>=0.5.0",
            "exrex>=0.11.0",
            "tensorflow>=2.13.0",
            "torch>=2.0.0",
            "scikit-learn>=1.3.0",
            "scipy>=1.11.0",
            "dnspython>=2.4.0",
            "paramiko>=3.3.0",
            "scapy>=2.5.0",
            "pymongo>=4.5.0",
            "redis>=4.6.0"
        ]
    elif system == "darwin":  # macOS
        return [
            "cryptography>=41.0.0",
            "pycryptodome>=3.19.0",
            "requests>=2.31.0",
            "psutil>=5.9.0",
            "argon2-cffi>=21.3.0",
            "pyobjc>=9.0.0",
            "pyobjc-framework-Cocoa>=9.0.0",
            "pyobjc-framework-Security>=9.0.0",
            "pyobjc-framework-SystemConfiguration>=9.0.0",
            "tensorflow>=2.13.0",
            "torch>=2.0.0",
            "scikit-learn>=1.3.0",
            "scipy>=1.11.0",
            "dnspython>=2.4.0",
            "paramiko>=3.3.0",
            "scapy>=2.5.0",
            "netifaces>=0.11.0",
            "pymongo>=4.5.0",
            "redis>=4.6.0"
        ]
    else:  # Linux
        return [
            "cryptography>=41.0.0",
            "pycryptodome>=3.19.0",
            "requests>=2.31.0",
            "psutil>=5.9.0",
            "argon2-cffi>=21.3.0",
            "tensorflow>=2.13.0",
            "torch>=2.0.0",
            "scikit-learn>=1.3.0",
            "scipy>=1.11.0",
            "dnspython>=2.4.0",
            "paramiko>=3.3.0",
            "scapy>=2.5.0",
            "netifaces>=0.11.0",
            "pymongo>=4.5.0",
            "redis>=4.6.0"
        ]

def main():
    """Main installation function"""
    print("VirusBuilder Dependency Installer")
    print("=" * 50)
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version}")
    print()
    
    # Get platform-specific requirements
    packages = get_platform_requirements()
    
    print(f"Installing {len(packages)} packages...")
    print()
    
    # Install packages
    failed_packages = install_packages(packages)
    
    print()
    print("Installation Summary:")
    print("=" * 20)
    
    if failed_packages:
        print(f"Failed to install {len(failed_packages)} packages:")
        for package in failed_packages:
            print(f"  - {package}")
        print()
        print("You may need to install these manually or with elevated privileges.")
    else:
        print("All packages installed successfully!")
    
    print()
    print("Testing core imports...")
    
    # Test core imports
    test_imports = [
        "cryptography",
        "Crypto",
        "requests",
        "psutil",
        "argon2",
        "numpy",
        "pandas"
    ]
    
    failed_imports = []
    for module in test_imports:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError:
            print(f"❌ {module}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"\nFailed imports: {failed_imports}")
        print("Some functionality may be limited.")
    else:
        print("\nAll core imports successful!")
    
    print("\nInstallation complete!")

if __name__ == "__main__":
    main()
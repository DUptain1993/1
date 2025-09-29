#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirusBuilder Launcher
Quick access to GUI and CLI versions
"""

import sys
import os

def main():
    print("🚀 VirusBuilder Launcher")
    print("=" * 30)
    print("1. GUI Builder (Windows)")
    print("2. CLI Builder (Cross-platform)")
    print("3. Install Dependencies")
    print("4. Exit")
    
    while True:
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == "1":
            try:
                os.system("python builder_gui.py")
            except Exception as e:
                print(f"Error launching GUI: {e}")
                print("Make sure tkinter is installed")
            break
        elif choice == "2":
            try:
                os.system("python builder_cli.py --interactive")
            except Exception as e:
                print(f"Error launching CLI: {e}")
            break
        elif choice == "3":
            try:
                os.system("python install_dependencies.py")
            except Exception as e:
                print(f"Error installing dependencies: {e}")
            break
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

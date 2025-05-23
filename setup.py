#!/usr/bin/env python3
"""
NeuroStrike Setup Script
Creates necessary directories and initializes the environment
"""

import os
import sys
import shutil
from pathlib import Path

def create_directory(path):
    """Create a directory if it doesn't exist"""
    try:
        os.makedirs(path, exist_ok=True)
        print(f"Created directory: {path}")
        return True
    except Exception as e:
        print(f"Error creating directory {path}: {e}")
        return False

def setup_environment():
    """Set up the NeuroStrike environment"""
    print("Setting up NeuroStrike environment...")
    
    # Create data directories
    data_dirs = [
        "data/logs",
        "data/reports",
        "data/rules",
        "data/rules/yara",
        "data/rules/snort",
        "data/rules/sigma"
    ]
    
    for directory in data_dirs:
        create_directory(directory)
    
    # Create .env file if it doesn't exist
    if not os.path.exists(".env"):
        if os.path.exists(".env.example"):
            shutil.copy(".env.example", ".env")
            print("Created .env file from .env.example")
            print("Please edit .env with your API keys and configuration")
        else:
            print("Warning: .env.example not found. Please create .env manually.")
    
    print("\nSetup complete!")
    print("\nNext steps:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Configure your API keys in .env")
    print("3. Run the application: python run.py")

if __name__ == "__main__":
    setup_environment()

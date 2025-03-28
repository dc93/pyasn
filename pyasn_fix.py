#!/usr/bin/env python3
"""
PyASN Fixer Script

This script fixes the package structure for PyASN by:
1. Creating all necessary __init__.py files
2. Adding version information to the main package
"""

import os
import sys
from pathlib import Path

def create_init_file(directory, content=""):
    """Create an __init__.py file in the specified directory if it doesn't exist"""
    init_path = os.path.join(directory, "__init__.py")
    if not os.path.exists(init_path):
        print(f"Creating {init_path}")
        with open(init_path, "w") as f:
            f.write(content)
    else:
        print(f"{init_path} already exists, skipping")

def main():
    """Main function to fix PyASN package structure"""
    # Get the base directory (where this script is or current directory)
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    
    print(f"Using base directory: {base_dir}")
    
    # Create root package __init__.py with version information
    root_init_content = '''"""
PyASN - Python Cross-Platform ASN Lookup Tool
"""

__version__ = "1.0.0"
'''
    create_init_file(base_dir, root_init_content)
    
    # Create __init__.py files in all subdirectories
    directories = [
        "core",
        "core/providers",
        "interfaces",
        "services",
        "utils",
        "tests",
        "tests/unit"
    ]
    
    for directory in directories:
        dir_path = os.path.join(base_dir, directory)
        if os.path.exists(dir_path):
            create_init_file(dir_path)
    
    print("PyASN package structure fixed successfully!")

if __name__ == "__main__":
    main()
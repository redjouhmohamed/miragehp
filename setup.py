#!/usr/bin/env python3
import os
import sys
import json
import shutil
from pathlib import Path

def setup_honeypot():
    """Set up the honeypot environment"""
    print("Setting up Honeypot environment...")
    
    # Determine the base directory
    base_dir = Path(__file__).resolve().parent
    
    # Create necessary directories
    dirs = ["logs", "web/static/css", "web/static/js", "web/templates"]
    for dir_path in dirs:
        full_path = base_dir / dir_path
        if not full_path.exists():
            print(f"Creating directory: {full_path}")
            full_path.mkdir(parents=True, exist_ok=True)
    
    # Create empty log file if it doesn't exist
    log_file = base_dir / "logs" / "honeypot.json"
    if not log_file.exists():
        print(f"Creating empty log file: {log_file}")
        with open(log_file, "w") as f:
            json.dump([], f)
    
    # Create a sample config file if it doesn't exist
    config_file = base_dir / "web" / "config.py"
    if not config_file.exists():
        print(f"Creating sample config file: {config_file}")
        with open(config_file, "w") as f:
            f.write("""import os

# Base directory of the project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Configuration settings
CONFIG = {
    # Log directory - can be relative to project or absolute
    'LOG_DIR': os.environ.get('HONEYPOT_LOG_DIR', os.path.join(BASE_DIR, "logs")),
    
    # Honeypot settings
    'HONEYPOT_HOST': os.environ.get('HONEYPOT_HOST', "0.0.0.0"),
    'HONEYPOT_PORT': int(os.environ.get('HONEYPOT_PORT', 8080)),
    
    # Web interface settings
    'WEB_HOST': os.environ.get('HONEYPOT_WEB_HOST', "0.0.0.0"),
    'WEB_PORT': int(os.environ.get('HONEYPOT_WEB_PORT', 5000)),
    'DEBUG': os.environ.get('HONEYPOT_DEBUG', "True").lower() in ('true', '1', 't'),
}
""")
    
    print("Setup complete! You can now run the honeypot with: python run.py")

if __name__ == "__main__":
    setup_honeypot()
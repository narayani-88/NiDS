#!/usr/bin/env python3
"""
LAN Security Monitor - Installation Script
Automated installation and setup script for LAN Security Monitor.
"""

import os
import sys
import subprocess
import platform
import urllib.request
import zipfile
import shutil
from pathlib import Path

def print_banner():
    """Print installation banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║              LAN Security Monitor Installer                  ║
║                                                              ║
║  This script will install and configure LAN Security        ║
║  Monitor on your system.                                     ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)

def check_python_version():
    """Check if Python version is compatible"""
    print("Checking Python version...")
    
    if sys.version_info < (3, 7):
        print("❌ Error: Python 3.7 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    
    print(f"✅ Python {sys.version.split()[0]} is compatible")
    return True

def check_system_requirements():
    """Check system requirements"""
    print("\nChecking system requirements...")
    
    system = platform.system()
    print(f"Operating System: {system}")
    
    # Check for required system tools
    required_tools = []
    
    if system == "Windows":
        required_tools = ["ping"]
    else:
        required_tools = ["ping", "nmap"]
    
    missing_tools = []
    for tool in required_tools:
        try:
            subprocess.run([tool, "--help" if tool != "ping" else "/?"], 
                         capture_output=True, timeout=5)
            print(f"✅ {tool} is available")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print(f"❌ {tool} is not available")
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"\n⚠️  Missing tools: {', '.join(missing_tools)}")
        if system == "Linux":
            print("Install with: sudo apt-get install nmap")
        elif system == "Darwin":  # macOS
            print("Install with: brew install nmap")
        elif system == "Windows":
            print("Download nmap from: https://nmap.org/download.html")
        
        return False
    
    return True

def install_python_packages():
    """Install required Python packages"""
    print("\nInstalling Python packages...")
    
    packages = [
        "python-nmap",
        "scapy",
        "psutil",
        "flask",
        "requests",
        "netifaces"
    ]
    
    for package in packages:
        print(f"Installing {package}...")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", package
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"✅ {package} installed successfully")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to install {package}")
            return False
    
    return True

def create_directories():
    """Create necessary directories"""
    print("\nCreating directories...")
    
    directories = [
        "logs",
        "reports",
        "templates",
        "static",
        "data"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def setup_configuration():
    """Setup initial configuration"""
    print("\nSetting up configuration...")
    
    # Create a simple config file for user settings
    config_content = """# LAN Security Monitor Configuration
# Edit this file to customize your settings

[DEFAULT]
# Network settings
default_network_range = auto
scan_interval = 300
max_threads = 50

# Web interface
web_host = 0.0.0.0
web_port = 5000

# Email alerts (optional)
email_alerts_enabled = false
smtp_server = smtp.gmail.com
smtp_port = 587
from_email = 
to_email = 

# Logging
log_level = INFO
log_file = logs/lansecmon.log

# Database
database_enabled = false
database_file = data/lansecmon.db
"""
    
    with open("lansecmon.conf", "w") as f:
        f.write(config_content)
    
    print("✅ Configuration file created: lansecmon.conf")

def create_startup_scripts():
    """Create startup scripts for different platforms"""
    print("\nCreating startup scripts...")
    
    system = platform.system()
    
    if system == "Windows":
        # Create batch file for Windows
        batch_content = """@echo off
echo Starting LAN Security Monitor...
python lansecmon.py %*
pause
"""
        with open("lansecmon.bat", "w") as f:
            f.write(batch_content)
        print("✅ Created Windows batch file: lansecmon.bat")
        
        # Create web interface launcher
        web_batch_content = """@echo off
echo Starting LAN Security Monitor Web Interface...
python lansecmon.py web
pause
"""
        with open("lansecmon_web.bat", "w") as f:
            f.write(web_batch_content)
        print("✅ Created web interface launcher: lansecmon_web.bat")
    
    else:
        # Create shell script for Linux/macOS
        shell_content = """#!/bin/bash
echo "Starting LAN Security Monitor..."
python3 lansecmon.py "$@"
"""
        with open("lansecmon.sh", "w") as f:
            f.write(shell_content)
        os.chmod("lansecmon.sh", 0o755)
        print("✅ Created shell script: lansecmon.sh")
        
        # Create web interface launcher
        web_shell_content = """#!/bin/bash
echo "Starting LAN Security Monitor Web Interface..."
python3 lansecmon.py web
"""
        with open("lansecmon_web.sh", "w") as f:
            f.write(web_shell_content)
        os.chmod("lansecmon_web.sh", 0o755)
        print("✅ Created web interface launcher: lansecmon_web.sh")

def setup_permissions():
    """Setup appropriate permissions"""
    print("\nSetting up permissions...")
    
    system = platform.system()
    
    if system != "Windows":
        # Make Python scripts executable
        scripts = ["lansecmon.py", "network_scanner.py", "vulnerability_detector.py", 
                  "monitor.py", "app.py"]
        
        for script in scripts:
            if os.path.exists(script):
                os.chmod(script, 0o755)
                print(f"✅ Made {script} executable")

def run_initial_test():
    """Run initial test to verify installation"""
    print("\nRunning initial test...")
    
    try:
        # Test import of main modules
        import network_scanner
        import vulnerability_detector
        import monitor
        print("✅ All modules imported successfully")
        
        # Test basic functionality
        scanner = network_scanner.NetworkScanner()
        network_range = scanner.get_local_network_range()
        print(f"✅ Auto-detected network range: {network_range}")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def print_usage_instructions():
    """Print usage instructions"""
    instructions = """
╔══════════════════════════════════════════════════════════════╗
║                    Installation Complete!                   ║
╚══════════════════════════════════════════════════════════════╝

🎉 LAN Security Monitor has been successfully installed!

Quick Start:
"""
    
    system = platform.system()
    
    if system == "Windows":
        instructions += """
1. Quick network scan:
   lansecmon.bat scan

2. Detailed scan with vulnerabilities:
   lansecmon.bat scan --detailed --vulns

3. Start web interface:
   lansecmon_web.bat
   Then open: http://localhost:5000

4. Start monitoring:
   lansecmon.bat monitor --interval 600
"""
    else:
        instructions += """
1. Quick network scan:
   ./lansecmon.sh scan

2. Detailed scan with vulnerabilities:
   ./lansecmon.sh scan --detailed --vulns

3. Start web interface:
   ./lansecmon_web.sh
   Then open: http://localhost:5000

4. Start monitoring:
   ./lansecmon.sh monitor --interval 600
"""
    
    instructions += """
Configuration:
- Edit lansecmon.conf to customize settings
- Check logs in the logs/ directory
- Reports are saved in the reports/ directory

Documentation:
- See README.md for detailed documentation
- Run 'python lansecmon.py --help' for all options

Security Note:
- Only use this tool on networks you own or have permission to test
- Some features may require administrator/root privileges

Happy monitoring! 🛡️
"""
    
    print(instructions)

def main():
    """Main installation function"""
    print_banner()
    
    # Check requirements
    if not check_python_version():
        sys.exit(1)
    
    if not check_system_requirements():
        print("\n⚠️  Some system requirements are missing.")
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            print("Installation cancelled.")
            sys.exit(1)
    
    # Install packages
    print("\n" + "="*60)
    print("INSTALLING DEPENDENCIES")
    print("="*60)
    
    if not install_python_packages():
        print("❌ Failed to install required packages")
        sys.exit(1)
    
    # Setup environment
    print("\n" + "="*60)
    print("SETTING UP ENVIRONMENT")
    print("="*60)
    
    create_directories()
    setup_configuration()
    create_startup_scripts()
    setup_permissions()
    
    # Test installation
    print("\n" + "="*60)
    print("TESTING INSTALLATION")
    print("="*60)
    
    if not run_initial_test():
        print("❌ Installation test failed")
        print("Please check the error messages above and try again.")
        sys.exit(1)
    
    # Success!
    print_usage_instructions()

if __name__ == "__main__":
    main()

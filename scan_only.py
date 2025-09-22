#!/usr/bin/env python3
"""
LAN Security Monitor - Scan Only Version
Simple scanner without monitor dependencies for troubleshooting.
"""

import sys
import os
import time
import json
from datetime import datetime
import logging

# Import our modules
from network_scanner import NetworkScanner
from vulnerability_detector import VulnerabilityDetector

def setup_logging():
    """Setup centralized logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('scan_only.log'),
            logging.StreamHandler()
        ]
    )

def print_banner():
    """Print application banner"""
    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                    LAN Security Monitor                      ║
║                      Scan Only Version                      ║
║                                                              ║
║  Network scanning and vulnerability assessment tool         ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)

def scan_network(network_range=None, detailed=False, vulnerabilities=False):
    """Perform network scan"""
    print("Starting network scan...")
    
    scanner = NetworkScanner()
    
    # Determine network range
    if not network_range:
        network_range = scanner.get_local_network_range()
    print(f"Scanning network: {network_range}")
    
    # Perform scan
    start_time = time.time()
    devices = scanner.discover_devices(network_range, use_detailed_scan=detailed)
    scan_duration = time.time() - start_time
    
    print(f"\nScan completed in {scan_duration:.2f} seconds")
    print(f"Found {len(devices)} devices")
    
    # Save results
    scanner.save_results("network_scan_results.json")
    
    vulnerabilities_list = []
    if vulnerabilities:
        print("\nScanning for vulnerabilities...")
        detector = VulnerabilityDetector()
        vulnerabilities_list = detector.scan_all_devices(devices)
        detector.save_report("vulnerability_report.json")
        print(f"Found {len(vulnerabilities_list)} vulnerabilities")
    
    # Print summary
    scanner.print_summary()
    
    # Save to database if enabled
    try:
        from config import Config
        if Config.DATABASE_ENABLED:
            if Config.DATABASE_TYPE.lower() == 'mongodb':
                from mongodb_manager import MongoDBManager
                db = MongoDBManager()
            else:
                from database import DatabaseManager
                db = DatabaseManager()
            
            scan_data = {
                'timestamp': datetime.now().isoformat(),
                'network_range': network_range,
                'devices': devices,
                'vulnerabilities': vulnerabilities_list,
                'scan_duration': scan_duration
            }
            db.save_scan_results(scan_data)
            print(f"✅ Results saved to {Config.DATABASE_TYPE} database")
    except Exception as e:
        print(f"⚠️  Database save failed: {e}")
        print("Results are still available in JSON files")
    
    return devices, vulnerabilities_list

def scan_vulnerabilities_only(input_file="network_scan_results.json"):
    """Scan for vulnerabilities only"""
    print("Scanning for vulnerabilities...")
    
    # Load existing network scan
    try:
        with open(input_file, 'r') as f:
            devices = json.load(f)
    except FileNotFoundError:
        print(f"Error: {input_file} not found. Please run a network scan first.")
        return
    
    detector = VulnerabilityDetector()
    vulnerabilities = detector.scan_all_devices(devices)
    
    detector.print_summary()
    detector.save_report("vulnerability_report.json")
    
    return vulnerabilities

def main():
    """Main function"""
    setup_logging()
    print_banner()
    
    print("Available options:")
    print("1. Quick network scan")
    print("2. Detailed network scan")
    print("3. Network scan with vulnerabilities")
    print("4. Detailed scan with vulnerabilities")
    print("5. Vulnerability scan only (requires existing network scan)")
    print("6. Custom scan")
    
    try:
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == "1":
            scan_network()
        elif choice == "2":
            scan_network(detailed=True)
        elif choice == "3":
            scan_network(vulnerabilities=True)
        elif choice == "4":
            scan_network(detailed=True, vulnerabilities=True)
        elif choice == "5":
            scan_vulnerabilities_only()
        elif choice == "6":
            network_range = input("Enter network range (or press Enter for auto-detection): ").strip()
            detailed = input("Detailed scan? (y/N): ").strip().lower() == 'y'
            vulns = input("Include vulnerabilities? (y/N): ").strip().lower() == 'y'
            
            scan_network(
                network_range if network_range else None,
                detailed=detailed,
                vulnerabilities=vulns
            )
        else:
            print("Invalid choice. Please select 1-6.")
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()

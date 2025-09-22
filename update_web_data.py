#!/usr/bin/env python3
"""
NIDS - Update Web Data Script
Runs the enhanced network scanner and updates the web app data files
"""

import json
import time
from datetime import datetime
from network_scanner import NetworkScanner

def run_enhanced_scan_for_web():
    """Run enhanced scanner and update web app data"""
    print("Running NIDS network scan for web dashboard...")
    
    scanner = NetworkScanner()
    
    # Run comprehensive scan
    devices = scanner.discover_devices(
        network_range=None,  # Auto-detect
        use_detailed_scan=False,  # Quick scan for web
        scan_all_networks=False  # Primary network only
    )
    
    # Generate basic vulnerabilities based on risky ports
    vulnerabilities = []
    risky_ports = {
        21: {"severity": "HIGH", "description": "FTP service exposed", "reason": "Potentially insecure file transfer", "recommendation": "Consider using SFTP instead of FTP"},
        23: {"severity": "HIGH", "description": "Telnet service exposed", "reason": "Unencrypted remote access", "recommendation": "Consider closing port 23 or implementing proper security controls"},
        135: {"severity": "MEDIUM", "description": "RPC service exposed", "reason": "Windows RPC endpoint exposed", "recommendation": "Ensure proper firewall configuration"},
        139: {"severity": "MEDIUM", "description": "NetBIOS service exposed", "reason": "Network file sharing exposed", "recommendation": "Ensure proper NetBIOS security"},
        445: {"severity": "MEDIUM", "description": "SMB service exposed", "reason": "Network file sharing exposed", "recommendation": "Ensure proper SMB security configuration"},
        3389: {"severity": "MEDIUM", "description": "RDP service exposed", "reason": "Remote desktop access exposed", "recommendation": "Ensure strong authentication and consider VPN access"}
    }
    
    scan_time = datetime.now().isoformat()
    
    for ip, device in devices.items():
        for port_info in device.get('ports', []):
            port = port_info.get('port')
            if port in risky_ports:
                vuln_info = risky_ports[port]
                vulnerabilities.append({
                    "type": "Risky Open Port",
                    "severity": vuln_info["severity"],
                    "description": vuln_info["description"] + f" on port {port}",
                    "port": port,
                    "reason": vuln_info["reason"],
                    "recommendation": vuln_info["recommendation"],
                    "ip": ip,
                    "hostname": device.get('hostname', 'Unknown'),
                    "scan_time": scan_time
                })
    
    # Create web app data structure
    web_data = {
        "timestamp": scan_time,
        "devices": devices,
        "vulnerabilities": vulnerabilities,
        "changes": {},
        "alerts": []
    }
    
    # Save to web app data file
    with open('latest_scan.json', 'w') as f:
        json.dump(web_data, f, indent=2)
    
    print(f"✅ Web data updated successfully!")
    print(f"   - Found {len(devices)} devices")
    print(f"   - Identified {len(vulnerabilities)} vulnerabilities")
    print(f"   - Data saved to latest_scan.json")
    
    # Also save a backup
    backup_filename = f"scan_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(backup_filename, 'w') as f:
        json.dump(web_data, f, indent=2)
    
    print(f"   - Backup saved to {backup_filename}")
    
    return web_data

if __name__ == "__main__":
    try:
        data = run_enhanced_scan_for_web()
        print("\n🌐 You can now view the updated data on your web dashboard!")
        print("   Visit: http://localhost:5000")
    except Exception as e:
        print(f"❌ Error updating web data: {e}")
        import traceback
        traceback.print_exc()

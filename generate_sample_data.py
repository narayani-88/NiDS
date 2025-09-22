#!/usr/bin/env python3
"""
Generate sample data for testing the frontend
"""

import json
from datetime import datetime

# Sample device data
sample_devices = {
    "192.168.1.1": {
        "hostname": "Router",
        "os": "Linux",
        "ports": [
            {"port": 80, "service": "HTTP", "state": "open"},
            {"port": 443, "service": "HTTPS", "state": "open"},
            {"port": 22, "service": "SSH", "state": "open"}
        ],
        "scan_time": datetime.now().isoformat()
    },
    "192.168.1.10": {
        "hostname": "Desktop-PC",
        "os": "Windows 10",
        "ports": [
            {"port": 135, "service": "RPC", "state": "open"},
            {"port": 445, "service": "SMB", "state": "open"},
            {"port": 3389, "service": "RDP", "state": "open"}
        ],
        "scan_time": datetime.now().isoformat()
    },
    "192.168.1.19": {
        "hostname": "Your-Computer",
        "os": "Windows",
        "ports": [
            {"port": 5000, "service": "HTTP", "state": "open"},
            {"port": 135, "service": "RPC", "state": "open"}
        ],
        "scan_time": datetime.now().isoformat()
    },
    "192.168.1.7": {
        "hostname": "Mobile-Device",
        "os": "Android",
        "ports": [
            {"port": 8080, "service": "HTTP-Alt", "state": "open"}
        ],
        "scan_time": datetime.now().isoformat()
    }
}

# Sample vulnerabilities
sample_vulnerabilities = [
    {
        "ip": "192.168.1.10",
        "type": "Weak SMB Configuration",
        "severity": "HIGH",
        "description": "SMB service is running with weak security settings",
        "recommendation": "Update SMB configuration and disable SMBv1",
        "port": 445,
        "service": "SMB",
        "scan_time": datetime.now().isoformat()
    },
    {
        "ip": "192.168.1.10",
        "type": "RDP Exposed",
        "severity": "MEDIUM",
        "description": "Remote Desktop Protocol is accessible from network",
        "recommendation": "Restrict RDP access or use VPN",
        "port": 3389,
        "service": "RDP",
        "scan_time": datetime.now().isoformat()
    },
    {
        "ip": "192.168.1.1",
        "type": "Default SSH Configuration",
        "severity": "LOW",
        "description": "SSH is running with default configuration",
        "recommendation": "Harden SSH configuration",
        "port": 22,
        "service": "SSH",
        "scan_time": datetime.now().isoformat()
    }
]

# Sample alerts
sample_alerts = [
    {
        "type": "HIGH_VULNERABILITY_COUNT",
        "severity": "HIGH",
        "message": "Multiple high-severity vulnerabilities detected on 192.168.1.10",
        "timestamp": datetime.now().isoformat(),
        "details": {"ip": "192.168.1.10", "count": 2}
    },
    {
        "type": "NEW_DEVICE",
        "severity": "MEDIUM",
        "message": "New device detected on network: 192.168.1.7",
        "timestamp": datetime.now().isoformat(),
        "details": {"ip": "192.168.1.7"}
    }
]

# Create scan data
scan_data = {
    "timestamp": datetime.now().isoformat(),
    "network_range": "192.168.1.0/24",
    "devices": sample_devices,
    "vulnerabilities": sample_vulnerabilities,
    "changes": {},
    "alerts": sample_alerts
}

# Save sample data files
with open('latest_scan.json', 'w') as f:
    json.dump(scan_data, f, indent=2)

with open('network_scan_results.json', 'w') as f:
    json.dump(sample_devices, f, indent=2)

with open('vulnerability_report.json', 'w') as f:
    json.dump(sample_vulnerabilities, f, indent=2)

with open('latest_alerts.json', 'w') as f:
    json.dump(sample_alerts, f, indent=2)

print("Sample data generated successfully!")
print(f"- {len(sample_devices)} devices")
print(f"- {len(sample_vulnerabilities)} vulnerabilities") 
print(f"- {len(sample_alerts)} alerts")
print("\nFiles created:")
print("- latest_scan.json")
print("- network_scan_results.json")
print("- vulnerability_report.json")
print("- latest_alerts.json")

#!/usr/bin/env python3
"""
Test script for the enhanced network scanner
Runs automatically without user input to test improvements
"""

import time
from network_scanner import NetworkScanner

def test_enhanced_scanner():
    """Test the enhanced network scanner"""
    print("Testing NIDS Network Scanner")
    print("=" * 30)
    
    scanner = NetworkScanner()
    
    # Test 1: Show detected network ranges
    print("\n1. Detecting network ranges...")
    primary_range = scanner.get_local_network_range()
    all_ranges = scanner.get_all_network_ranges()
    
    print(f"Primary network range: {primary_range}")
    print(f"All network ranges: {all_ranges}")
    
    # Test 2: ARP table scan
    print("\n2. Checking ARP table...")
    arp_devices = scanner.get_arp_table()
    print(f"Devices found in ARP table: {len(arp_devices)}")
    for device in arp_devices[:5]:  # Show first 5
        print(f"  - {device}")
    if len(arp_devices) > 5:
        print(f"  ... and {len(arp_devices) - 5} more")
    
    # Test 3: Quick network scan (primary range only)
    print(f"\n3. Quick scan of primary range: {primary_range}")
    start_time = time.time()
    
    devices = scanner.discover_devices(
        network_range=primary_range, 
        use_detailed_scan=False,
        scan_all_networks=False
    )
    
    end_time = time.time()
    
    print(f"\nScan Results:")
    print(f"- Scan time: {end_time - start_time:.2f} seconds")
    print(f"- Devices found: {len(devices)}")
    
    # Show device summary
    if devices:
        print("\nDevice Summary:")
        for ip, info in sorted(devices.items()):
            hostname = info.get('hostname', 'Unknown')
            ports = len(info.get('ports', []))
            print(f"  {ip:15} | {hostname:20} | {ports:2} ports")
    
    # Save results
    scanner.save_results("test_scan_results.json")
    print(f"\nResults saved to test_scan_results.json")
    
    return devices

if __name__ == "__main__":
    try:
        devices = test_enhanced_scanner()
        print(f"\n✅ Test completed successfully! Found {len(devices)} devices.")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

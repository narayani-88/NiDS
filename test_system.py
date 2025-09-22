#!/usr/bin/env python3
"""
LAN Security Monitor - System Test Script
Quick test to verify all components are working correctly.
"""

import sys
import os
import json
import time
from datetime import datetime

def print_header(title):
    """Print a formatted header"""
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

def test_imports():
    """Test if all modules can be imported"""
    print_header("TESTING MODULE IMPORTS")
    
    modules = [
        'network_scanner',
        'vulnerability_detector', 
        'monitor',
        'database',
        'config'
    ]
    
    success = True
    for module in modules:
        try:
            __import__(module)
            print(f"✅ {module} imported successfully")
        except ImportError as e:
            print(f"❌ Failed to import {module}: {e}")
            success = False
    
    return success

def test_network_scanner():
    """Test network scanner functionality"""
    print_header("TESTING NETWORK SCANNER")
    
    try:
        from network_scanner import NetworkScanner
        
        scanner = NetworkScanner()
        print("✅ NetworkScanner created successfully")
        
        # Test network range detection
        network_range = scanner.get_local_network_range()
        print(f"✅ Auto-detected network range: {network_range}")
        
        # Test ping functionality
        test_ip = "127.0.0.1"  # localhost should always be available
        if scanner.ping_host(test_ip):
            print(f"✅ Ping test successful for {test_ip}")
        else:
            print(f"⚠️  Ping test failed for {test_ip}")
        
        return True
        
    except Exception as e:
        print(f"❌ Network scanner test failed: {e}")
        return False

def test_vulnerability_detector():
    """Test vulnerability detector"""
    print_header("TESTING VULNERABILITY DETECTOR")
    
    try:
        from vulnerability_detector import VulnerabilityDetector
        
        detector = VulnerabilityDetector()
        print("✅ VulnerabilityDetector created successfully")
        
        # Test with dummy device data
        test_device = {
            'ip': '127.0.0.1',
            'hostname': 'localhost',
            'ports': [
                {'port': 80, 'service': 'HTTP'},
                {'port': 22, 'service': 'SSH'}
            ]
        }
        
        vulns = detector.scan_device_vulnerabilities(test_device)
        print(f"✅ Vulnerability scan completed, found {len(vulns)} potential issues")
        
        return True
        
    except Exception as e:
        print(f"❌ Vulnerability detector test failed: {e}")
        return False

def test_database():
    """Test database functionality"""
    print_header("TESTING DATABASE")
    
    try:
        from database import DatabaseManager
        
        # Use a test database
        db = DatabaseManager('test_lansecmon.db')
        print("✅ Database created successfully")
        
        # Test saving data
        test_data = {
            'timestamp': datetime.now().isoformat(),
            'devices': {
                '127.0.0.1': {
                    'hostname': 'localhost',
                    'ports': [{'port': 80, 'service': 'HTTP'}]
                }
            },
            'vulnerabilities': []
        }
        
        scan_id = db.save_scan_results(test_data)
        print(f"✅ Test data saved with scan ID: {scan_id}")
        
        # Test statistics
        stats = db.get_statistics()
        print(f"✅ Database statistics retrieved: {stats}")
        
        # Cleanup test database
        os.remove('test_lansecmon.db')
        print("✅ Test database cleaned up")
        
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_config():
    """Test configuration"""
    print_header("TESTING CONFIGURATION")
    
    try:
        from config import Config
        
        print(f"✅ Configuration loaded successfully")
        print(f"   - Version: {Config.VERSION}")
        print(f"   - Default scan interval: {Config.DEFAULT_SCAN_INTERVAL}")
        print(f"   - Max threads: {Config.MAX_SCAN_THREADS}")
        
        # Test configuration validation
        errors = Config.validate_config()
        if errors:
            print(f"⚠️  Configuration warnings: {errors}")
        else:
            print("✅ Configuration validation passed")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_web_app():
    """Test web application"""
    print_header("TESTING WEB APPLICATION")
    
    try:
        from app import app
        
        # Test app creation
        print("✅ Flask app created successfully")
        
        # Test template creation
        from app import create_templates
        if not os.path.exists('templates'):
            create_templates()
            print("✅ Templates created successfully")
        else:
            print("✅ Templates already exist")
        
        return True
        
    except Exception as e:
        print(f"❌ Web application test failed: {e}")
        return False

def test_main_launcher():
    """Test main launcher"""
    print_header("TESTING MAIN LAUNCHER")
    
    try:
        # Import the main module
        import lansecmon
        print("✅ Main launcher imported successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Main launcher test failed: {e}")
        return False

def run_quick_scan_test():
    """Run a quick scan test on localhost"""
    print_header("RUNNING QUICK SCAN TEST")
    
    try:
        from network_scanner import NetworkScanner
        
        scanner = NetworkScanner()
        
        # Scan localhost only for testing
        print("Testing localhost scan...")
        devices = scanner.discover_devices("127.0.0.1/32", use_detailed_scan=False)
        
        if devices:
            print(f"✅ Quick scan successful, found {len(devices)} device(s)")
            for ip, device in devices.items():
                print(f"   - {ip}: {device.get('hostname', 'Unknown')} ({len(device.get('ports', []))} ports)")
        else:
            print("⚠️  No devices found in quick scan")
        
        return True
        
    except Exception as e:
        print(f"❌ Quick scan test failed: {e}")
        return False

def main():
    """Main test function"""
    print("LAN Security Monitor - System Test")
    print("==================================")
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tests = [
        ("Module Imports", test_imports),
        ("Configuration", test_config),
        ("Network Scanner", test_network_scanner),
        ("Vulnerability Detector", test_vulnerability_detector),
        ("Database", test_database),
        ("Web Application", test_web_app),
        ("Main Launcher", test_main_launcher),
        ("Quick Scan", run_quick_scan_test)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Print summary
    print_header("TEST SUMMARY")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"Tests passed: {passed}/{total}")
    print(f"Success rate: {(passed/total)*100:.1f}%")
    print()
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    if passed == total:
        print("\n🎉 All tests passed! The system is ready to use.")
        print("\nNext steps:")
        print("1. Run 'python lansecmon.py scan' for a quick network scan")
        print("2. Run 'python lansecmon.py web' to start the web interface")
        print("3. Check USAGE_EXAMPLES.md for detailed usage instructions")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the errors above.")
        print("You may need to install missing dependencies or fix configuration issues.")
    
    print(f"\nTest completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()

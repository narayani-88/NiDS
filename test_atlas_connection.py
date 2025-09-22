#!/usr/bin/env python3
"""
Test MongoDB Atlas Connection
Quick test to verify Atlas connection is working.
"""

import sys
import os
from datetime import datetime

def test_atlas_connection():
    """Test the MongoDB Atlas connection"""
    print("Testing MongoDB Atlas Connection")
    print("=" * 40)
    
    try:
        # Load environment variables
        from dotenv import load_dotenv
        load_dotenv()
        print("✅ Environment variables loaded")
        
        # Import MongoDB manager
        from mongodb_manager import MongoDBManager
        print("✅ MongoDB manager imported")
        
        # Create connection
        print("Connecting to Atlas...")
        db = MongoDBManager()
        print("✅ Connected to MongoDB Atlas successfully!")
        
        # Test basic operations
        print("\nTesting database operations...")
        
        # Test data
        test_scan_data = {
            'timestamp': datetime.now().isoformat(),
            'network_range': '127.0.0.1/32',
            'scan_type': 'test',
            'devices': {
                '127.0.0.1': {
                    'hostname': 'localhost',
                    'os': 'Test OS',
                    'ports': [
                        {'port': 80, 'service': 'HTTP', 'state': 'open'}
                    ],
                    'scan_time': datetime.now().isoformat()
                }
            },
            'vulnerabilities': [
                {
                    'ip': '127.0.0.1',
                    'type': 'Test Vulnerability',
                    'severity': 'LOW',
                    'description': 'This is a test vulnerability',
                    'recommendation': 'This is a test recommendation',
                    'port': 80,
                    'service': 'HTTP',
                    'scan_time': datetime.now().isoformat()
                }
            ]
        }
        
        # Save test data
        scan_id = db.save_scan_results(test_scan_data)
        print(f"✅ Test scan saved with ID: {scan_id}")
        
        # Test alerts
        test_alerts = [
            {
                'timestamp': datetime.now().isoformat(),
                'type': 'TEST_ALERT',
                'severity': 'LOW',
                'message': 'This is a test alert',
                'details': {'ip': '127.0.0.1', 'test': True}
            }
        ]
        
        db.save_alerts(test_alerts)
        print("✅ Test alerts saved")
        
        # Get statistics
        stats = db.get_statistics()
        print(f"✅ Database statistics retrieved:")
        print(f"   - Total scans: {stats.get('total_scans', 0)}")
        print(f"   - Total devices: {stats.get('total_devices', 0)}")
        print(f"   - Total vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
        print(f"   - Total alerts: {stats.get('total_alerts', 0)}")
        
        # Get scan history
        history = db.get_scan_history(limit=5)
        print(f"✅ Retrieved {len(history)} recent scans")
        
        # Close connection
        db.close_connection()
        print("✅ Connection closed")
        
        print("\n🎉 All tests passed! Your MongoDB Atlas is ready to use.")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Please install required packages: pip install pymongo python-dotenv dnspython")
        return False
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print("\nTroubleshooting tips:")
        print("1. Check your internet connection")
        print("2. Verify your Atlas cluster is running")
        print("3. Ensure your IP is whitelisted in Atlas Network Access")
        print("4. Verify username and password are correct")
        print("5. Check if the database name exists")
        return False

def main():
    """Main test function"""
    print("LAN Security Monitor - Atlas Connection Test")
    print("=" * 50)
    
    # Check if .env file exists
    if not os.path.exists('.env'):
        print("❌ .env file not found")
        print("Please create .env file with your Atlas credentials")
        return
    
    # Run connection test
    success = test_atlas_connection()
    
    if success:
        print("\nNext steps:")
        print("1. Run: python lansecmon.py scan --vulnerabilities")
        print("2. Start web interface: python lansecmon.py web")
        print("3. Your data will be stored in MongoDB Atlas!")
    else:
        print("\nPlease fix the connection issues and try again.")

if __name__ == "__main__":
    main()

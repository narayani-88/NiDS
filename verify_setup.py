#!/usr/bin/env python3
"""
Verify LAN Security Monitor Setup with MongoDB Atlas
"""

import os
import sys

def check_requirements():
    """Check if all required packages are installed"""
    print("Checking Python packages...")
    
    # Package name mapping: pip_name -> import_name
    required_packages = {
        'pymongo': 'pymongo',
        'dnspython': 'dns',
        'python-dotenv': 'dotenv',
        'flask': 'flask',
        'requests': 'requests',
        'netifaces': 'netifaces',
        'psutil': 'psutil'
    }
    
    missing_packages = []
    
    for pip_name, import_name in required_packages.items():
        try:
            __import__(import_name)
            print(f"✅ {pip_name}")
        except ImportError:
            print(f"❌ {pip_name}")
            missing_packages.append(pip_name)
    
    if missing_packages:
        print(f"\nMissing packages: {', '.join(missing_packages)}")
        print("Install with: pip install " + " ".join(missing_packages))
        return False
    
    return True

def check_config():
    """Check configuration"""
    print("\nChecking configuration...")
    
    if not os.path.exists('.env'):
        print("❌ .env file not found")
        return False
    
    print("✅ .env file exists")
    
    try:
        from dotenv import load_dotenv
        load_dotenv()
        
        # Check environment variables
        db_type = os.environ.get('DATABASE_TYPE')
        connection_string = os.environ.get('MONGODB_CONNECTION_STRING')
        
        if db_type == 'mongodb':
            print("✅ Database type set to MongoDB")
            if connection_string and 'mongodb+srv://' in connection_string:
                print("✅ MongoDB Atlas connection string configured")
                return True
            else:
                print("❌ Invalid MongoDB connection string")
                return False
        else:
            print(f"⚠️  Database type is {db_type}, not MongoDB")
            return True
            
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False

def main():
    """Main verification function"""
    print("LAN Security Monitor - Setup Verification")
    print("=" * 45)
    
    print("Your Atlas Connection String:")
    print("mongodb+srv://narayanip868_db_user:***@nids.bepzfrc.mongodb.net/")
    print()
    
    # Check requirements
    if not check_requirements():
        print("\n❌ Setup incomplete - missing packages")
        return
    
    # Check configuration
    if not check_config():
        print("\n❌ Setup incomplete - configuration issues")
        return
    
    print("\n✅ Setup verification complete!")
    print("\nNext steps:")
    print("1. Test Atlas connection: python test_atlas_connection.py")
    print("2. Run network scan: python lansecmon.py scan --vulnerabilities")
    print("3. Start web interface: python lansecmon.py web")
    print("\nYour scan data will be stored in MongoDB Atlas! 🚀")

if __name__ == "__main__":
    main()

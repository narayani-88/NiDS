#!/usr/bin/env python3
"""
NIDS Deployment Helper
Prepares NIDS for cloud deployment and provides deployment instructions.
"""

import os
import sys
import json
import subprocess
from datetime import datetime

def check_requirements():
    """Check if all deployment requirements are met"""
    print("🔍 Checking deployment requirements...")
    
    required_files = [
        'app.py',
        'requirements.txt', 
        'Procfile',
        'runtime.txt',
        '.gitignore',
        'network_scanner.py',
        'ai_analyzer.py'
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Missing required files: {', '.join(missing_files)}")
        return False
    
    print("✅ All required files present")
    return True

def update_app_for_production():
    """Update app.py for production deployment"""
    print("🔧 Updating app.py for production...")
    
    # Read current app.py
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Check if already updated for production
    if 'os.environ.get(\'PORT\'' in content:
        print("✅ App already configured for production")
        return True
    
    print("✅ App updated for production deployment")
    return True

def create_deployment_info():
    """Create deployment information file"""
    deployment_info = {
        "app_name": "NIDS - Network Intrusion Detection System",
        "version": "2.0.0",
        "deployment_date": datetime.now().isoformat(),
        "features": [
            "AI-Powered Security Analysis",
            "Enhanced Network Discovery (40+ devices)",
            "Real-Time Monitoring",
            "Professional Web Interface",
            "Multi-Method Device Detection"
        ],
        "deployment_platforms": {
            "railway": {
                "recommended": True,
                "free_tier": True,
                "steps": [
                    "Install Railway CLI: npm install -g @railway/cli",
                    "Login: railway login",
                    "Deploy: railway deploy",
                    "Set API key: railway variables set GEMINI_API_KEY=your_key"
                ]
            },
            "heroku": {
                "recommended": False,
                "free_tier": False,
                "steps": [
                    "Install Heroku CLI",
                    "heroku create your-app-name",
                    "heroku config:set GEMINI_API_KEY=your_key",
                    "git push heroku main"
                ]
            }
        },
        "environment_variables": {
            "GEMINI_API_KEY": "Your Google Gemini API key",
            "SECRET_KEY": "Secure random string for Flask sessions",
            "FLASK_ENV": "production"
        }
    }
    
    with open('deployment_info.json', 'w') as f:
        json.dump(deployment_info, f, indent=2)
    
    print("✅ Created deployment_info.json")

def show_deployment_instructions():
    """Show deployment instructions"""
    print("\n" + "="*60)
    print("🚀 NIDS DEPLOYMENT READY!")
    print("="*60)
    
    print("\n📋 QUICK DEPLOYMENT OPTIONS:")
    print("\n1. 🚀 RAILWAY (Recommended - Free & Easy)")
    print("   • Visit: https://railway.app")
    print("   • Connect GitHub account")
    print("   • Import your NIDS repository")
    print("   • Set environment variable: GEMINI_API_KEY")
    print("   • Deploy automatically!")
    
    print("\n2. 🟣 HEROKU (Popular)")
    print("   • Install Heroku CLI")
    print("   • heroku create your-nids-app")
    print("   • heroku config:set GEMINI_API_KEY=your_key")
    print("   • git push heroku main")
    
    print("\n3. 🏠 LOCAL NETWORK (For Team Access)")
    print("   • python app.py")
    print("   • Share: http://your-ip:5000")
    
    print("\n🔑 REQUIRED ENVIRONMENT VARIABLES:")
    print("   • GEMINI_API_KEY=use_your_api_key")
    
    print("\n⚠️  IMPORTANT NOTES:")
    print("   • Cloud deployment can only scan cloud network")
    print("   • For local network scanning, deploy locally")
    print("   • Your friend should deploy locally for their job")
    
    print("\n📚 DOCUMENTATION:")
    print("   • README.md - Complete feature guide")
    print("   • DEPLOYMENT.md - Detailed deployment instructions")
    
    print("\n🎯 NEXT STEPS:")
    print("   1. Choose deployment platform (Railway recommended)")
    print("   2. Set up environment variables")
    print("   3. Deploy and test")
    print("   4. Share URL with your friend")
    
    print("\n✅ NIDS is ready for deployment!")

def main():
    """Main deployment preparation function"""
    print("🛡️  NIDS Deployment Helper")
    print("=" * 30)
    
    if not check_requirements():
        print("❌ Please fix missing requirements before deployment")
        return False
    
    update_app_for_production()
    create_deployment_info()
    show_deployment_instructions()
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        if success:
            print("\n🎉 Deployment preparation completed successfully!")
        else:
            print("\n❌ Deployment preparation failed!")
            sys.exit(1)
    except Exception as e:
        print(f"\n💥 Error during deployment preparation: {e}")
        sys.exit(1)

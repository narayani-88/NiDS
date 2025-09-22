# NIDS - Network Intrusion Detection System

🛡️ **A comprehensive AI-powered network security monitoring and vulnerability assessment tool designed for modern networks.** 

NIDS helps network administrators, security professionals, and IT teams identify potential security risks, monitor network changes in real-time, and maintain robust network security posture with intelligent insights.

## 🚀 Key Features

### 🤖 AI-Powered Analysis
- **Google Gemini Integration**: Advanced AI analysis of network security data
- **Intelligent Risk Assessment**: Automated security posture evaluation
- **Smart Recommendations**: Prioritized, actionable security guidance
- **Compliance Insights**: Regulatory and best practice compliance checking
- **Fallback Analysis**: Rule-based intelligent analysis when AI is unavailable

### 🔍 Enhanced Network Discovery
- **Multi-Method Detection**: ARP table scanning + ping sweep + TCP connect
- **Comprehensive Device Discovery**: Finds 40+ devices vs traditional methods
- **Multiple Network Interface Support**: Scans all network segments
- **Improved Timeout Logic**: Better detection of slow-responding devices
- **Hostname Resolution**: Automatic device name identification

### 📊 Real-Time Monitoring
- **Continuous Network Surveillance**: Configurable scan intervals (1 min - 1 hour)
- **Change Detection**: Alerts on new/removed devices and port changes
- **Live Dashboard**: Real-time status updates and metrics
- **Alert Management**: Severity-based notification system
- **Historical Tracking**: Trend analysis and pattern recognition

### 🌐 Modern Web Interface
- **Professional Dashboard**: Clean, responsive design with custom branding
- **Interactive Device Management**: Detailed device information and controls
- **Vulnerability Visualization**: Risk-based security issue presentation
- **AI Analysis Reports**: Comprehensive security insights and recommendations
- **Mobile-Friendly**: Works on all devices and screen sizes

### 🔒 Advanced Security Checks
- **Risky Protocol Detection**: Telnet, FTP, unencrypted HTTP identification
- **Port Security Analysis**: 40+ common ports with service fingerprinting
- **SSL/TLS Assessment**: Certificate and encryption vulnerability detection
- **Network Service Auditing**: SMB, RDP, SSH, database exposure analysis
- **Compliance Monitoring**: Security standard adherence checking
- **Risk Scoring**: Automated 0-100 risk assessment with color coding

### Security Checks
- **Weak/Default Credentials**: Tests for common weak passwords on various services
- **SSL/TLS Vulnerabilities**: Checks for weak encryption and certificate issues
- **Open Port Analysis**: Identifies risky services exposed to the network
- **Web Application Security**: Basic checks for common web vulnerabilities
- **SMB/NetBIOS Issues**: Detects SMB-related security risks
- **Database Exposure**: Identifies exposed database services
- **Network Service Misconfiguration**: Detects insecure service configurations

## 📋 Requirements

- **Python**: 3.7 or higher
- **Operating System**: Windows, Linux, or macOS
- **Network Access**: Local network access for scanning
- **Optional**: Administrator/root privileges for advanced scanning features

## 🛠️ Installation

### Prerequisites
- **Python 3.8+** (Required for AI features)
- **pip** (Python package installer)
- **Administrative privileges** (for network scanning)
- **Network access** to target systems
- **Google Gemini API Key** (for AI analysis - free tier available)

### 🚀 Quick Install
```bash
# Clone the repository
git clone https://github.com/yourusername/nids.git
cd nids

# Install dependencies
pip install -r requirements.txt

# Configure API key (optional - fallback analysis available)
export GEMINI_API_KEY="your_api_key_here"

# Run NIDS
python app.py
```

### 📦 Dependencies
```bash
# Core dependencies
pip install flask python-nmap netifaces google-generativeai

# Optional dependencies for enhanced features
pip install requests beautifulsoup4 cryptography
```

### 🔧 Configuration
1. **API Key Setup**: Add your Gemini API key to `app.py` or environment variables
2. **Network Configuration**: Adjust scan ranges in the web interface
3. **Monitoring Settings**: Configure scan intervals and alert thresholds

## 🎯 Usage

### 🌐 Web Interface (Recommended)
1. **Start NIDS Server**:
   ```bash
   python app.py
   ```
2. **Access Dashboard**: Open `http://localhost:5000` in your browser
3. **Navigate Features**:
   - **📊 Dashboard**: Overview of network security status
   - **🖥️ Devices**: Detailed device list with 40+ discovered devices
   - **🛡️ Vulnerabilities**: Security issues and risk assessment
   - **🔔 Alerts**: Real-time security notifications
   - **📡 Monitoring**: Continuous network surveillance
   - **🤖 AI Analysis**: Generate intelligent security reports

### 🤖 AI Analysis Features
```bash
# Generate AI-powered security report
# 1. Click "AI Analysis" in navigation
# 2. Click "Generate Analysis" button
# 3. Wait 30-60 seconds for comprehensive report
# 4. Review security assessment, risks, and recommendations
```

### 📡 Real-Time Monitoring
```bash
# Start continuous monitoring
# 1. Navigate to "Monitoring" page
# 2. Configure scan interval (1 min - 1 hour)
# 3. Set network range (optional - auto-detects)
# 4. Click "Start Monitoring"
# 5. View real-time alerts and status updates
```

### 💻 Command Line Interface
```bash
# Enhanced network scan with ARP detection
python network_scanner.py

# Test enhanced scanner
python test_enhanced_scanner.py

# Update web data with latest scan
python update_web_data.py

# Simple monitoring (no web interface)
python simple_monitoring.py
```

## 🔑 API Configuration
```python
# Google Gemini AI API Key (in app.py)
GEMINI_API_KEY = "your_gemini_api_key_here"

# Get free API key at: https://makersuite.google.com/app/apikey
```

## 🌐 Network Configuration
```python
# Enhanced scanning settings
SCAN_TIMEOUT = 3          # Improved timeout for better detection
MAX_THREADS = 50          # Concurrent scanning threads
EXPANDED_PORTS = [         # 40+ common ports for comprehensive scanning
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389,
    8080, 8443, 8000, 9000, 5000, 631, 515, 161, 162, 389, 636, 1433, 1521,
    5984, 6379, 27017, 9200, 5601, 3000, 4000, 5900, 5901, 8888, 9090, 10000
]

# Multi-method discovery
ENABLE_ARP_SCANNING = True    # ARP table integration
ENABLE_TCP_CONNECT = True     # TCP connect scanning
SCAN_ALL_INTERFACES = False   # Multiple network interface support
```

## 📡 Monitoring Configuration
```python
# Real-time monitoring settings
MONITOR_INTERVALS = [60, 300, 600, 1800, 3600]  # Available intervals
DEFAULT_INTERVAL = 300        # 5 minutes default
ALERT_RETENTION = 50          # Keep last 50 alerts
STATUS_POLL_INTERVAL = 10     # Status update frequency (seconds)
```

## 🎨 Interface Configuration
```python
# Web interface settings
APP_NAME = "NIDS"             # Application branding
LOGO_PATH = "static/logo.png" # Custom logo location
FAVICON_PATH = "static/"      # Favicon files location
THEME_COLOR = "primary"       # Bootstrap theme color
```

## 🔒 Security & Privacy

### ⚠️ Important Security Considerations
- **🔐 Authorization Required**: Only use NIDS on networks you own or have explicit written permission to scan
- **🌐 Network Impact**: Enhanced scanning generates more traffic; configure appropriate intervals
- **🔑 API Key Security**: Keep your Gemini API key secure and never commit it to version control
- **📊 Data Privacy**: Scan results contain sensitive network topology and device information
- **🛡️ Production Security**: Implement authentication, HTTPS, and access controls for production use
- **🚨 Responsible Disclosure**: Report security vulnerabilities responsibly

### 🔐 Production Deployment Security
```python
# Recommended production settings
app.secret_key = 'secure_random_key_here'  # Change default key
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Use environment variables for sensitive data
import os
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
```

## 🌐 Deployment Options

### 🚀 Cloud Deployment
```bash
# For cloud deployment (Heroku, Railway, etc.)
# 1. Add Procfile: web: python app.py
# 2. Set environment variables for API keys
# 3. Configure port binding: app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
```

### 🏠 Local Network Deployment
```bash
# Run on local network for team access
python app.py  # Access via http://your-ip:5000
```

## 🤝 Contributing

We welcome contributions to make NIDS even better!

### 🛠️ Development Setup
```bash
# Clone and setup
git clone https://github.com/yourusername/nids.git
cd nids
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run development server
python app.py
```

### 🎯 Areas for Contribution
- 🤖 Enhanced AI analysis features
- 📊 Additional visualization components
- 🔍 New vulnerability detection methods
- 🌐 Mobile app development
- 📚 Documentation improvements
- 🧪 Test coverage expansion

## 🐛 Troubleshooting

### Common Issues

1. **Permission Errors**: Run with administrator/root privileges for advanced features
2. **Network Access**: Ensure proper network connectivity and firewall settings
3. **Slow Scans**: Reduce scan scope or increase scan intervals
4. **Missing Dependencies**: Run `python install.py` to reinstall requirements

### Log Files
Check these log files for detailed error information:
- `nids.log` - Main application log
- `network_scan.log` - Network scanning details
- `vulnerability_scan.log` - Vulnerability assessment log
- `webapp.log` - Web interface log

### Debug Mode
Enable debug logging by setting `LOG_LEVEL = DEBUG` in configuration.

## 🔌 API Documentation

### 🚀 Enhanced REST Endpoints

#### 🤖 AI Analysis
- `POST /api/ai-analysis` - Generate AI-powered security analysis
- `GET /ai-analysis` - View AI analysis dashboard

#### 📊 Scanning & Data
- `POST /api/scan` - Trigger enhanced network scan with ARP detection
- `GET /api/data/latest` - Get latest comprehensive scan results
- `GET /api/device/{ip}` - Get detailed device information

#### 📡 Real-Time Monitoring
- `POST /api/monitoring/start` - Start continuous monitoring with configuration
- `POST /api/monitoring/stop` - Stop active monitoring
- `GET /api/monitoring/status` - Get real-time monitoring status

#### 🔔 Alerts & Notifications
- `GET /api/alerts/latest` - Get recent security alerts
- `GET /alerts` - View alerts dashboard

#### 🛠️ System
- `GET /api/test` - Test API connectivity and feature availability
- `GET /debug` - System debug information

### 📝 API Examples
```bash
# Start AI analysis
curl -X POST http://localhost:5000/api/ai-analysis

# Start monitoring with custom interval
curl -X POST http://localhost:5000/api/monitoring/start \
  -H "Content-Type: application/json" \
  -d '{"scan_interval": 300, "detailed_scan": false}'

# Get device details
curl http://localhost:5000/api/device/192.168.1.6

# Check monitoring status
curl http://localhost:5000/api/monitoring/status
```

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**NIDS is designed for legitimate network security assessment and monitoring purposes only.** 

- 🔐 **Authorization Required**: Users must have explicit permission to scan target networks
- 🛡️ **Responsible Use**: Follow ethical hacking and responsible disclosure practices
- ⚖️ **Legal Compliance**: Ensure compliance with local laws and regulations
- 🚫 **No Liability**: Developers assume no responsibility for misuse or unauthorized access

## 🆘 Support & Community

### 📞 Get Help
1. 📖 **Documentation**: Check the comprehensive guides above
2. 🐛 **Issues**: Search [GitHub Issues](https://github.com/yourusername/nids/issues)
3. 💬 **Discussions**: Join [Community Discussions](https://github.com/yourusername/nids/discussions)
4. 📧 **Contact**: Create a new issue for bugs or feature requests

## 🔄 Version History

- **v1.0.0** - Initial release with core functionality
  - Network discovery and port scanning
  - Vulnerability detection
  - Web dashboard
  - Real-time monitoring
  - Database storage
  - Comprehensive reporting

---

**Remember**: Use this tool responsibly and ethically. Always ensure you have proper authorization before scanning any network!

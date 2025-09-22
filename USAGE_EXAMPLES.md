# LAN Security Monitor - Usage Examples

This document provides practical examples of how to use the LAN Security Monitor tool for various network security scenarios.

## Table of Contents
- [Basic Network Discovery](#basic-network-discovery)
- [Vulnerability Assessment](#vulnerability-assessment)
- [Continuous Monitoring](#continuous-monitoring)
- [Web Dashboard Usage](#web-dashboard-usage)
- [Advanced Scenarios](#advanced-scenarios)
- [Troubleshooting](#troubleshooting)

## Basic Network Discovery

### Quick Network Scan
Perform a basic scan of your local network:

```bash
# Windows
python lansecmon.py scan

# Linux/macOS
python3 lansecmon.py scan
```

This will:
- Auto-detect your network range
- Discover all active devices
- Identify open ports and services
- Generate a summary report

### Scan Specific Network Range
Target a specific network subnet:

```bash
python lansecmon.py scan --network 192.168.1.0/24
```

### Detailed Network Scan
Perform an in-depth scan with OS detection:

```bash
python lansecmon.py scan --detailed
```

**Note:** Detailed scans take longer but provide more information about each device.

### Save Results to Custom File
Specify a custom output file:

```bash
python lansecmon.py scan --output my_network_scan.json
```

## Vulnerability Assessment

### Basic Vulnerability Scan
Scan for vulnerabilities after discovering devices:

```bash
python lansecmon.py scan --vulnerabilities
```

### Vulnerability-Only Scan
Scan for vulnerabilities using existing network data:

```bash
python lansecmon.py vulns
```

### Custom Input/Output Files
Use specific files for vulnerability scanning:

```bash
python lansecmon.py vulns --input my_scan.json --output my_vulns.json
```

### Combined Detailed Scan
Perform comprehensive scanning in one command:

```bash
python lansecmon.py scan --detailed --vulnerabilities --output complete_assessment.json
```

## Continuous Monitoring

### Start Basic Monitoring
Monitor your network with default 5-minute intervals:

```bash
python lansecmon.py monitor
```

### Custom Monitoring Interval
Set a specific monitoring interval (in seconds):

```bash
# Monitor every 10 minutes
python lansecmon.py monitor --interval 600

# Monitor every hour
python lansecmon.py monitor --interval 3600
```

### Monitor Specific Network
Monitor a particular network range:

```bash
python lansecmon.py monitor --network 10.0.0.0/24 --interval 300
```

### Background Monitoring
Run monitoring in the background (Linux/macOS):

```bash
nohup python3 lansecmon.py monitor --interval 600 > monitor.log 2>&1 &
```

## Web Dashboard Usage

### Start Web Interface
Launch the web dashboard:

```bash
python lansecmon.py web
```

Then open your browser to: `http://localhost:5000`

### Custom Host and Port
Bind to specific host/port:

```bash
python lansecmon.py web --host 0.0.0.0 --port 8080
```

### Debug Mode
Run with debug mode for development:

```bash
python lansecmon.py web --debug
```

### Web Dashboard Features

#### Dashboard Overview
- View total devices, vulnerabilities, and alerts
- See recent security alerts
- Monitor vulnerability trends

#### Device Management
- Browse all discovered devices
- View device details and open ports
- Check device history

#### Vulnerability Analysis
- Filter vulnerabilities by severity
- View detailed vulnerability descriptions
- Get remediation recommendations

#### Real-time Monitoring
- Start/stop monitoring from web interface
- Configure monitoring intervals
- View live monitoring status

#### Manual Scanning
- Trigger scans from web interface
- Configure scan parameters
- View scan progress and results

## Advanced Scenarios

### Office Network Assessment
Comprehensive assessment of an office network:

```bash
# Step 1: Discover all devices with detailed information
python lansecmon.py scan --detailed --network 192.168.0.0/16 --output office_scan.json

# Step 2: Perform thorough vulnerability assessment
python lansecmon.py vulns --input office_scan.json --output office_vulnerabilities.json

# Step 3: Start continuous monitoring
python lansecmon.py monitor --network 192.168.0.0/16 --interval 1800
```

### Security Audit Workflow
Regular security audit process:

```bash
# Daily quick scan
python lansecmon.py scan --vulnerabilities --output daily_$(date +%Y%m%d).json

# Weekly detailed assessment
python lansecmon.py scan --detailed --vulnerabilities --output weekly_$(date +%Y%m%d).json

# Export results for reporting
python lansecmon.py export --output security_report_$(date +%Y%m%d).json
```

### Incident Response
Quick assessment during security incidents:

```bash
# Rapid network scan to identify new devices
python lansecmon.py scan --output incident_scan.json

# Check for immediate vulnerabilities
python lansecmon.py vulns --input incident_scan.json

# Start intensive monitoring
python lansecmon.py monitor --interval 60
```

### Multi-Network Environment
Scanning multiple network segments:

```bash
# Scan different subnets
python lansecmon.py scan --network 192.168.1.0/24 --output subnet1.json
python lansecmon.py scan --network 192.168.2.0/24 --output subnet2.json
python lansecmon.py scan --network 10.0.0.0/24 --output subnet3.json

# Combine vulnerability assessments
python lansecmon.py vulns --input subnet1.json --output vulns1.json
python lansecmon.py vulns --input subnet2.json --output vulns2.json
python lansecmon.py vulns --input subnet3.json --output vulns3.json
```

## Status and Reporting

### Check Current Status
View current system status:

```bash
python lansecmon.py status
```

### Export Data
Export all data for external analysis:

```bash
python lansecmon.py export --output full_export.json
```

### View Help
Get help for any command:

```bash
python lansecmon.py --help
python lansecmon.py scan --help
python lansecmon.py monitor --help
```

## Real-World Use Cases

### 1. Small Office Network Security
**Scenario:** 20-device office network needs regular security monitoring.

```bash
# Initial assessment
python lansecmon.py scan --detailed --vulnerabilities --output office_baseline.json

# Set up daily monitoring
python lansecmon.py monitor --interval 3600

# Weekly detailed scans
# (Add to cron job or task scheduler)
python lansecmon.py scan --detailed --vulnerabilities --output weekly_$(date +%Y%m%d).json
```

### 2. Home Network Protection
**Scenario:** Protect home network from unauthorized devices and vulnerabilities.

```bash
# Quick daily check
python lansecmon.py scan --vulnerabilities

# Start web interface for family members
python lansecmon.py web --host 0.0.0.0 --port 5000

# Continuous monitoring
python lansecmon.py monitor --interval 1800
```

### 3. IT Department Security Audits
**Scenario:** Regular security audits for compliance.

```bash
# Comprehensive monthly audit
python lansecmon.py scan --detailed --vulnerabilities --network 10.0.0.0/8 --output audit_$(date +%Y%m).json

# Generate compliance report
python lansecmon.py export --output compliance_report_$(date +%Y%m%d).json

# Set up monitoring dashboard
python lansecmon.py web --host 0.0.0.0 --port 8080
```

### 4. Network Change Detection
**Scenario:** Detect unauthorized changes to network infrastructure.

```bash
# Establish baseline
python lansecmon.py scan --detailed --output baseline.json

# Daily comparison scans
python lansecmon.py scan --output daily_$(date +%Y%m%d).json

# Continuous monitoring for immediate alerts
python lansecmon.py monitor --interval 300
```

## Troubleshooting

### Common Issues and Solutions

#### Permission Errors
If you get permission errors:

```bash
# Windows: Run as Administrator
# Linux/macOS: Use sudo for privileged operations
sudo python3 lansecmon.py scan --detailed
```

#### Network Access Issues
If devices aren't being discovered:

```bash
# Check network connectivity
ping 192.168.1.1

# Try different network range
python lansecmon.py scan --network 10.0.0.0/24

# Use detailed scan for better detection
python lansecmon.py scan --detailed
```

#### Slow Scans
If scans are taking too long:

```bash
# Use quick scan instead of detailed
python lansecmon.py scan

# Scan smaller network ranges
python lansecmon.py scan --network 192.168.1.0/28

# Reduce thread count in config.py
```

#### Missing Dependencies
If you get import errors:

```bash
# Reinstall dependencies
pip install -r requirements.txt

# Or run the installer
python install.py
```

### Log Files
Check log files for detailed error information:

- `lansecmon.log` - Main application log
- `network_scan.log` - Network scanning log
- `vulnerability_scan.log` - Vulnerability scanning log
- `network_monitor.log` - Monitoring log
- `webapp.log` - Web interface log

### Debug Mode
Enable debug logging for troubleshooting:

```bash
# Set LOG_LEVEL = 'DEBUG' in config.py
# Or use debug mode in web interface
python lansecmon.py web --debug
```

## Security Considerations

### Ethical Usage
- Only scan networks you own or have explicit permission to test
- Inform network users about security scanning activities
- Follow your organization's security policies
- Respect privacy and data protection regulations

### Network Impact
- Start with small network ranges to test impact
- Use appropriate scan intervals to avoid network congestion
- Monitor network performance during scans
- Consider off-hours scanning for production networks

### Data Protection
- Secure scan results and reports
- Use encrypted storage for sensitive data
- Implement access controls for web interface
- Regular cleanup of old scan data

## Getting Help

If you need additional help:

1. Check the README.md file for basic information
2. Review the configuration options in config.py
3. Check log files for error details
4. Use the `--help` option with any command
5. Review the source code for advanced customization

Remember: This tool is designed for legitimate security assessment and monitoring. Always use it responsibly and ethically!

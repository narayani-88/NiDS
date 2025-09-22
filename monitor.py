#!/usr/bin/env python3
"""
LAN Security Monitor - Real-time Monitoring Module
Continuously monitors the network for changes and security threats.
"""

import time
import json
import logging
import threading
from datetime import datetime, timedelta
from network_scanner import NetworkScanner
from vulnerability_detector import VulnerabilityDetector

# Email imports - handle gracefully if not available
try:
    import smtplib
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
    EMAIL_AVAILABLE = True
except ImportError:
    EMAIL_AVAILABLE = False
    print("Warning: Email functionality not available. Email alerts will be disabled.")

class NetworkMonitor:
    def __init__(self, scan_interval=300, alert_threshold=5):  # 5 minutes default
        self.scan_interval = scan_interval  # seconds between scans
        self.alert_threshold = alert_threshold  # number of new vulnerabilities to trigger alert
        self.scanner = NetworkScanner()
        self.detector = VulnerabilityDetector()
        self.previous_devices = {}
        self.previous_vulnerabilities = []
        self.monitoring = False
        self.monitor_thread = None
        self.setup_logging()
        self.alerts = []
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def compare_devices(self, current_devices, previous_devices):
        """Compare current scan with previous scan to detect changes"""
        changes = {
            'new_devices': [],
            'removed_devices': [],
            'changed_devices': [],
            'new_services': [],
            'removed_services': []
        }
        
        # Find new and removed devices
        current_ips = set(current_devices.keys())
        previous_ips = set(previous_devices.keys())
        
        changes['new_devices'] = list(current_ips - previous_ips)
        changes['removed_devices'] = list(previous_ips - current_ips)
        
        # Find changes in existing devices
        for ip in current_ips & previous_ips:
            current_device = current_devices[ip]
            previous_device = previous_devices[ip]
            
            # Compare ports/services
            current_ports = set(p.get('port') if isinstance(p, dict) else p 
                              for p in current_device.get('ports', []))
            previous_ports = set(p.get('port') if isinstance(p, dict) else p 
                               for p in previous_device.get('ports', []))
            
            new_ports = current_ports - previous_ports
            removed_ports = previous_ports - current_ports
            
            if new_ports or removed_ports:
                changes['changed_devices'].append({
                    'ip': ip,
                    'hostname': current_device.get('hostname', 'Unknown'),
                    'new_ports': list(new_ports),
                    'removed_ports': list(removed_ports)
                })
            
            # Track new services specifically
            for port in new_ports:
                port_info = next((p for p in current_device.get('ports', []) 
                                if (p.get('port') if isinstance(p, dict) else p) == port), None)
                if port_info:
                    service = port_info.get('service', 'Unknown') if isinstance(port_info, dict) else 'Unknown'
                    changes['new_services'].append({
                        'ip': ip,
                        'hostname': current_device.get('hostname', 'Unknown'),
                        'port': port,
                        'service': service
                    })
        
        return changes

    def detect_suspicious_activity(self, changes, vulnerabilities):
        """Detect suspicious activities that might indicate security threats"""
        alerts = []
        
        # Alert on new devices
        for ip in changes['new_devices']:
            alerts.append({
                'type': 'NEW_DEVICE',
                'severity': 'MEDIUM',
                'message': f'New device detected on network: {ip}',
                'timestamp': datetime.now().isoformat(),
                'details': {'ip': ip}
            })
        
        # Alert on new high-risk services
        risky_services = ['ftp', 'telnet', 'smb', 'rdp', 'ssh']
        for service_info in changes['new_services']:
            if any(risky in service_info['service'].lower() for risky in risky_services):
                alerts.append({
                    'type': 'RISKY_SERVICE',
                    'severity': 'HIGH',
                    'message': f'Risky service {service_info["service"]} detected on {service_info["ip"]}:{service_info["port"]}',
                    'timestamp': datetime.now().isoformat(),
                    'details': service_info
                })
        
        # Alert on high severity vulnerabilities
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
        if len(high_vulns) >= self.alert_threshold:
            alerts.append({
                'type': 'HIGH_VULNERABILITY_COUNT',
                'severity': 'HIGH',
                'message': f'{len(high_vulns)} high-severity vulnerabilities detected',
                'timestamp': datetime.now().isoformat(),
                'details': {'count': len(high_vulns), 'vulnerabilities': high_vulns[:5]}  # First 5
            })
        
        # Alert on specific vulnerability types
        critical_vulns = ['Weak Credentials', 'SMB Service Exposed', 'Database Exposure']
        for vuln in vulnerabilities:
            if vuln.get('type') in critical_vulns:
                alerts.append({
                    'type': 'CRITICAL_VULNERABILITY',
                    'severity': 'HIGH',
                    'message': f'Critical vulnerability detected: {vuln["type"]} on {vuln["ip"]}',
                    'timestamp': datetime.now().isoformat(),
                    'details': vuln
                })
        
        # Alert on unusual port activity
        for device_change in changes['changed_devices']:
            if len(device_change['new_ports']) > 5:  # Many new ports suddenly
                alerts.append({
                    'type': 'UNUSUAL_PORT_ACTIVITY',
                    'severity': 'MEDIUM',
                    'message': f'Unusual port activity on {device_change["ip"]}: {len(device_change["new_ports"])} new ports',
                    'timestamp': datetime.now().isoformat(),
                    'details': device_change
                })
        
        return alerts

    def send_email_alert(self, alerts, smtp_config=None):
        """Send email alerts (requires SMTP configuration)"""
        if not EMAIL_AVAILABLE:
            self.logger.warning("Email functionality not available, skipping email alert")
            return
            
        if not smtp_config or not alerts:
            return
        
        try:
            msg = MimeMultipart()
            msg['From'] = smtp_config['from_email']
            msg['To'] = smtp_config['to_email']
            msg['Subject'] = f'LAN Security Alert - {len(alerts)} issues detected'
            
            body = "LAN Security Monitor Alert\n"
            body += "=" * 30 + "\n\n"
            body += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            body += f"Total alerts: {len(alerts)}\n\n"
            
            for alert in alerts:
                body += f"[{alert['severity']}] {alert['type']}\n"
                body += f"Message: {alert['message']}\n"
                body += f"Time: {alert['timestamp']}\n"
                body += "-" * 40 + "\n"
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port'])
            if smtp_config.get('use_tls'):
                server.starttls()
            if smtp_config.get('username'):
                server.login(smtp_config['username'], smtp_config['password'])
            
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent with {len(alerts)} alerts")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")

    def save_monitoring_data(self, scan_data, changes, alerts):
        """Save monitoring data to files"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save current scan
        with open(f'monitor_scan_{timestamp}.json', 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        # Save changes
        if changes:
            with open(f'monitor_changes_{timestamp}.json', 'w') as f:
                json.dump(changes, f, indent=2)
        
        # Save alerts
        if alerts:
            with open(f'monitor_alerts_{timestamp}.json', 'w') as f:
                json.dump(alerts, f, indent=2)
        
        # Update latest files
        with open('latest_scan.json', 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        with open('latest_alerts.json', 'w') as f:
            json.dump(alerts, f, indent=2)

    def perform_monitoring_scan(self):
        """Perform a single monitoring scan"""
        self.logger.info("Starting monitoring scan...")
        
        try:
            # Discover devices
            current_devices = self.scanner.discover_devices(use_detailed_scan=False)
            
            # Compare with previous scan
            changes = self.compare_devices(current_devices, self.previous_devices)
            
            # Scan for vulnerabilities
            current_vulnerabilities = self.detector.scan_all_devices(current_devices)
            
            # Detect suspicious activity
            alerts = self.detect_suspicious_activity(changes, current_vulnerabilities)
            
            # Log results
            self.logger.info(f"Scan completed: {len(current_devices)} devices, {len(current_vulnerabilities)} vulnerabilities, {len(alerts)} alerts")
            
            # Save data
            scan_data = {
                'timestamp': datetime.now().isoformat(),
                'devices': current_devices,
                'vulnerabilities': current_vulnerabilities,
                'changes': changes,
                'alerts': alerts
            }
            
            self.save_monitoring_data(scan_data, changes, alerts)
            
            # Print summary if there are changes or alerts
            if changes['new_devices'] or changes['removed_devices'] or changes['changed_devices'] or alerts:
                self.print_monitoring_summary(changes, alerts)
            
            # Update previous state
            self.previous_devices = current_devices.copy()
            self.previous_vulnerabilities = current_vulnerabilities.copy()
            self.alerts.extend(alerts)
            
            return scan_data
            
        except Exception as e:
            self.logger.error(f"Error during monitoring scan: {e}")
            return None

    def print_monitoring_summary(self, changes, alerts):
        """Print monitoring summary"""
        print("\n" + "="*60)
        print("NETWORK MONITORING UPDATE")
        print("="*60)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Print changes
        if changes['new_devices']:
            print(f"\nNEW DEVICES ({len(changes['new_devices'])}):")
            for ip in changes['new_devices']:
                print(f"  + {ip}")
        
        if changes['removed_devices']:
            print(f"\nREMOVED DEVICES ({len(changes['removed_devices'])}):")
            for ip in changes['removed_devices']:
                print(f"  - {ip}")
        
        if changes['changed_devices']:
            print(f"\nCHANGED DEVICES ({len(changes['changed_devices'])}):")
            for device in changes['changed_devices']:
                print(f"  {device['ip']} ({device['hostname']})")
                if device['new_ports']:
                    print(f"    New ports: {device['new_ports']}")
                if device['removed_ports']:
                    print(f"    Removed ports: {device['removed_ports']}")
        
        # Print alerts
        if alerts:
            print(f"\nSECURITY ALERTS ({len(alerts)}):")
            for alert in alerts:
                print(f"  [{alert['severity']}] {alert['message']}")
        
        print("="*60)

    def start_monitoring(self, network_range=None):
        """Start continuous monitoring"""
        if self.monitoring:
            self.logger.warning("Monitoring is already running")
            return
        
        self.monitoring = True
        self.logger.info(f"Starting network monitoring (scan interval: {self.scan_interval} seconds)")
        
        # Perform initial scan
        if network_range:
            self.scanner.get_local_network_range = lambda: network_range
        
        initial_scan = self.perform_monitoring_scan()
        if initial_scan:
            self.logger.info("Initial baseline scan completed")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                time.sleep(self.scan_interval)
                if self.monitoring:  # Check again in case stop was called during sleep
                    self.perform_monitoring_scan()
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")

    def stop_monitoring(self):
        """Stop continuous monitoring"""
        if not self.monitoring:
            self.logger.warning("Monitoring is not running")
            return
        
        self.monitoring = False
        self.logger.info("Stopping network monitoring...")
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        
        self.logger.info("Network monitoring stopped")

    def get_monitoring_status(self):
        """Get current monitoring status"""
        return {
            'monitoring': self.monitoring,
            'scan_interval': self.scan_interval,
            'devices_count': len(self.previous_devices),
            'total_alerts': len(self.alerts),
            'last_scan': datetime.now().isoformat() if self.previous_devices else None
        }

def main():
    """Main function for standalone execution"""
    print("LAN Security Monitor - Real-time Monitoring")
    print("==========================================")
    
    # Configuration
    scan_interval = int(input("Enter scan interval in seconds (default 300): ") or "300")
    network_range = input("Enter network range (press Enter for auto-detection): ").strip()
    
    monitor = NetworkMonitor(scan_interval=scan_interval)
    
    try:
        print(f"\nStarting monitoring with {scan_interval} second intervals...")
        print("Press Ctrl+C to stop monitoring")
        
        monitor.start_monitoring(network_range if network_range else None)
        
        # Keep main thread alive
        while monitor.monitoring:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        monitor.stop_monitoring()
        print("Monitoring stopped.")

if __name__ == "__main__":
    main()

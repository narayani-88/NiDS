#!/usr/bin/env python3
"""
Simple Network Monitoring - Without Email Dependencies
Basic monitoring functionality that works without email imports.
"""

import time
import json
import logging
import threading
from datetime import datetime, timedelta

class SimpleNetworkMonitor:
    def __init__(self, scan_interval=300):
        self.scan_interval = scan_interval
        self.monitoring = False
        self.monitor_thread = None
        self.previous_devices = {}
        self.alerts = []
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('monitoring.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def perform_scan(self):
        """Perform a network scan"""
        try:
            # Import here to avoid startup issues
            from network_scanner import NetworkScanner
            
            scanner = NetworkScanner()
            current_devices = scanner.discover_devices(use_detailed_scan=False)
            
            # Compare with previous scan
            changes = self.compare_devices(current_devices, self.previous_devices)
            
            # Generate alerts for changes
            alerts = self.generate_alerts(changes)
            
            # Save results
            scan_data = {
                'timestamp': datetime.now().isoformat(),
                'devices': current_devices,
                'changes': changes,
                'alerts': alerts,
                'monitoring': True
            }
            
            # Save to files
            with open('latest_monitoring_scan.json', 'w') as f:
                json.dump(scan_data, f, indent=2)
            
            with open('latest_scan.json', 'w') as f:
                json.dump(scan_data, f, indent=2)
            
            # Update alerts
            self.alerts.extend(alerts)
            with open('latest_alerts.json', 'w') as f:
                json.dump(self.alerts[-50:], f, indent=2)  # Keep last 50 alerts
            
            # Log results
            self.logger.info(f"Monitoring scan: {len(current_devices)} devices, {len(alerts)} new alerts")
            
            # Update previous state
            self.previous_devices = current_devices.copy()
            
            return scan_data
            
        except Exception as e:
            self.logger.error(f"Monitoring scan failed: {e}")
            return None

    def compare_devices(self, current_devices, previous_devices):
        """Compare current scan with previous scan"""
        changes = {
            'new_devices': [],
            'removed_devices': [],
            'changed_devices': []
        }
        
        current_ips = set(current_devices.keys())
        previous_ips = set(previous_devices.keys())
        
        changes['new_devices'] = list(current_ips - previous_ips)
        changes['removed_devices'] = list(previous_ips - current_ips)
        
        # Check for port changes
        for ip in current_ips & previous_ips:
            current_ports = set(p.get('port', p) for p in current_devices[ip].get('ports', []))
            previous_ports = set(p.get('port', p) for p in previous_devices[ip].get('ports', []))
            
            if current_ports != previous_ports:
                changes['changed_devices'].append({
                    'ip': ip,
                    'hostname': current_devices[ip].get('hostname', 'Unknown'),
                    'new_ports': list(current_ports - previous_ports),
                    'removed_ports': list(previous_ports - current_ports)
                })
        
        return changes

    def generate_alerts(self, changes):
        """Generate alerts based on changes"""
        alerts = []
        timestamp = datetime.now().isoformat()
        
        # Alert on new devices
        for ip in changes['new_devices']:
            alerts.append({
                'type': 'NEW_DEVICE',
                'severity': 'MEDIUM',
                'message': f'New device detected: {ip}',
                'timestamp': timestamp,
                'details': {'ip': ip}
            })
        
        # Alert on removed devices
        for ip in changes['removed_devices']:
            alerts.append({
                'type': 'DEVICE_OFFLINE',
                'severity': 'LOW',
                'message': f'Device went offline: {ip}',
                'timestamp': timestamp,
                'details': {'ip': ip}
            })
        
        # Alert on port changes
        for device_change in changes['changed_devices']:
            if device_change['new_ports']:
                alerts.append({
                    'type': 'NEW_PORTS',
                    'severity': 'MEDIUM',
                    'message': f'New ports detected on {device_change["ip"]}: {device_change["new_ports"]}',
                    'timestamp': timestamp,
                    'details': device_change
                })
        
        return alerts

    def start_monitoring(self, network_range=None):
        """Start continuous monitoring"""
        if self.monitoring:
            self.logger.warning("Monitoring is already running")
            return False
        
        self.monitoring = True
        self.logger.info(f"Starting network monitoring (interval: {self.scan_interval}s)")
        
        # Perform initial scan
        initial_scan = self.perform_scan()
        if initial_scan:
            self.logger.info("Initial monitoring scan completed")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        return True

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                time.sleep(self.scan_interval)
                if self.monitoring:
                    self.perform_scan()
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")

    def stop_monitoring(self):
        """Stop continuous monitoring"""
        if not self.monitoring:
            self.logger.warning("Monitoring is not running")
            return False
        
        self.monitoring = False
        self.logger.info("Stopping network monitoring...")
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        
        self.logger.info("Network monitoring stopped")
        return True

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
    print("Simple Network Monitoring")
    print("=" * 30)
    
    scan_interval = int(input("Enter scan interval in seconds (default 300): ") or "300")
    
    monitor = SimpleNetworkMonitor(scan_interval=scan_interval)
    
    try:
        print(f"\nStarting monitoring with {scan_interval} second intervals...")
        print("Press Ctrl+C to stop monitoring")
        
        monitor.start_monitoring()
        
        # Keep main thread alive
        while monitor.monitoring:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        monitor.stop_monitoring()
        print("Monitoring stopped.")

if __name__ == "__main__":
    main()

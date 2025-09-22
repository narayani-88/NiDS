#!/usr/bin/env python3
"""
LAN Security Monitor - Database Module
Database abstraction layer supporting both SQLite and MongoDB.
"""

import sqlite3
import json
import logging
from datetime import datetime
from contextlib import contextmanager
import os
from config import Config

class DatabaseManager:
    def __init__(self, db_path='lansecmon.db'):
        self.db_path = db_path
        self.setup_logging()
        self.init_database()
    
    def setup_logging(self):
        """Setup logging configuration"""
        self.logger = logging.getLogger(__name__)
    
    def init_database(self):
        """Initialize database tables"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create scans table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        network_range TEXT,
                        scan_type TEXT,
                        devices_count INTEGER,
                        vulnerabilities_count INTEGER,
                        scan_duration REAL,
                        status TEXT DEFAULT 'completed'
                    )
                ''')
                
                # Create devices table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS devices (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        ip_address TEXT NOT NULL,
                        hostname TEXT,
                        os_info TEXT,
                        mac_address TEXT,
                        first_seen TEXT,
                        last_seen TEXT,
                        status TEXT DEFAULT 'active',
                        FOREIGN KEY (scan_id) REFERENCES scans (id)
                    )
                ''')
                
                # Create ports table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id INTEGER,
                        port_number INTEGER,
                        service_name TEXT,
                        service_version TEXT,
                        state TEXT,
                        protocol TEXT DEFAULT 'tcp',
                        FOREIGN KEY (device_id) REFERENCES devices (id)
                    )
                ''')
                
                # Create vulnerabilities table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        device_id INTEGER,
                        vuln_type TEXT,
                        severity TEXT,
                        description TEXT,
                        recommendation TEXT,
                        port_number INTEGER,
                        service_name TEXT,
                        first_detected TEXT,
                        last_detected TEXT,
                        status TEXT DEFAULT 'open',
                        FOREIGN KEY (scan_id) REFERENCES scans (id),
                        FOREIGN KEY (device_id) REFERENCES devices (id)
                    )
                ''')
                
                # Create alerts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        alert_type TEXT,
                        severity TEXT,
                        message TEXT,
                        device_ip TEXT,
                        details TEXT,
                        acknowledged BOOLEAN DEFAULT FALSE,
                        resolved BOOLEAN DEFAULT FALSE
                    )
                ''')
                
                # Create monitoring_sessions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS monitoring_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        start_time TEXT NOT NULL,
                        end_time TEXT,
                        scan_interval INTEGER,
                        network_range TEXT,
                        scans_performed INTEGER DEFAULT 0,
                        alerts_generated INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'active'
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)')
                
                conn.commit()
                self.logger.info("Database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """Get database connection with context manager"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def save_scan_results(self, scan_data):
        """Save complete scan results to database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Insert scan record
                cursor.execute('''
                    INSERT INTO scans (timestamp, network_range, scan_type, devices_count, vulnerabilities_count)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    scan_data.get('timestamp', datetime.now().isoformat()),
                    scan_data.get('network_range', 'auto-detected'),
                    scan_data.get('scan_type', 'quick'),
                    len(scan_data.get('devices', {})),
                    len(scan_data.get('vulnerabilities', []))
                ))
                
                scan_id = cursor.lastrowid
                
                # Save devices
                devices = scan_data.get('devices', {})
                device_ids = {}
                
                for ip, device_info in devices.items():
                    cursor.execute('''
                        INSERT INTO devices (scan_id, ip_address, hostname, os_info, last_seen)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        scan_id,
                        ip,
                        device_info.get('hostname', 'Unknown'),
                        device_info.get('os', 'Unknown'),
                        device_info.get('scan_time', datetime.now().isoformat())
                    ))
                    
                    device_id = cursor.lastrowid
                    device_ids[ip] = device_id
                    
                    # Save ports for this device
                    ports = device_info.get('ports', [])
                    for port_info in ports:
                        if isinstance(port_info, dict):
                            cursor.execute('''
                                INSERT INTO ports (device_id, port_number, service_name, service_version, state)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (
                                device_id,
                                port_info.get('port'),
                                port_info.get('service', 'unknown'),
                                port_info.get('version', ''),
                                port_info.get('state', 'open')
                            ))
                
                # Save vulnerabilities
                vulnerabilities = scan_data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    device_id = device_ids.get(vuln.get('ip'))
                    if device_id:
                        cursor.execute('''
                            INSERT INTO vulnerabilities 
                            (scan_id, device_id, vuln_type, severity, description, recommendation, 
                             port_number, service_name, first_detected, last_detected)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            scan_id,
                            device_id,
                            vuln.get('type'),
                            vuln.get('severity'),
                            vuln.get('description'),
                            vuln.get('recommendation'),
                            vuln.get('port'),
                            vuln.get('service', ''),
                            vuln.get('scan_time', datetime.now().isoformat()),
                            vuln.get('scan_time', datetime.now().isoformat())
                        ))
                
                conn.commit()
                self.logger.info(f"Scan results saved with ID: {scan_id}")
                return scan_id
                
        except Exception as e:
            self.logger.error(f"Error saving scan results: {e}")
            raise
    
    def save_alerts(self, alerts):
        """Save alerts to database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                for alert in alerts:
                    cursor.execute('''
                        INSERT INTO alerts (timestamp, alert_type, severity, message, device_ip, details)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        alert.get('timestamp', datetime.now().isoformat()),
                        alert.get('type'),
                        alert.get('severity'),
                        alert.get('message'),
                        alert.get('details', {}).get('ip', ''),
                        json.dumps(alert.get('details', {}))
                    ))
                
                conn.commit()
                self.logger.info(f"Saved {len(alerts)} alerts to database")
                
        except Exception as e:
            self.logger.error(f"Error saving alerts: {e}")
            raise
    
    def get_scan_history(self, limit=50):
        """Get scan history"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM scans 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Error getting scan history: {e}")
            return []
    
    def get_device_history(self, ip_address):
        """Get history for a specific device"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT d.*, s.timestamp as scan_timestamp
                    FROM devices d
                    JOIN scans s ON d.scan_id = s.id
                    WHERE d.ip_address = ?
                    ORDER BY s.timestamp DESC
                ''', (ip_address,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Error getting device history: {e}")
            return []
    
    def get_vulnerability_trends(self, days=30):
        """Get vulnerability trends over time"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT 
                        DATE(timestamp) as date,
                        COUNT(*) as total_vulnerabilities,
                        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_severity,
                        SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_severity,
                        SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low_severity
                    FROM vulnerabilities v
                    JOIN scans s ON v.scan_id = s.id
                    WHERE DATE(timestamp) >= DATE('now', '-{} days')
                    GROUP BY DATE(timestamp)
                    ORDER BY date DESC
                '''.format(days))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Error getting vulnerability trends: {e}")
            return []
    
    def get_active_alerts(self):
        """Get unresolved alerts"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM alerts 
                    WHERE resolved = FALSE 
                    ORDER BY timestamp DESC
                ''')
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Error getting active alerts: {e}")
            return []
    
    def acknowledge_alert(self, alert_id):
        """Mark alert as acknowledged"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE alerts 
                    SET acknowledged = TRUE 
                    WHERE id = ?
                ''', (alert_id,))
                
                conn.commit()
                self.logger.info(f"Alert {alert_id} acknowledged")
                
        except Exception as e:
            self.logger.error(f"Error acknowledging alert: {e}")
            raise
    
    def resolve_alert(self, alert_id):
        """Mark alert as resolved"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE alerts 
                    SET resolved = TRUE, acknowledged = TRUE 
                    WHERE id = ?
                ''', (alert_id,))
                
                conn.commit()
                self.logger.info(f"Alert {alert_id} resolved")
                
        except Exception as e:
            self.logger.error(f"Error resolving alert: {e}")
            raise
    
    def get_statistics(self):
        """Get overall statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Total scans
                cursor.execute('SELECT COUNT(*) FROM scans')
                stats['total_scans'] = cursor.fetchone()[0]
                
                # Total devices discovered
                cursor.execute('SELECT COUNT(DISTINCT ip_address) FROM devices')
                stats['total_devices'] = cursor.fetchone()[0]
                
                # Total vulnerabilities
                cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
                stats['total_vulnerabilities'] = cursor.fetchone()[0]
                
                # Vulnerabilities by severity
                cursor.execute('''
                    SELECT severity, COUNT(*) 
                    FROM vulnerabilities 
                    GROUP BY severity
                ''')
                severity_counts = dict(cursor.fetchall())
                stats['high_severity'] = severity_counts.get('HIGH', 0)
                stats['medium_severity'] = severity_counts.get('MEDIUM', 0)
                stats['low_severity'] = severity_counts.get('LOW', 0)
                
                # Total alerts
                cursor.execute('SELECT COUNT(*) FROM alerts')
                stats['total_alerts'] = cursor.fetchone()[0]
                
                # Unresolved alerts
                cursor.execute('SELECT COUNT(*) FROM alerts WHERE resolved = FALSE')
                stats['unresolved_alerts'] = cursor.fetchone()[0]
                
                return stats
                
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {}
    
    def cleanup_old_data(self, days=90):
        """Clean up old data beyond specified days"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Delete old scans and related data
                cursor.execute('''
                    DELETE FROM scans 
                    WHERE timestamp < DATE('now', '-{} days')
                '''.format(days))
                
                deleted_scans = cursor.rowcount
                
                # Delete old alerts
                cursor.execute('''
                    DELETE FROM alerts 
                    WHERE timestamp < DATE('now', '-{} days') 
                    AND resolved = TRUE
                '''.format(days))
                
                deleted_alerts = cursor.rowcount
                
                conn.commit()
                self.logger.info(f"Cleaned up {deleted_scans} old scans and {deleted_alerts} old alerts")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")
            raise
    
    def export_data(self, output_file='lansecmon_export.json'):
        """Export all data to JSON file"""
        try:
            data = {
                'export_timestamp': datetime.now().isoformat(),
                'scans': self.get_scan_history(limit=1000),
                'statistics': self.get_statistics(),
                'active_alerts': self.get_active_alerts()
            }
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"Data exported to {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error exporting data: {e}")
            raise

def main():
    """Test the database functionality"""
    print("Testing Database Manager...")
    
    # Initialize database
    db = DatabaseManager('test_lansecmon.db')
    
    # Test data
    test_scan_data = {
        'timestamp': datetime.now().isoformat(),
        'devices': {
            '192.168.1.1': {
                'hostname': 'router.local',
                'os': 'Linux',
                'ports': [
                    {'port': 80, 'service': 'HTTP', 'state': 'open'},
                    {'port': 443, 'service': 'HTTPS', 'state': 'open'}
                ]
            }
        },
        'vulnerabilities': [
            {
                'ip': '192.168.1.1',
                'type': 'Weak Credentials',
                'severity': 'HIGH',
                'description': 'Default admin credentials detected',
                'recommendation': 'Change default password',
                'port': 80
            }
        ]
    }
    
    # Save test data
    scan_id = db.save_scan_results(test_scan_data)
    print(f"Saved scan with ID: {scan_id}")
    
    # Get statistics
    stats = db.get_statistics()
    print(f"Statistics: {stats}")
    
    # Clean up test database
    os.remove('test_lansecmon.db')
    print("Test completed successfully!")

if __name__ == "__main__":
    main()

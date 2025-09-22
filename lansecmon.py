#!/usr/bin/env python3
"""
LAN Security Monitor - Main Launcher
Central launcher for all LAN Security Monitor functionality.
"""

import argparse
import sys
import os
import time
import json
from datetime import datetime
import logging

# Import our modules
from network_scanner import NetworkScanner
from vulnerability_detector import VulnerabilityDetector
from monitor import NetworkMonitor
from config import Config
from database import DatabaseManager

def setup_logging():
    """Setup centralized logging"""
    logging.basicConfig(
        level=getattr(logging, Config.LOG_LEVEL),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(Config.LOG_FILE),
            logging.StreamHandler()
        ]
    )

def print_banner():
    """Print application banner"""
    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                    LAN Security Monitor                      ║
║                         Version {Config.VERSION}                        ║
║                                                              ║
║  A comprehensive network security monitoring and             ║
║  vulnerability assessment tool for local area networks.     ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)

def scan_network(args):
    """Perform network scan"""
    print("Starting network scan...")
    
    scanner = NetworkScanner()
    
    # Determine network range
    network_range = args.network if args.network else scanner.get_local_network_range()
    print(f"Scanning network: {network_range}")
    
    # Perform scan
    start_time = time.time()
    devices = scanner.discover_devices(network_range, use_detailed_scan=args.detailed)
    scan_duration = time.time() - start_time
    
    print(f"\nScan completed in {scan_duration:.2f} seconds")
    print(f"Found {len(devices)} devices")
    
    # Save results
    scanner.save_results(args.output if args.output else "network_scan_results.json")
    
    if args.vulnerabilities:
        print("\nScanning for vulnerabilities...")
        detector = VulnerabilityDetector()
        vulnerabilities = detector.scan_all_devices(devices)
        detector.save_report("vulnerability_report.json")
        print(f"Found {len(vulnerabilities)} vulnerabilities")
    
    # Print summary
    scanner.print_summary()
    
    # Save to database if enabled
    if Config.DATABASE_ENABLED:
        try:
            if Config.DATABASE_TYPE.lower() == 'mongodb':
                from mongodb_manager import MongoDBManager
                db = MongoDBManager()
            else:
                from database import DatabaseManager
                db = DatabaseManager()
            
            scan_data = {
                'timestamp': datetime.now().isoformat(),
                'network_range': network_range,
                'devices': devices,
                'vulnerabilities': vulnerabilities if args.vulnerabilities else [],
                'scan_duration': scan_duration
            }
            db.save_scan_results(scan_data)
            print(f"✅ Results saved to {Config.DATABASE_TYPE} database")
        except Exception as e:
            print(f"⚠️  Database save failed: {e}")
            print("Results are still available in JSON files")

def scan_vulnerabilities(args):
    """Scan for vulnerabilities only"""
    print("Scanning for vulnerabilities...")
    
    # Load existing network scan
    try:
        with open(args.input if args.input else "network_scan_results.json", 'r') as f:
            devices = json.load(f)
    except FileNotFoundError:
        print("Error: No network scan results found. Please run a network scan first.")
        return
    
    detector = VulnerabilityDetector()
    vulnerabilities = detector.scan_all_devices(devices)
    
    detector.print_summary()
    detector.save_report(args.output if args.output else "vulnerability_report.json")

def start_monitoring(args):
    """Start continuous monitoring"""
    print("Starting network monitoring...")
    
    monitor = NetworkMonitor(scan_interval=args.interval)
    
    try:
        monitor.start_monitoring(args.network)
        print(f"Monitoring started with {args.interval} second intervals")
        print("Press Ctrl+C to stop monitoring")
        
        # Keep running until interrupted
        while monitor.monitoring:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        monitor.stop_monitoring()
        print("Monitoring stopped.")

def start_web_interface(args):
    """Start web interface"""
    print("Starting web interface...")
    
    # Import and run Flask app
    from app import app, create_templates
    
    # Create templates if they don't exist
    if not os.path.exists('templates'):
        create_templates()
    
    print(f"Web interface starting on http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop")
    
    app.run(host=args.host, port=args.port, debug=args.debug)

def show_status(args):
    """Show current status"""
    print("LAN Security Monitor Status")
    print("=" * 40)
    
    # Check for recent scan data
    try:
        with open('latest_scan.json', 'r') as f:
            data = json.load(f)
        
        print(f"Last scan: {data.get('timestamp', 'Unknown')}")
        print(f"Devices found: {len(data.get('devices', {}))}")
        print(f"Vulnerabilities: {len(data.get('vulnerabilities', []))}")
        
        # Show vulnerability breakdown
        vulns = data.get('vulnerabilities', [])
        high = len([v for v in vulns if v.get('severity') == 'HIGH'])
        medium = len([v for v in vulns if v.get('severity') == 'MEDIUM'])
        low = len([v for v in vulns if v.get('severity') == 'LOW'])
        
        print(f"  - High severity: {high}")
        print(f"  - Medium severity: {medium}")
        print(f"  - Low severity: {low}")
        
    except FileNotFoundError:
        print("No recent scan data found")
    
    # Check for alerts
    try:
        with open('latest_alerts.json', 'r') as f:
            alerts = json.load(f)
        print(f"Active alerts: {len(alerts)}")
    except FileNotFoundError:
        print("No alerts found")
    
    # Database statistics if enabled
    if Config.DATABASE_ENABLED:
        try:
            db = DatabaseManager()
            stats = db.get_statistics()
            print(f"\nDatabase Statistics:")
            print(f"  - Total scans: {stats.get('total_scans', 0)}")
            print(f"  - Total devices: {stats.get('total_devices', 0)}")
            print(f"  - Total vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
            print(f"  - Unresolved alerts: {stats.get('unresolved_alerts', 0)}")
        except Exception as e:
            print(f"Database error: {e}")

def export_data(args):
    """Export data to various formats"""
    print(f"Exporting data to {args.output}...")
    
    if Config.DATABASE_ENABLED:
        db = DatabaseManager()
        db.export_data(args.output)
    else:
        # Export from JSON files
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'version': Config.VERSION
        }
        
        # Load scan results
        try:
            with open('latest_scan.json', 'r') as f:
                export_data['latest_scan'] = json.load(f)
        except FileNotFoundError:
            pass
        
        # Load alerts
        try:
            with open('latest_alerts.json', 'r') as f:
                export_data['latest_alerts'] = json.load(f)
        except FileNotFoundError:
            pass
        
        with open(args.output, 'w') as f:
            json.dump(export_data, f, indent=2)
    
    print(f"Data exported successfully to {args.output}")

def main():
    """Main function"""
    setup_logging()
    
    parser = argparse.ArgumentParser(
        description="LAN Security Monitor - Network Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan                          # Quick network scan
  %(prog)s scan --detailed --vulns       # Detailed scan with vulnerabilities
  %(prog)s scan --network 10.0.0.0/24   # Scan specific network
  %(prog)s vulns                         # Scan vulnerabilities only
  %(prog)s monitor --interval 600        # Monitor every 10 minutes
  %(prog)s web                           # Start web interface
  %(prog)s status                        # Show current status
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Perform network scan')
    scan_parser.add_argument('--network', '-n', help='Network range to scan (e.g., 192.168.1.0/24)')
    scan_parser.add_argument('--detailed', '-d', action='store_true', help='Perform detailed scan with OS detection')
    scan_parser.add_argument('--vulnerabilities', '--vulns', action='store_true', help='Also scan for vulnerabilities')
    scan_parser.add_argument('--output', '-o', help='Output file for results')
    
    # Vulnerability scan command
    vuln_parser = subparsers.add_parser('vulns', help='Scan for vulnerabilities')
    vuln_parser.add_argument('--input', '-i', help='Input file with network scan results')
    vuln_parser.add_argument('--output', '-o', help='Output file for vulnerability report')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Start continuous monitoring')
    monitor_parser.add_argument('--interval', '-i', type=int, default=300, help='Scan interval in seconds (default: 300)')
    monitor_parser.add_argument('--network', '-n', help='Network range to monitor')
    
    # Web interface command
    web_parser = subparsers.add_parser('web', help='Start web interface')
    web_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    web_parser.add_argument('--port', type=int, default=5000, help='Port to bind to (default: 5000)')
    web_parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show current status')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export data')
    export_parser.add_argument('--output', '-o', default='lansecmon_export.json', help='Output file')
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        print_banner()
        parser.print_help()
        return
    
    # Validate configuration
    config_errors = Config.validate_config()
    if config_errors:
        print("Configuration errors:")
        for error in config_errors:
            print(f"  - {error}")
        return
    
    print_banner()
    
    # Execute command
    try:
        if args.command == 'scan':
            scan_network(args)
        elif args.command == 'vulns':
            scan_vulnerabilities(args)
        elif args.command == 'monitor':
            start_monitoring(args)
        elif args.command == 'web':
            start_web_interface(args)
        elif args.command == 'status':
            show_status(args)
        elif args.command == 'export':
            export_data(args)
        else:
            print(f"Unknown command: {args.command}")
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        logging.error(f"Error executing command '{args.command}': {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

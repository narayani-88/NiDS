#!/usr/bin/env python3
"""
NIDS - Network Scanner Module
Discovers devices and scans for open ports and services on the local network.
"""

import socket
import subprocess
import threading
import time
import json
import logging
import re
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import netifaces
import nmap

class NetworkScanner:
    def __init__(self, max_threads=50):
        self.max_threads = max_threads
        self.devices = {}
        self.nm = nmap.PortScanner()
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_scan.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def get_all_network_ranges(self):
        """Get all local network ranges from all interfaces"""
        networks = []
        try:
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        for addr_info in addrs[netifaces.AF_INET]:
                            ip = addr_info.get('addr')
                            netmask = addr_info.get('netmask')
                            if ip and netmask and not ip.startswith('127.'):
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                networks.append(str(network))
                except Exception as e:
                    continue
        except Exception as e:
            self.logger.error(f"Error getting network ranges: {e}")
        
        # Remove duplicates and return
        return list(set(networks)) if networks else ["192.168.1.0/24"]

    def get_local_network_range(self):
        """Get the primary local network range automatically"""
        try:
            # Get default gateway interface
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET]
            interface = default_gateway[1]
            
            # Get network info for the interface
            addrs = netifaces.ifaddresses(interface)
            ipv4_info = addrs[netifaces.AF_INET][0]
            
            ip = ipv4_info['addr']
            netmask = ipv4_info['netmask']
            
            # Calculate network range
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
            
        except Exception as e:
            self.logger.error(f"Error getting network range: {e}")
            return "192.168.1.0/24"  # Default fallback

    def ping_host(self, ip, timeout=3):
        """Ping a single host to check if it's alive with improved timeout"""
        try:
            system = platform.system().lower()
            if system == 'windows':
                result = subprocess.run(
                    ['ping', '-n', '2', '-w', str(timeout * 1000), ip],
                    capture_output=True,
                    text=True,
                    timeout=timeout + 1
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '2', '-W', str(timeout), ip],
                    capture_output=True,
                    text=True,
                    timeout=timeout + 1
                )
            return result.returncode == 0
        except Exception as e:
            self.logger.debug(f"Ping failed for {ip}: {e}")
            return False

    def get_arp_table(self):
        """Get devices from ARP table"""
        devices = set()
        try:
            system = platform.system().lower()
            if system == 'windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    # Parse Windows ARP output
                    for line in result.stdout.split('\n'):
                        # Look for IP addresses in the format: 192.168.1.1
                        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                        if ip_match and 'dynamic' in line.lower():
                            ip = ip_match.group(1)
                            if not ip.startswith('224.') and not ip.startswith('239.'):
                                devices.add(ip)
            else:
                # Linux/Mac
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        ip_match = re.search(r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)', line)
                        if ip_match:
                            devices.add(ip_match.group(1))
        except Exception as e:
            self.logger.debug(f"ARP table scan failed: {e}")
        
        return list(devices)

    def tcp_connect_scan(self, ip, port=80, timeout=1):
        """Try TCP connect to detect if host is alive"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0 or result == 10061  # Connection refused also means host is alive
        except:
            return False

    def udp_scan(self, ip, port=53, timeout=1):
        """Try UDP scan to detect if host is alive"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b'\x00', (ip, port))
            sock.close()
            return True  # If no exception, host might be alive
        except:
            return False

    def get_hostname(self, ip):
        """Get hostname for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"

    def scan_port(self, ip, port):
        """Scan a single port on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def get_service_info(self, port):
        """Get service information for a port with expanded service list"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 587: "SMTP", 465: "SMTPS", 135: "RPC", 139: "NetBIOS",
            445: "SMB", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL",
            1433: "MSSQL", 6379: "Redis", 27017: "MongoDB", 5984: "CouchDB",
            9200: "Elasticsearch", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            8000: "HTTP-Dev", 9000: "HTTP-Admin", 5000: "HTTP-Dev", 631: "IPP",
            515: "LPD", 161: "SNMP", 162: "SNMP-Trap", 389: "LDAP", 636: "LDAPS",
            1521: "Oracle", 5601: "Kibana", 3000: "Grafana", 4000: "HTTP-Dev",
            5900: "VNC", 5901: "VNC", 8888: "HTTP-Alt", 9090: "HTTP-Metrics",
            10000: "Webmin"
        }
        return common_ports.get(port, f"Unknown-{port}")

    def detailed_port_scan(self, ip, ports=None):
        """Perform detailed port scan using nmap with better error handling"""
        if ports is None:
            ports = "1-1000"  # Scan first 1000 ports
            
        try:
            self.logger.info(f"Detailed scanning {ip}...")
            # Use less aggressive scan if OS detection fails
            try:
                scan_result = self.nm.scan(ip, ports, arguments='-sV -sS -O')
            except:
                # Fallback without OS detection
                scan_result = self.nm.scan(ip, ports, arguments='-sV -sS')
            
            if ip in scan_result['scan']:
                host_info = scan_result['scan'][ip]
                os_info = 'Unknown'
                if 'osmatch' in host_info and host_info['osmatch']:
                    os_info = host_info['osmatch'][0].get('name', 'Unknown')
                
                hostname = 'Unknown'
                if 'hostnames' in host_info and host_info['hostnames']:
                    hostname = host_info['hostnames'][0].get('name', 'Unknown')
                
                return {
                    'state': host_info.get('status', {}).get('state', 'up'),
                    'hostname': hostname,
                    'os': os_info,
                    'ports': self.parse_nmap_ports(host_info.get('tcp', {}))
                }
        except Exception as e:
            self.logger.debug(f"Nmap scan failed for {ip}: {e}")
            
        return None

    def parse_nmap_ports(self, tcp_ports):
        """Parse nmap TCP port results with better formatting"""
        ports = []
        for port, info in tcp_ports.items():
            version_info = ''
            if info.get('product'):
                version_info = info.get('product', '')
                if info.get('version'):
                    version_info += f" {info.get('version')}"
            elif info.get('version'):
                version_info = info.get('version')
            
            ports.append({
                'port': port,
                'state': info.get('state', 'unknown'),
                'service': info.get('name', 'unknown'),
                'version': version_info,
                'product': info.get('product', '')
            })
        return ports

    def quick_port_scan(self, ip, common_ports_only=True):
        """Quick port scan for common ports with expanded port list"""
        if common_ports_only:
            # Expanded common ports list for better device detection
            ports_to_scan = [
                21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389, 5432, 3306,
                8080, 8443, 8000, 9000, 5000, 631, 515, 161, 162, 389, 636, 1433, 1521, 5984,
                6379, 27017, 9200, 5601, 3000, 4000, 5900, 5901, 8888, 9090, 10000
            ]
        else:
            ports_to_scan = range(1, 1001)  # First 1000 ports
            
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in ports_to_scan}
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        service = self.get_service_info(port)
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'state': 'open'
                        })
                except Exception as e:
                    self.logger.debug(f"Error scanning port {port} on {ip}: {e}")
                    
        return open_ports

    def discover_devices(self, network_range=None, use_detailed_scan=False, scan_all_networks=False):
        """Discover all devices on the network with multiple detection methods"""
        if network_range is None:
            if scan_all_networks:
                network_ranges = self.get_all_network_ranges()
                self.logger.info(f"Scanning all network ranges: {network_ranges}")
            else:
                network_ranges = [self.get_local_network_range()]
        else:
            network_ranges = [network_range]
            
        all_alive_hosts = set()
        
        # First, get devices from ARP table
        self.logger.info("Getting devices from ARP table...")
        arp_devices = self.get_arp_table()
        all_alive_hosts.update(arp_devices)
        self.logger.info(f"Found {len(arp_devices)} devices in ARP table")
        
        # Scan each network range
        for network_range in network_ranges:
            self.logger.info(f"Scanning network range: {network_range}")
            
            try:
                network = ipaddress.IPv4Network(network_range, strict=False)
                hosts = list(network.hosts())
                
                # Add network and broadcast addresses for completeness
                all_ips = [str(network.network_address)] + [str(ip) for ip in hosts] + [str(network.broadcast_address)]
                
            except Exception as e:
                self.logger.error(f"Invalid network range {network_range}: {e}")
                continue

            # Multi-method host discovery
            self.logger.info(f"Performing multi-method discovery on {len(all_ips)} addresses...")
            
            # Method 1: Ping sweep
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                ping_futures = {executor.submit(self.ping_host, ip): ip for ip in all_ips}
                tcp_futures = {executor.submit(self.tcp_connect_scan, ip): ip for ip in all_ips}
                
                # Process ping results
                for future in as_completed(ping_futures):
                    ip = ping_futures[future]
                    try:
                        if future.result():
                            all_alive_hosts.add(ip)
                            self.logger.debug(f"Ping detected: {ip}")
                    except Exception as e:
                        self.logger.debug(f"Error pinging {ip}: {e}")
                
                # Process TCP connect results
                for future in as_completed(tcp_futures):
                    ip = tcp_futures[future]
                    try:
                        if future.result():
                            all_alive_hosts.add(ip)
                            self.logger.debug(f"TCP detected: {ip}")
                    except Exception as e:
                        self.logger.debug(f"Error TCP scanning {ip}: {e}")

        alive_hosts = list(all_alive_hosts)
        self.logger.info(f"Total unique alive hosts found: {len(alive_hosts)}")
        
        # Now scan the alive hosts for services
        self.logger.info("Scanning alive hosts for services...")
        
        for ip in alive_hosts:
            try:
                hostname = self.get_hostname(ip)
                
                if use_detailed_scan:
                    detailed_info = self.detailed_port_scan(ip)
                    if detailed_info:
                        self.devices[ip] = {
                            'ip': ip,
                            'hostname': detailed_info['hostname'] if detailed_info['hostname'] != 'Unknown' else hostname,
                            'os': detailed_info['os'],
                            'state': detailed_info['state'],
                            'ports': detailed_info['ports'],
                            'scan_time': datetime.now().isoformat(),
                            'scan_type': 'detailed'
                        }
                    else:
                        # Fallback to quick scan
                        open_ports = self.quick_port_scan(ip)
                        self.devices[ip] = {
                            'ip': ip,
                            'hostname': hostname,
                            'os': 'Unknown',
                            'state': 'up',
                            'ports': open_ports,
                            'scan_time': datetime.now().isoformat(),
                            'scan_type': 'quick_fallback'
                        }
                else:
                    open_ports = self.quick_port_scan(ip)
                    self.devices[ip] = {
                        'ip': ip,
                        'hostname': hostname,
                        'os': 'Unknown',
                        'state': 'up',
                        'ports': open_ports,
                        'scan_time': datetime.now().isoformat(),
                        'scan_type': 'quick'
                    }
                    
                self.logger.info(f"Scanned {ip} ({hostname}) - Found {len(self.devices[ip]['ports'])} open ports")
                
            except Exception as e:
                self.logger.error(f"Error scanning {ip}: {e}")

        return self.devices

    def save_results(self, filename="network_scan_results.json"):
        """Save scan results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.devices, f, indent=2)
            self.logger.info(f"Results saved to {filename}")
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")

    def print_summary(self):
        """Print a summary of discovered devices"""
        print("\n" + "="*60)
        print("NIDS - NETWORK SCAN SUMMARY")
        print("="*60)
        print(f"Total devices found: {len(self.devices)}")
        print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n")
        
        # Sort devices by IP for better readability
        sorted_devices = sorted(self.devices.items(), key=lambda x: ipaddress.IPv4Address(x[0]))
        
        for ip, info in sorted_devices:
            print(f"Device: {ip}")
            print(f"  Hostname: {info['hostname']}")
            print(f"  OS: {info['os']}")
            print(f"  Scan Type: {info.get('scan_type', 'unknown')}")
            print(f"  Open Ports: {len(info['ports'])}")
            
            if info['ports']:
                print("  Services:")
                for port_info in info['ports']:
                    if isinstance(port_info, dict):
                        port = port_info.get('port', 'Unknown')
                        service = port_info.get('service', 'Unknown')
                        version = port_info.get('version', '')
                        if version:
                            print(f"    {port}: {service} ({version})")
                        else:
                            print(f"    {port}: {service}")
            print()

def main():
    """Main function for standalone execution"""
    print("NIDS - Network Scanner")
    print("=====================")
    
    scanner = NetworkScanner()
    
    # Get network range from user or auto-detect
    network_range = input("Enter network range (e.g., 192.168.1.0/24) or press Enter for auto-detection: ").strip()
    scan_all = False
    
    if not network_range:
        scan_all = input("Scan all network interfaces? (y/N): ").strip().lower() == 'y'
        if not scan_all:
            network_range = scanner.get_local_network_range()
            print(f"Auto-detected network range: {network_range}")
        else:
            ranges = scanner.get_all_network_ranges()
            print(f"Auto-detected network ranges: {ranges}")
    
    # Ask for scan type
    detailed = input("Use detailed scan with OS detection? (y/N): ").strip().lower() == 'y'
    
    print("\nStarting enhanced network scan...")
    start_time = time.time()
    
    devices = scanner.discover_devices(network_range, use_detailed_scan=detailed, scan_all_networks=scan_all)
    
    end_time = time.time()
    print(f"\nScan completed in {end_time - start_time:.2f} seconds")
    
    scanner.print_summary()
    scanner.save_results()

if __name__ == "__main__":
    main()

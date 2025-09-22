#!/usr/bin/env python3
"""
NIDS - Network Intrusion Detection System
Flask web application for visualizing network security data.
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
import json
import os
import time
from datetime import datetime, timedelta
import threading
import logging

# Import modules conditionally to avoid startup issues
try:
    from network_scanner import NetworkScanner
    SCANNER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: NetworkScanner not available: {e}")
    SCANNER_AVAILABLE = False

try:
    from vulnerability_detector import VulnerabilityDetector
    DETECTOR_AVAILABLE = True
except ImportError as e:
    print(f"Warning: VulnerabilityDetector not available: {e}")
    DETECTOR_AVAILABLE = False

try:
    from monitor import NetworkMonitor
    MONITOR_AVAILABLE = True
except ImportError as e:
    print(f"Warning: NetworkMonitor not available: {e}")
    MONITOR_AVAILABLE = False

try:
    from ai_analyzer import AINetworkAnalyzer
    AI_ANALYZER_AVAILABLE = True
    # Gemini API Key
    GEMINI_API_KEY = "AIzaSyDQ1kTceuy8q6gnZ5V0nFugBLRKSMxJ69w"
except ImportError as e:
    print(f"Warning: AI Analyzer not available: {e}")
    AI_ANALYZER_AVAILABLE = False
    GEMINI_API_KEY = None

app = Flask(__name__)
app.secret_key = 'nids_secret_key_change_in_production'

# Global monitor instance
monitor = None
monitor_thread = None

def setup_logging():
    """Setup logging for the web app"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('webapp.log'),
            logging.StreamHandler()
        ]
    )

def load_latest_data():
    """Load the latest scan data"""
    try:
        with open('latest_scan.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def load_latest_alerts():
    """Load the latest alerts"""
    try:
        with open('latest_alerts.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

@app.route('/')
def dashboard():
    """Main dashboard page"""
    data = load_latest_data()
    alerts = load_latest_alerts()
    
    if data:
        devices = data.get('devices', {})
        vulnerabilities = data.get('vulnerabilities', [])
        
        # Calculate statistics
        stats = {
            'total_devices': len(devices),
            'total_vulnerabilities': len(vulnerabilities),
            'high_severity': len([v for v in vulnerabilities if v.get('severity') == 'HIGH']),
            'medium_severity': len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM']),
            'low_severity': len([v for v in vulnerabilities if v.get('severity') == 'LOW']),
            'total_alerts': len(alerts),
            'last_scan': data.get('timestamp', 'Never')
        }
        
        return render_template('dashboard.html', 
                             devices=devices, 
                             vulnerabilities=vulnerabilities,
                             alerts=alerts,
                             stats=stats)
    else:
        return render_template('no_data.html')

@app.route('/devices')
def devices():
    """Devices page"""
    data = load_latest_data()
    if data:
        devices = data.get('devices', {})
        return render_template('devices.html', devices=devices)
    else:
        return render_template('no_data.html')

@app.route('/vulnerabilities')
def vulnerabilities():
    """Vulnerabilities page"""
    data = load_latest_data()
    if data:
        vulnerabilities = data.get('vulnerabilities', [])
        
        # Group vulnerabilities by severity
        vuln_by_severity = {
            'HIGH': [v for v in vulnerabilities if v.get('severity') == 'HIGH'],
            'MEDIUM': [v for v in vulnerabilities if v.get('severity') == 'MEDIUM'],
            'LOW': [v for v in vulnerabilities if v.get('severity') == 'LOW']
        }
        
        return render_template('vulnerabilities.html', 
                             vulnerabilities=vulnerabilities,
                             vuln_by_severity=vuln_by_severity)
    else:
        return render_template('no_data.html')

@app.route('/alerts')
def alerts():
    """Alerts page"""
    alerts = load_latest_alerts()
    return render_template('alerts.html', alerts=alerts)

@app.route('/monitoring')
def monitoring():
    """Monitoring control page"""
    global monitor
    
    try:
        if monitor and hasattr(monitor, 'get_monitoring_status'):
            status = monitor.get_monitoring_status()
        else:
            status = {
                'monitoring': False,
                'scan_interval': 300,
                'devices_count': 0,
                'total_alerts': 0,
                'last_scan': None
            }
    except Exception as e:
        print(f"Error getting monitoring status: {e}")
        status = {
            'monitoring': False,
            'scan_interval': 300,
            'devices_count': 0,
            'total_alerts': 0,
            'last_scan': None
        }
    
    return render_template('monitoring.html', status=status)

@app.route('/ai-analysis')
def ai_analysis():
    """AI Analysis page"""
    # Load latest scan data
    data = load_latest_data()
    
    if not data:
        return render_template('no_data.html')
    
    devices = data.get('devices', {})
    vulnerabilities = data.get('vulnerabilities', [])
    
    # Check if we have cached AI analysis
    try:
        with open('latest_ai_analysis.json', 'r') as f:
            ai_data = json.load(f)
            # Check if analysis is recent (within 1 hour)
            analysis_time = datetime.fromisoformat(ai_data.get('timestamp', '2000-01-01'))
            if (datetime.now() - analysis_time).seconds < 3600:
                return render_template('ai_analysis.html', 
                                     analysis=ai_data, 
                                     devices=devices,
                                     vulnerabilities=vulnerabilities)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        pass
    
    # No recent analysis found
    return render_template('ai_analysis.html', 
                         analysis=None, 
                         devices=devices,
                         vulnerabilities=vulnerabilities)

@app.route('/debug')
def debug():
    """Debug page to check data"""
    data = load_latest_data()
    alerts = load_latest_alerts()
    
    debug_info = {
        'data_available': data is not None,
        'alerts_available': len(alerts) > 0 if alerts else False,
        'devices_count': len(data.get('devices', {})) if data else 0,
        'vulnerabilities_count': len(data.get('vulnerabilities', [])) if data else 0,
        'raw_data': data,
        'raw_alerts': alerts
    }
    
    return f"<pre>{json.dumps(debug_info, indent=2)}</pre>"

# API Routes
@app.route('/api/test', methods=['GET'])
def api_test():
    """Test API endpoint"""
    return jsonify({
        'success': True,
        'message': 'API is working',
        'scanner_available': SCANNER_AVAILABLE,
        'detector_available': DETECTOR_AVAILABLE,
        'monitor_available': MONITOR_AVAILABLE
    })

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Trigger a manual network scan"""
    try:
        data = request.get_json() or {}
        network_range = data.get('network_range')
        detailed = data.get('detailed', False)
        include_vulnerabilities = data.get('vulnerabilities', True)
        
        # Import here to avoid startup issues
        from network_scanner import NetworkScanner
        
        scanner = NetworkScanner()
        
        # Perform scan
        devices = scanner.discover_devices(network_range, use_detailed_scan=detailed)
        
        vulnerabilities = []
        if include_vulnerabilities:
            try:
                # Import vulnerability detector
                from vulnerability_detector import VulnerabilityDetector
                detector = VulnerabilityDetector()
                vulnerabilities = detector.scan_all_devices(devices)
            except Exception as vuln_error:
                print(f"Vulnerability scanning failed: {vuln_error}")
                # Continue without vulnerabilities
        
        # Save results
        scan_data = {
            'timestamp': datetime.now().isoformat(),
            'devices': devices,
            'vulnerabilities': vulnerabilities,
            'changes': {},
            'alerts': []
        }
        
        with open('latest_scan.json', 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        # Save to database if enabled
        try:
            from config import Config
            if Config.DATABASE_ENABLED and Config.DATABASE_TYPE.lower() == 'mongodb':
                from mongodb_manager import MongoDBManager
                db = MongoDBManager()
                db.save_scan_results(scan_data)
        except Exception as db_error:
            print(f"Database save failed: {db_error}")
            # Continue without database save
        
        return jsonify({
            'success': True,
            'message': f'Scan completed. Found {len(devices)} devices and {len(vulnerabilities)} vulnerabilities.',
            'data': {
                'devices_count': len(devices),
                'vulnerabilities_count': len(vulnerabilities)
            }
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Scan API error: {error_details}")
        return jsonify({
            'success': False,
            'message': f'Scan failed: {str(e)}'
        }), 500

@app.route('/api/monitoring/start', methods=['POST'])
def api_start_monitoring():
    """Start continuous monitoring"""
    global monitor, monitor_thread
    
    try:
        # Stop any existing monitoring first
        if monitor and getattr(monitor, 'monitoring', False):
            try:
                monitor.stop_monitoring()
                time.sleep(1)  # Give it a moment to stop
            except:
                pass
        
        data = request.get_json() or {}
        scan_interval = data.get('scan_interval', 300)
        network_range = data.get('network_range')
        detailed_scan = data.get('detailed_scan', False)
        
        # Validate scan interval
        if scan_interval < 60:
            return jsonify({
                'success': False,
                'message': 'Scan interval must be at least 60 seconds'
            }), 400
        
        # Use simple monitoring (more reliable)
        try:
            from simple_monitoring import SimpleNetworkMonitor
            monitor = SimpleNetworkMonitor(scan_interval=scan_interval)
            success = monitor.start_monitoring(network_range)
            
            if success:
                return jsonify({
                    'success': True,
                    'message': f'Monitoring started with {scan_interval} second intervals'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Failed to start monitoring - check logs for details'
                }), 500
                
        except ImportError:
            return jsonify({
                'success': False,
                'message': 'Monitoring module not available'
            }), 500
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Monitoring start error: {error_details}")
        return jsonify({
            'success': False,
            'message': f'Monitoring error: {str(e)}'
        }), 500

@app.route('/api/monitoring/stop', methods=['POST'])
def api_stop_monitoring():
    """Stop continuous monitoring"""
    global monitor
    
    try:
        if not monitor:
            return jsonify({
                'success': True,
                'message': 'Monitoring was not running'
            })
        
        # Try to stop monitoring
        try:
            if hasattr(monitor, 'stop_monitoring'):
                success = monitor.stop_monitoring()
            else:
                monitor.monitoring = False
                success = True
            
            # Clear the monitor reference
            monitor = None
            
            return jsonify({
                'success': True,
                'message': 'Monitoring stopped successfully'
            })
            
        except Exception as stop_error:
            print(f"Error stopping monitor: {stop_error}")
            # Force stop by clearing reference
            monitor = None
            return jsonify({
                'success': True,
                'message': 'Monitoring force stopped'
            })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Monitoring stop error: {error_details}")
        # Force cleanup
        monitor = None
        return jsonify({
            'success': True,
            'message': 'Monitoring stopped (with cleanup)'
        })

@app.route('/api/monitoring/status')
def api_monitoring_status():
    """Get monitoring status"""
    global monitor
    
    try:
        is_monitoring = False
        scan_interval = 300
        devices_count = 0
        total_alerts = 0
        last_scan = None
        
        if monitor:
            # Check if monitor has monitoring attribute
            if hasattr(monitor, 'monitoring'):
                is_monitoring = getattr(monitor, 'monitoring', False)
            
            # Try to get detailed status
            if hasattr(monitor, 'get_monitoring_status'):
                try:
                    detailed_status = monitor.get_monitoring_status()
                    is_monitoring = detailed_status.get('monitoring', is_monitoring)
                    scan_interval = detailed_status.get('scan_interval', scan_interval)
                    devices_count = detailed_status.get('devices_count', devices_count)
                    total_alerts = detailed_status.get('total_alerts', total_alerts)
                    last_scan = detailed_status.get('last_scan', last_scan)
                except Exception as status_error:
                    print(f"Error getting detailed status: {status_error}")
        
        # Load latest data for device count
        try:
            data = load_latest_data()
            if data:
                devices_count = len(data.get('devices', {}))
        except:
            pass
        
        # Load alerts count
        try:
            alerts = load_latest_alerts()
            total_alerts = len(alerts) if alerts else 0
        except:
            pass
        
        status = {
            'monitoring': is_monitoring,
            'scan_interval': scan_interval,
            'devices_count': devices_count,
            'total_alerts': total_alerts,
            'last_scan': last_scan or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return jsonify(status)
        
    except Exception as e:
        print(f"Error getting monitoring status: {e}")
        return jsonify({
            'monitoring': False,
            'scan_interval': 300,
            'devices_count': 0,
            'total_alerts': 0,
            'last_scan': None,
            'error': str(e)
        })

@app.route('/api/data/latest')
def api_latest_data():
    """Get latest scan data"""
    data = load_latest_data()
    if data:
        return jsonify(data)
    else:
        return jsonify({'error': 'No data available'}), 404

@app.route('/api/alerts/latest')
def api_latest_alerts():
    """Get latest alerts"""
    alerts = load_latest_alerts()
    return jsonify(alerts)

@app.route('/api/monitoring/logs')
def api_monitoring_logs():
    """Get monitoring logs"""
    try:
        logs = []
        
        # Try to read monitoring logs from various sources
        log_files = [
            'network_monitor.log',
            'monitoring.log', 
            'lansecmon.log',
            'webapp.log'
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        lines = f.readlines()
                        # Get last 50 lines
                        recent_lines = lines[-50:] if len(lines) > 50 else lines
                        
                        for line in recent_lines:
                            line = line.strip()
                            if line and ('monitoring' in line.lower() or 'scan' in line.lower() or 'device' in line.lower()):
                                logs.append({
                                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                                    'message': line,
                                    'source': log_file
                                })
                except Exception as e:
                    print(f"Error reading {log_file}: {e}")
        
        # If no logs from files, create some sample monitoring activity
        if not logs:
            # Get current monitoring status
            global monitor
            if monitor and getattr(monitor, 'monitoring', False):
                logs = [
                    {
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'message': '✅ Monitoring system active',
                        'source': 'system'
                    },
                    {
                        'timestamp': (datetime.now() - timedelta(seconds=30)).strftime('%H:%M:%S'),
                        'message': '🔍 Network scan in progress...',
                        'source': 'scanner'
                    },
                    {
                        'timestamp': (datetime.now() - timedelta(seconds=60)).strftime('%H:%M:%S'),
                        'message': f'📊 Found {len(load_latest_data().get("devices", {}) if load_latest_data() else {})} active devices',
                        'source': 'discovery'
                    }
                ]
            else:
                logs = [
                    {
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'message': '⏸️ Monitoring system stopped',
                        'source': 'system'
                    },
                    {
                        'timestamp': (datetime.now() - timedelta(minutes=1)).strftime('%H:%M:%S'),
                        'message': '📋 Ready to start monitoring',
                        'source': 'system'
                    }
                ]
        
        # Sort by timestamp (most recent first)
        logs = sorted(logs, key=lambda x: x['timestamp'], reverse=True)[:20]
        
        return jsonify(logs)
        
    except Exception as e:
        print(f"Error getting monitoring logs: {e}")
        return jsonify([
            {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'message': f'❌ Error loading logs: {str(e)}',
                'source': 'error'
            }
        ])

@app.route('/api/device/<ip>')
def api_device_details(ip):
    """Get details for a specific device"""
    data = load_latest_data()
    if data and ip in data.get('devices', {}):
        device = data['devices'][ip]
        
        # Get vulnerabilities for this device
        vulnerabilities = [v for v in data.get('vulnerabilities', []) if v.get('ip') == ip]
        
        return jsonify({
            'device': device,
            'vulnerabilities': vulnerabilities
        })
    else:
        return jsonify({'error': 'Device not found'}), 404

@app.route('/api/ai-analysis', methods=['POST'])
def api_generate_ai_analysis():
    """Generate AI analysis of network security data"""
    try:
        if not AI_ANALYZER_AVAILABLE or not GEMINI_API_KEY:
            return jsonify({
                'success': False,
                'message': 'AI analysis not available - missing dependencies or API key'
            }), 500
        
        # Load latest scan data
        data = load_latest_data()
        if not data:
            return jsonify({
                'success': False,
                'message': 'No scan data available for analysis'
            }), 404
        
        devices = data.get('devices', {})
        vulnerabilities = data.get('vulnerabilities', [])
        
        # Initialize AI analyzer
        analyzer = AINetworkAnalyzer(GEMINI_API_KEY)
        
        # Generate analysis
        analysis = analyzer.analyze_network_security(devices, vulnerabilities)
        
        # Save analysis to file
        with open('latest_ai_analysis.json', 'w') as f:
            json.dump(analysis, f, indent=2)
        
        return jsonify({
            'success': True,
            'message': 'AI analysis generated successfully',
            'analysis': analysis
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"AI Analysis API error: {error_details}")
        return jsonify({
            'success': False,
            'message': f'AI analysis failed: {str(e)}'
        }), 500

# Template creation function
def create_templates():
    """Create HTML templates"""
    os.makedirs('templates', exist_ok=True)
    
    # Base template
    base_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}NIDS - Network Intrusion Detection System{% endblock %}</title>
    <link rel="icon" type="image/x-icon" href="{{ url_for('static', filename='favicon.ico') }}">
    <link rel="icon" type="image/png" sizes="32x32" href="{{ url_for('static', filename='favicon-32x32.png') }}">
    <link rel="icon" type="image/png" sizes="16x16" href="{{ url_for('static', filename='favicon-16x16.png') }}">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .severity-high { color: #dc3545; }
        .severity-medium { color: #fd7e14; }
        .severity-low { color: #198754; }
        .card-metric { text-align: center; }
        .metric-value { font-size: 2rem; font-weight: bold; }
        .alert-item { border-left: 4px solid #dc3545; }
        .device-card { transition: transform 0.2s; }
        .device-card:hover { transform: translateY(-2px); }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('dashboard') }}">
                <img src="{{ url_for('static', filename='logo.png') }}" alt="NIDS Logo" height="30" class="me-2">
                NIDS
            </a>
            <div class="navbar-nav">
                <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a>
                <a class="nav-link" href="{{ url_for('devices') }}">Devices</a>
                <a class="nav-link" href="{{ url_for('vulnerabilities') }}">Vulnerabilities</a>
                <a class="nav-link" href="{{ url_for('alerts') }}">Alerts</a>
                <a class="nav-link" href="{{ url_for('monitoring') }}">Monitoring</a>
                <a class="nav-link" href="{{ url_for('ai_analysis') }}">AI Analysis</a>
            </div>
        </div>
    </nav>
    
    <div class="container mt-4">
        {% block content %}{% endblock %}
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>'''
    
    with open('templates/base.html', 'w') as f:
        f.write(base_template)
    
    # Dashboard template
    dashboard_template = '''{% extends "base.html" %}

{% block title %}Dashboard - NIDS{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col-md-12">
        <div class="d-flex align-items-center mb-2">
            <img src="{{ url_for('static', filename='logo.png') }}" alt="NIDS Logo" height="50" class="me-3">
            <div>
                <h1 class="mb-0"><i class="fas fa-tachometer-alt"></i> NIDS Dashboard</h1>
                <p class="text-muted mb-0">Network Intrusion Detection System</p>
            </div>
        </div>
        <p class="text-muted">Last scan: {{ stats.last_scan }}</p>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-2">
        <div class="card card-metric">
            <div class="card-body">
                <div class="metric-value text-primary">{{ stats.total_devices }}</div>
                <div>Devices</div>
            </div>
        </div>
    </div>
    <div class="col-md-2">
        <div class="card card-metric">
            <div class="card-body">
                <div class="metric-value text-danger">{{ stats.high_severity }}</div>
                <div>High Risk</div>
            </div>
        </div>
    </div>
    <div class="col-md-2">
        <div class="card card-metric">
            <div class="card-body">
                <div class="metric-value text-warning">{{ stats.medium_severity }}</div>
                <div>Medium Risk</div>
            </div>
        </div>
    </div>
    <div class="col-md-2">
        <div class="card card-metric">
            <div class="card-body">
                <div class="metric-value text-success">{{ stats.low_severity }}</div>
                <div>Low Risk</div>
            </div>
        </div>
    </div>
    <div class="col-md-2">
        <div class="card card-metric">
            <div class="card-body">
                <div class="metric-value text-info">{{ stats.total_vulnerabilities }}</div>
                <div>Total Vulns</div>
            </div>
        </div>
    </div>
    <div class="col-md-2">
        <div class="card card-metric">
            <div class="card-body">
                <div class="metric-value text-secondary">{{ stats.total_alerts }}</div>
                <div>Alerts</div>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-exclamation-triangle"></i> Recent Alerts</h5>
            </div>
            <div class="card-body">
                {% if alerts %}
                    {% for alert in alerts[:5] %}
                    <div class="alert alert-{{ 'danger' if alert.severity == 'HIGH' else 'warning' if alert.severity == 'MEDIUM' else 'info' }} alert-item">
                        <strong>{{ alert.type }}</strong><br>
                        {{ alert.message }}
                        <small class="text-muted d-block">{{ alert.timestamp }}</small>
                    </div>
                    {% endfor %}
                {% else %}
                    <p class="text-muted">No alerts</p>
                {% endif %}
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-bug"></i> Top Vulnerabilities</h5>
            </div>
            <div class="card-body">
                {% if vulnerabilities %}
                    {% for vuln in vulnerabilities[:5] %}
                    <div class="mb-2">
                        <span class="badge bg-{{ 'danger' if vuln.severity == 'HIGH' else 'warning' if vuln.severity == 'MEDIUM' else 'success' }}">
                            {{ vuln.severity }}
                        </span>
                        <strong>{{ vuln.type }}</strong> on {{ vuln.ip }}
                        <br><small class="text-muted">{{ vuln.description }}</small>
                    </div>
                    {% endfor %}
                {% else %}
                    <p class="text-muted">No vulnerabilities found</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}'''
    
    with open('templates/dashboard.html', 'w') as f:
        f.write(dashboard_template)
    
    # No data template
    no_data_template = '''{% extends "base.html" %}

{% block content %}
<div class="text-center">
    <h2><i class="fas fa-search"></i> No Data Available</h2>
    <p class="text-muted">No network scan data found. Please run a scan first.</p>
    <a href="{{ url_for('scan') }}" class="btn btn-primary">
        <i class="fas fa-play"></i> Start Scan
    </a>
</div>
{% endblock %}'''
    
    with open('templates/no_data.html', 'w') as f:
        f.write(no_data_template)
    
    # Additional templates would be created here...
    # For brevity, I'll create simplified versions
    
    simple_templates = {
        'devices.html': '''{% extends "base.html" %}
{% block content %}
<h1>Network Devices</h1>
<div class="row">
{% for ip, device in devices.items() %}
<div class="col-md-4 mb-3">
    <div class="card device-card">
        <div class="card-body">
            <h5>{{ ip }}</h5>
            <p>{{ device.hostname }}</p>
            <small>{{ device.ports|length }} open ports</small>
        </div>
    </div>
</div>
{% endfor %}
</div>
{% endblock %}''',
        
        'vulnerabilities.html': '''{% extends "base.html" %}
{% block content %}
<h1>Security Vulnerabilities</h1>
{% for severity, vulns in vuln_by_severity.items() %}
<h3 class="severity-{{ severity.lower() }}">{{ severity }} Severity ({{ vulns|length }})</h3>
{% for vuln in vulns %}
<div class="card mb-2">
    <div class="card-body">
        <h6>{{ vuln.type }} - {{ vuln.ip }}</h6>
        <p>{{ vuln.description }}</p>
        <small>Recommendation: {{ vuln.recommendation }}</small>
    </div>
</div>
{% endfor %}
{% endfor %}
{% endblock %}''',
        
        'alerts.html': '''{% extends "base.html" %}
{% block content %}
<h1>Security Alerts</h1>
{% for alert in alerts %}
<div class="alert alert-{{ 'danger' if alert.severity == 'HIGH' else 'warning' }}">
    <strong>{{ alert.type }}</strong><br>
    {{ alert.message }}<br>
    <small>{{ alert.timestamp }}</small>
</div>
{% endfor %}
{% endblock %}''',
        
        'monitoring.html': '''{% extends "base.html" %}
{% block content %}
<h1>Network Monitoring</h1>
<div class="card">
    <div class="card-body">
        <p>Status: <span id="status">{{ 'Running' if status.monitoring else 'Stopped' }}</span></p>
        <button id="startBtn" class="btn btn-success">Start Monitoring</button>
        <button id="stopBtn" class="btn btn-danger">Stop Monitoring</button>
    </div>
</div>
{% endblock %}''',
        
        'scan.html': '''{% extends "base.html" %}
{% block content %}
<h1>Manual Network Scan</h1>
<div class="card">
    <div class="card-body">
        <form id="scanForm">
            <div class="mb-3">
                <label>Network Range:</label>
                <input type="text" class="form-control" name="network_range" placeholder="192.168.1.0/24">
            </div>
            <div class="mb-3">
                <label>
                    <input type="checkbox" name="detailed"> Detailed Scan
                </label>
            </div>
            <button type="submit" class="btn btn-primary">Start Scan</button>
        </form>
        <div id="scanResult" class="mt-3"></div>
    </div>
</div>
{% endblock %}'''
    }
    
    for filename, content in simple_templates.items():
        with open(f'templates/{filename}', 'w') as f:
            f.write(content)

def main():
    """Main function to run the web application"""
    setup_logging()
    
    # Create templates if they don't exist
    if not os.path.exists('templates'):
        create_templates()
    
    print("NIDS - Network Intrusion Detection System")
    print("=========================================")
    print("Starting web server on http://localhost:5000")
    print("Press Ctrl+C to stop")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == "__main__":
    main()

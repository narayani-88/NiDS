#!/usr/bin/env python3
"""
LAN Security Monitor - Configuration Module
Central configuration for the application.
"""

import os
from datetime import timedelta

# Load environment variables from .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed, use system environment variables
    pass

class Config:
    """Main configuration class"""
    
    # Application settings
    APP_NAME = "LAN Security Monitor"
    VERSION = "1.0.0"
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Network scanning settings
    DEFAULT_SCAN_INTERVAL = 300  # 5 minutes
    MAX_SCAN_THREADS = 50
    PING_TIMEOUT = 2  # seconds
    PORT_SCAN_TIMEOUT = 1  # seconds
    
    # Default ports to scan (common services)
    COMMON_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        135,   # RPC
        139,   # NetBIOS
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        993,   # IMAPS
        995,   # POP3S
        1433,  # MSSQL
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        6379,  # Redis
        8080,  # HTTP-Alt
        8443,  # HTTPS-Alt
        27017  # MongoDB
    ]
    
    # Vulnerability detection settings
    VULNERABILITY_SCAN_ENABLED = True
    CHECK_WEAK_PASSWORDS = True
    CHECK_SSL_VULNERABILITIES = True
    CHECK_WEB_VULNERABILITIES = True
    
    # Common weak passwords to test
    WEAK_PASSWORDS = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('admin', 'admin123'),
        ('root', 'root'),
        ('root', 'password'),
        ('root', 'toor'),
        ('root', '123456'),
        ('user', 'user'),
        ('user', 'password'),
        ('guest', 'guest'),
        ('test', 'test'),
        ('administrator', 'administrator'),
        ('administrator', 'password'),
        ('sa', ''),
        ('sa', 'sa'),
        ('postgres', 'postgres'),
        ('mysql', 'mysql'),
        ('oracle', 'oracle'),
        ('ftp', 'ftp'),
        ('anonymous', ''),
        ('demo', 'demo')
    ]
    
    # Risky ports and services
    RISKY_PORTS = {
        21: {'service': 'FTP', 'risk': 'HIGH', 'reason': 'Unencrypted file transfer'},
        23: {'service': 'Telnet', 'risk': 'HIGH', 'reason': 'Unencrypted remote access'},
        25: {'service': 'SMTP', 'risk': 'MEDIUM', 'reason': 'Potential mail relay'},
        53: {'service': 'DNS', 'risk': 'MEDIUM', 'reason': 'DNS amplification attacks'},
        135: {'service': 'RPC', 'risk': 'HIGH', 'reason': 'Windows RPC vulnerabilities'},
        139: {'service': 'NetBIOS', 'risk': 'HIGH', 'reason': 'SMB vulnerabilities'},
        445: {'service': 'SMB', 'risk': 'HIGH', 'reason': 'SMB vulnerabilities (WannaCry, etc.)'},
        1433: {'service': 'MSSQL', 'risk': 'MEDIUM', 'reason': 'Database exposure'},
        3306: {'service': 'MySQL', 'risk': 'MEDIUM', 'reason': 'Database exposure'},
        3389: {'service': 'RDP', 'risk': 'HIGH', 'reason': 'Remote desktop vulnerabilities'},
        5432: {'service': 'PostgreSQL', 'risk': 'MEDIUM', 'reason': 'Database exposure'},
        6379: {'service': 'Redis', 'risk': 'HIGH', 'reason': 'Often misconfigured without auth'},
        27017: {'service': 'MongoDB', 'risk': 'HIGH', 'reason': 'Often exposed without auth'}
    }
    
    # Monitoring settings
    MONITORING_ENABLED = True
    ALERT_THRESHOLD = 5  # Number of vulnerabilities to trigger alert
    REAL_TIME_ALERTS = True
    
    # Alert settings
    EMAIL_ALERTS_ENABLED = False
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'True').lower() == 'true'
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    FROM_EMAIL = os.environ.get('FROM_EMAIL', '')
    TO_EMAIL = os.environ.get('TO_EMAIL', '')
    
    # Web interface settings
    WEB_HOST = '0.0.0.0'
    WEB_PORT = 5000
    SECRET_KEY = os.environ.get('SECRET_KEY', 'lansecmon_secret_key_change_in_production')
    
    # File paths
    SCAN_RESULTS_FILE = 'network_scan_results.json'
    VULNERABILITY_REPORT_FILE = 'vulnerability_report.json'
    LATEST_SCAN_FILE = 'latest_scan.json'
    LATEST_ALERTS_FILE = 'latest_alerts.json'
    
    # Logging settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = 'lansecmon.log'
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # Database settings
    DATABASE_TYPE = os.environ.get('DATABASE_TYPE', 'mongodb')  # 'sqlite' or 'mongodb'
    DATABASE_ENABLED = True  # Set to False to disable database storage
    
    # SQLite settings
    SQLITE_DATABASE_URL = os.environ.get('SQLITE_DATABASE_URL', 'sqlite:///lansecmon.db')
    SQLITE_DATABASE_FILE = 'lansecmon.db'
    
    # MongoDB Atlas settings
    MONGODB_CONNECTION_STRING = os.environ.get('MONGODB_CONNECTION_STRING', 'mongodb+srv://<username>:<password>@<cluster>.mongodb.net/')
    MONGODB_DATABASE_NAME = os.environ.get('MONGODB_DATABASE_NAME', 'lansecmon')
    MONGODB_COLLECTION_PREFIX = os.environ.get('MONGODB_COLLECTION_PREFIX', 'lansecmon_')
    MONGODB_USERNAME = os.environ.get('MONGODB_USERNAME', '')
    MONGODB_PASSWORD = os.environ.get('MONGODB_PASSWORD', '')
    MONGODB_CLUSTER_NAME = os.environ.get('MONGODB_CLUSTER_NAME', '')
    MONGODB_SSL = True  # Atlas always uses SSL
    MONGODB_AUTH_SOURCE = 'admin'  # Atlas uses admin as auth source
    
    # Security settings
    RATE_LIMITING_ENABLED = True
    MAX_REQUESTS_PER_MINUTE = 60
    
    # Advanced scanning options
    NMAP_ENABLED = True
    NMAP_ARGUMENTS = '-sV -sS'  # Service version detection, SYN scan
    OS_DETECTION = False  # Requires root privileges
    
    # Network discovery settings
    AUTO_DETECT_NETWORK = True
    DEFAULT_NETWORK_RANGE = '192.168.1.0/24'
    EXCLUDE_NETWORKS = []  # Networks to exclude from scanning
    
    # Performance settings
    MAX_CONCURRENT_SCANS = 10
    SCAN_TIMEOUT = 300  # 5 minutes
    PORT_SCAN_DELAY = 0  # Delay between port scans (seconds)
    
    @classmethod
    def get_smtp_config(cls):
        """Get SMTP configuration for email alerts"""
        if not cls.EMAIL_ALERTS_ENABLED:
            return None
            
        return {
            'smtp_server': cls.SMTP_SERVER,
            'smtp_port': cls.SMTP_PORT,
            'use_tls': cls.SMTP_USE_TLS,
            'username': cls.SMTP_USERNAME,
            'password': cls.SMTP_PASSWORD,
            'from_email': cls.FROM_EMAIL,
            'to_email': cls.TO_EMAIL
        }
    
    @classmethod
    def validate_config(cls):
        """Validate configuration settings"""
        errors = []
        
        if cls.EMAIL_ALERTS_ENABLED:
            if not cls.SMTP_SERVER:
                errors.append("SMTP_SERVER is required when email alerts are enabled")
            if not cls.FROM_EMAIL:
                errors.append("FROM_EMAIL is required when email alerts are enabled")
            if not cls.TO_EMAIL:
                errors.append("TO_EMAIL is required when email alerts are enabled")
        
        if cls.DEFAULT_SCAN_INTERVAL < 60:
            errors.append("DEFAULT_SCAN_INTERVAL should be at least 60 seconds")
        
        if cls.MAX_SCAN_THREADS > 100:
            errors.append("MAX_SCAN_THREADS should not exceed 100")
        
        return errors

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    LOG_LEVEL = 'WARNING'
    EMAIL_ALERTS_ENABLED = True

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    DATABASE_URL = 'sqlite:///:memory:'
    EMAIL_ALERTS_ENABLED = False

# Configuration selector
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config(config_name=None):
    """Get configuration based on environment"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')
    
    return config.get(config_name, config['default'])

# Export the default configuration
Config = get_config()

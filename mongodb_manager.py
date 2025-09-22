#!/usr/bin/env python3
"""
LAN Security Monitor - MongoDB Database Manager
MongoDB database manager for storing scan history and results.
"""

import logging
from datetime import datetime, timedelta
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import json
from bson import ObjectId
from config import Config

class MongoDBManager:
    def __init__(self, connection_string=None, database_name=None):
        self.connection_string = connection_string or Config.MONGODB_CONNECTION_STRING
        self.database_name = database_name or Config.MONGODB_DATABASE_NAME
        self.collection_prefix = Config.MONGODB_COLLECTION_PREFIX
        self.client = None
        self.db = None
        self.setup_logging()
        self.connect()
        
    def setup_logging(self):
        """Setup logging configuration"""
        self.logger = logging.getLogger(__name__)
    
    def connect(self):
        """Connect to MongoDB Atlas"""
        try:
            # Build MongoDB Atlas connection string
            if Config.MONGODB_USERNAME and Config.MONGODB_PASSWORD and Config.MONGODB_CLUSTER_NAME:
                # Build Atlas connection string
                self.connection_string = f"mongodb+srv://{Config.MONGODB_USERNAME}:{Config.MONGODB_PASSWORD}@{Config.MONGODB_CLUSTER_NAME}.mongodb.net/{self.database_name}?retryWrites=true&w=majority"
            elif "mongodb+srv://" in self.connection_string:
                # Use provided Atlas connection string
                if Config.MONGODB_USERNAME and Config.MONGODB_PASSWORD:
                    # Replace placeholders in connection string
                    self.connection_string = self.connection_string.replace('<username>', Config.MONGODB_USERNAME)
                    self.connection_string = self.connection_string.replace('<password>', Config.MONGODB_PASSWORD)
                    if Config.MONGODB_CLUSTER_NAME:
                        self.connection_string = self.connection_string.replace('<cluster>', Config.MONGODB_CLUSTER_NAME)
            
            # MongoDB Atlas connection parameters
            connection_params = {
                'serverSelectionTimeoutMS': 10000,  # 10 second timeout for Atlas
                'connectTimeoutMS': 10000,
                'socketTimeoutMS': 10000,
                'retryWrites': True,
                'w': 'majority'
            }
            
            self.client = MongoClient(self.connection_string, **connection_params)
            
            # Test connection with Atlas
            self.client.admin.command('ping')
            self.db = self.client[self.database_name]
            
            self.logger.info(f"Connected to MongoDB Atlas database: {self.database_name}")
            self.create_indexes()
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            self.logger.error(f"Failed to connect to MongoDB Atlas: {e}")
            self.logger.error("Please check your Atlas connection string, username, password, and network access")
            raise
        except Exception as e:
            self.logger.error(f"MongoDB Atlas connection error: {e}")
            raise
    
    def create_indexes(self):
        """Create database indexes for better performance"""
        try:
            # Scans collection indexes
            scans_collection = self.db[f"{self.collection_prefix}scans"]
            scans_collection.create_index([("timestamp", DESCENDING)])
            scans_collection.create_index([("network_range", ASCENDING)])
            scans_collection.create_index([("scan_type", ASCENDING)])
            
            # Devices collection indexes
            devices_collection = self.db[f"{self.collection_prefix}devices"]
            devices_collection.create_index([("ip_address", ASCENDING)])
            devices_collection.create_index([("scan_id", ASCENDING)])
            devices_collection.create_index([("last_seen", DESCENDING)])
            devices_collection.create_index([("hostname", ASCENDING)])
            
            # Vulnerabilities collection indexes
            vulnerabilities_collection = self.db[f"{self.collection_prefix}vulnerabilities"]
            vulnerabilities_collection.create_index([("scan_id", ASCENDING)])
            vulnerabilities_collection.create_index([("device_ip", ASCENDING)])
            vulnerabilities_collection.create_index([("severity", ASCENDING)])
            vulnerabilities_collection.create_index([("vuln_type", ASCENDING)])
            vulnerabilities_collection.create_index([("first_detected", DESCENDING)])
            
            # Alerts collection indexes
            alerts_collection = self.db[f"{self.collection_prefix}alerts"]
            alerts_collection.create_index([("timestamp", DESCENDING)])
            alerts_collection.create_index([("alert_type", ASCENDING)])
            alerts_collection.create_index([("severity", ASCENDING)])
            alerts_collection.create_index([("resolved", ASCENDING)])
            alerts_collection.create_index([("device_ip", ASCENDING)])
            
            # Monitoring sessions collection indexes
            monitoring_collection = self.db[f"{self.collection_prefix}monitoring_sessions"]
            monitoring_collection.create_index([("start_time", DESCENDING)])
            monitoring_collection.create_index([("status", ASCENDING)])
            
            self.logger.info("MongoDB indexes created successfully")
            
        except Exception as e:
            self.logger.error(f"Error creating MongoDB indexes: {e}")
    
    def save_scan_results(self, scan_data):
        """Save complete scan results to MongoDB"""
        try:
            # Insert scan record
            scan_doc = {
                "timestamp": scan_data.get('timestamp', datetime.now().isoformat()),
                "network_range": scan_data.get('network_range', 'auto-detected'),
                "scan_type": scan_data.get('scan_type', 'quick'),
                "devices_count": len(scan_data.get('devices', {})),
                "vulnerabilities_count": len(scan_data.get('vulnerabilities', [])),
                "scan_duration": scan_data.get('scan_duration', 0),
                "status": "completed",
                "created_at": datetime.utcnow()
            }
            
            scans_collection = self.db[f"{self.collection_prefix}scans"]
            scan_result = scans_collection.insert_one(scan_doc)
            scan_id = scan_result.inserted_id
            
            # Save devices
            devices = scan_data.get('devices', {})
            devices_collection = self.db[f"{self.collection_prefix}devices"]
            device_docs = []
            device_ids = {}
            
            for ip, device_info in devices.items():
                device_doc = {
                    "scan_id": scan_id,
                    "ip_address": ip,
                    "hostname": device_info.get('hostname', 'Unknown'),
                    "os_info": device_info.get('os', 'Unknown'),
                    "mac_address": device_info.get('mac_address', ''),
                    "ports": device_info.get('ports', []),
                    "first_seen": device_info.get('scan_time', datetime.now().isoformat()),
                    "last_seen": device_info.get('scan_time', datetime.now().isoformat()),
                    "status": "active",
                    "created_at": datetime.utcnow()
                }
                device_docs.append(device_doc)
            
            if device_docs:
                device_results = devices_collection.insert_many(device_docs)
                # Map IP addresses to MongoDB ObjectIds
                for i, ip in enumerate(devices.keys()):
                    device_ids[ip] = device_results.inserted_ids[i]
            
            # Save vulnerabilities
            vulnerabilities = scan_data.get('vulnerabilities', [])
            if vulnerabilities:
                vulnerabilities_collection = self.db[f"{self.collection_prefix}vulnerabilities"]
                vuln_docs = []
                
                for vuln in vulnerabilities:
                    device_id = device_ids.get(vuln.get('ip'))
                    vuln_doc = {
                        "scan_id": scan_id,
                        "device_id": device_id,
                        "device_ip": vuln.get('ip'),
                        "vuln_type": vuln.get('type'),
                        "severity": vuln.get('severity'),
                        "description": vuln.get('description'),
                        "recommendation": vuln.get('recommendation'),
                        "port_number": vuln.get('port'),
                        "service_name": vuln.get('service', ''),
                        "first_detected": vuln.get('scan_time', datetime.now().isoformat()),
                        "last_detected": vuln.get('scan_time', datetime.now().isoformat()),
                        "status": "open",
                        "created_at": datetime.utcnow()
                    }
                    vuln_docs.append(vuln_doc)
                
                vulnerabilities_collection.insert_many(vuln_docs)
            
            self.logger.info(f"Scan results saved to MongoDB with ID: {scan_id}")
            return str(scan_id)
            
        except Exception as e:
            self.logger.error(f"Error saving scan results to MongoDB: {e}")
            raise
    
    def save_alerts(self, alerts):
        """Save alerts to MongoDB"""
        try:
            if not alerts:
                return
                
            alerts_collection = self.db[f"{self.collection_prefix}alerts"]
            alert_docs = []
            
            for alert in alerts:
                alert_doc = {
                    "timestamp": alert.get('timestamp', datetime.now().isoformat()),
                    "alert_type": alert.get('type'),
                    "severity": alert.get('severity'),
                    "message": alert.get('message'),
                    "device_ip": alert.get('details', {}).get('ip', ''),
                    "details": alert.get('details', {}),
                    "acknowledged": False,
                    "resolved": False,
                    "created_at": datetime.utcnow()
                }
                alert_docs.append(alert_doc)
            
            alerts_collection.insert_many(alert_docs)
            self.logger.info(f"Saved {len(alerts)} alerts to MongoDB")
            
        except Exception as e:
            self.logger.error(f"Error saving alerts to MongoDB: {e}")
            raise
    
    def get_scan_history(self, limit=50):
        """Get scan history from MongoDB"""
        try:
            scans_collection = self.db[f"{self.collection_prefix}scans"]
            cursor = scans_collection.find().sort("timestamp", DESCENDING).limit(limit)
            
            scans = []
            for scan in cursor:
                scan['_id'] = str(scan['_id'])  # Convert ObjectId to string
                scans.append(scan)
            
            return scans
            
        except Exception as e:
            self.logger.error(f"Error getting scan history from MongoDB: {e}")
            return []
    
    def get_device_history(self, ip_address):
        """Get history for a specific device from MongoDB"""
        try:
            devices_collection = self.db[f"{self.collection_prefix}devices"]
            scans_collection = self.db[f"{self.collection_prefix}scans"]
            
            # Aggregate devices with scan information
            pipeline = [
                {"$match": {"ip_address": ip_address}},
                {"$lookup": {
                    "from": f"{self.collection_prefix}scans",
                    "localField": "scan_id",
                    "foreignField": "_id",
                    "as": "scan_info"
                }},
                {"$unwind": "$scan_info"},
                {"$sort": {"scan_info.timestamp": -1}}
            ]
            
            cursor = devices_collection.aggregate(pipeline)
            
            devices = []
            for device in cursor:
                device['_id'] = str(device['_id'])
                device['scan_id'] = str(device['scan_id'])
                device['scan_info']['_id'] = str(device['scan_info']['_id'])
                devices.append(device)
            
            return devices
            
        except Exception as e:
            self.logger.error(f"Error getting device history from MongoDB: {e}")
            return []
    
    def get_vulnerability_trends(self, days=30):
        """Get vulnerability trends over time from MongoDB"""
        try:
            vulnerabilities_collection = self.db[f"{self.collection_prefix}vulnerabilities"]
            
            # Calculate date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Aggregation pipeline for vulnerability trends
            pipeline = [
                {"$lookup": {
                    "from": f"{self.collection_prefix}scans",
                    "localField": "scan_id",
                    "foreignField": "_id",
                    "as": "scan_info"
                }},
                {"$unwind": "$scan_info"},
                {"$match": {
                    "scan_info.created_at": {
                        "$gte": start_date,
                        "$lte": end_date
                    }
                }},
                {"$group": {
                    "_id": {
                        "date": {"$dateToString": {
                            "format": "%Y-%m-%d",
                            "date": "$scan_info.created_at"
                        }}
                    },
                    "total_vulnerabilities": {"$sum": 1},
                    "high_severity": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "HIGH"]}, 1, 0]}
                    },
                    "medium_severity": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "MEDIUM"]}, 1, 0]}
                    },
                    "low_severity": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "LOW"]}, 1, 0]}
                    }
                }},
                {"$sort": {"_id.date": -1}}
            ]
            
            cursor = vulnerabilities_collection.aggregate(pipeline)
            
            trends = []
            for trend in cursor:
                trend_data = {
                    "date": trend["_id"]["date"],
                    "total_vulnerabilities": trend["total_vulnerabilities"],
                    "high_severity": trend["high_severity"],
                    "medium_severity": trend["medium_severity"],
                    "low_severity": trend["low_severity"]
                }
                trends.append(trend_data)
            
            return trends
            
        except Exception as e:
            self.logger.error(f"Error getting vulnerability trends from MongoDB: {e}")
            return []
    
    def get_active_alerts(self):
        """Get unresolved alerts from MongoDB"""
        try:
            alerts_collection = self.db[f"{self.collection_prefix}alerts"]
            cursor = alerts_collection.find({"resolved": False}).sort("timestamp", DESCENDING)
            
            alerts = []
            for alert in cursor:
                alert['_id'] = str(alert['_id'])
                alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Error getting active alerts from MongoDB: {e}")
            return []
    
    def acknowledge_alert(self, alert_id):
        """Mark alert as acknowledged in MongoDB"""
        try:
            alerts_collection = self.db[f"{self.collection_prefix}alerts"]
            result = alerts_collection.update_one(
                {"_id": ObjectId(alert_id)},
                {"$set": {"acknowledged": True, "updated_at": datetime.utcnow()}}
            )
            
            if result.modified_count > 0:
                self.logger.info(f"Alert {alert_id} acknowledged in MongoDB")
            else:
                self.logger.warning(f"Alert {alert_id} not found in MongoDB")
                
        except Exception as e:
            self.logger.error(f"Error acknowledging alert in MongoDB: {e}")
            raise
    
    def resolve_alert(self, alert_id):
        """Mark alert as resolved in MongoDB"""
        try:
            alerts_collection = self.db[f"{self.collection_prefix}alerts"]
            result = alerts_collection.update_one(
                {"_id": ObjectId(alert_id)},
                {"$set": {
                    "resolved": True,
                    "acknowledged": True,
                    "resolved_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }}
            )
            
            if result.modified_count > 0:
                self.logger.info(f"Alert {alert_id} resolved in MongoDB")
            else:
                self.logger.warning(f"Alert {alert_id} not found in MongoDB")
                
        except Exception as e:
            self.logger.error(f"Error resolving alert in MongoDB: {e}")
            raise
    
    def get_statistics(self):
        """Get overall statistics from MongoDB"""
        try:
            stats = {}
            
            # Total scans
            scans_collection = self.db[f"{self.collection_prefix}scans"]
            stats['total_scans'] = scans_collection.count_documents({})
            
            # Total unique devices
            devices_collection = self.db[f"{self.collection_prefix}devices"]
            stats['total_devices'] = len(devices_collection.distinct("ip_address"))
            
            # Total vulnerabilities
            vulnerabilities_collection = self.db[f"{self.collection_prefix}vulnerabilities"]
            stats['total_vulnerabilities'] = vulnerabilities_collection.count_documents({})
            
            # Vulnerabilities by severity
            severity_pipeline = [
                {"$group": {
                    "_id": "$severity",
                    "count": {"$sum": 1}
                }}
            ]
            severity_cursor = vulnerabilities_collection.aggregate(severity_pipeline)
            severity_counts = {item['_id']: item['count'] for item in severity_cursor}
            
            stats['high_severity'] = severity_counts.get('HIGH', 0)
            stats['medium_severity'] = severity_counts.get('MEDIUM', 0)
            stats['low_severity'] = severity_counts.get('LOW', 0)
            
            # Total alerts
            alerts_collection = self.db[f"{self.collection_prefix}alerts"]
            stats['total_alerts'] = alerts_collection.count_documents({})
            
            # Unresolved alerts
            stats['unresolved_alerts'] = alerts_collection.count_documents({"resolved": False})
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting statistics from MongoDB: {e}")
            return {}
    
    def cleanup_old_data(self, days=90):
        """Clean up old data beyond specified days from MongoDB"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Delete old scans and related data
            scans_collection = self.db[f"{self.collection_prefix}scans"]
            old_scans = scans_collection.find({"created_at": {"$lt": cutoff_date}})
            old_scan_ids = [scan['_id'] for scan in old_scans]
            
            if old_scan_ids:
                # Delete related devices and vulnerabilities
                devices_collection = self.db[f"{self.collection_prefix}devices"]
                devices_result = devices_collection.delete_many({"scan_id": {"$in": old_scan_ids}})
                
                vulnerabilities_collection = self.db[f"{self.collection_prefix}vulnerabilities"]
                vulns_result = vulnerabilities_collection.delete_many({"scan_id": {"$in": old_scan_ids}})
                
                # Delete old scans
                scans_result = scans_collection.delete_many({"_id": {"$in": old_scan_ids}})
                
                self.logger.info(f"Cleaned up {scans_result.deleted_count} old scans, "
                               f"{devices_result.deleted_count} devices, "
                               f"{vulns_result.deleted_count} vulnerabilities from MongoDB")
            
            # Delete old resolved alerts
            alerts_collection = self.db[f"{self.collection_prefix}alerts"]
            alerts_result = alerts_collection.delete_many({
                "created_at": {"$lt": cutoff_date},
                "resolved": True
            })
            
            self.logger.info(f"Cleaned up {alerts_result.deleted_count} old alerts from MongoDB")
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old data from MongoDB: {e}")
            raise
    
    def export_data(self, output_file='lansecmon_mongodb_export.json'):
        """Export all data from MongoDB to JSON file"""
        try:
            data = {
                'export_timestamp': datetime.now().isoformat(),
                'database_type': 'mongodb',
                'scans': self.get_scan_history(limit=1000),
                'statistics': self.get_statistics(),
                'active_alerts': self.get_active_alerts()
            }
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)  # default=str handles ObjectId serialization
            
            self.logger.info(f"MongoDB data exported to {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error exporting MongoDB data: {e}")
            raise
    
    def close_connection(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self.logger.info("MongoDB connection closed")

def main():
    """Test the MongoDB functionality"""
    print("Testing MongoDB Manager...")
    
    try:
        # Initialize MongoDB manager
        db = MongoDBManager()
        
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
        
        # Close connection
        db.close_connection()
        print("Test completed successfully!")
        
    except Exception as e:
        print(f"Test failed: {e}")
        print("Make sure MongoDB is running and accessible")

if __name__ == "__main__":
    main()

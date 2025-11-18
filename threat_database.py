"""
SQLite Database for Threat Intelligence Storage
"""
import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Optional

class ThreatDatabase:
    def __init__(self, db_path="threat_intelligence.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Threat IPs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                threat_level TEXT,
                threat_type TEXT,
                hostname TEXT,
                country TEXT,
                isp TEXT,
                status TEXT DEFAULT 'ACTIVE',
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Operations log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operations_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                ip_address TEXT,
                status TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                execution_time REAL,
                FOREIGN KEY (ip_address) REFERENCES threat_ips(ip_address)
            )
        ''')
        
        # Network scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ip_address) REFERENCES threat_ips(ip_address)
            )
        ''')
        
        # Related IPs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS related_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                primary_ip TEXT NOT NULL,
                related_ip TEXT NOT NULL,
                relationship_type TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (primary_ip) REFERENCES threat_ips(ip_address)
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT,
                ip_address TEXT,
                message TEXT,
                acknowledged BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ip_address) REFERENCES threat_ips(ip_address)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_address ON threat_ips(ip_address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_level ON threat_ips(threat_level)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_operation_timestamp ON operations_log(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON network_scans(scan_timestamp)')
        
        conn.commit()
        conn.close()
    
    def add_threat_ip(self, ip: str, threat_level: str = "MEDIUM", threat_type: str = "UNKNOWN", 
                     hostname: str = None, notes: str = None) -> bool:
        """Add or update a threat IP"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO threat_ips 
                (ip_address, threat_level, threat_type, hostname, notes, last_seen)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (ip, threat_level, threat_type, hostname, notes))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding threat IP: {e}")
            return False
        finally:
            conn.close()
    
    def get_threat_ip(self, ip: str) -> Optional[Dict]:
        """Get threat IP information"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM threat_ips WHERE ip_address = ?', (ip,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    def log_operation(self, operation_type: str, ip: str = None, status: str = "SUCCESS", 
                     details: str = "", execution_time: float = None):
        """Log an operation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO operations_log (operation_type, ip_address, status, details, execution_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (operation_type, ip, status, details, execution_time))
        
        conn.commit()
        conn.close()
    
    def add_network_scan(self, ip: str, scan_type: str, open_ports: List[int] = None, 
                        services: Dict = None, os_info: str = None):
        """Store network scan results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        ports_str = json.dumps(open_ports) if open_ports else None
        services_str = json.dumps(services) if services else None
        
        cursor.execute('''
            INSERT INTO network_scans (ip_address, scan_type, open_ports, services, os_info)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip, scan_type, ports_str, services_str, os_info))
        
        conn.commit()
        conn.close()
    
    def add_related_ip(self, primary_ip: str, related_ip: str, relationship_type: str = "SUBNET"):
        """Add a related IP"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR IGNORE INTO related_ips (primary_ip, related_ip, relationship_type)
            VALUES (?, ?, ?)
        ''', (primary_ip, related_ip, relationship_type))
        
        conn.commit()
        conn.close()
    
    def create_alert(self, alert_type: str, severity: str, ip: str = None, message: str = ""):
        """Create an alert"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (alert_type, severity, ip_address, message)
            VALUES (?, ?, ?, ?)
        ''', (alert_type, severity, ip, message))
        
        conn.commit()
        conn.close()
    
    def get_all_threats(self) -> List[Dict]:
        """Get all threat IPs"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM threat_ips ORDER BY last_seen DESC')
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_operations_stats(self) -> Dict:
        """Get operation statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM operations_log')
        total_ops = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM threat_ips')
        total_threats = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged = 0')
        unacknowledged_alerts = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT operation_type, COUNT(*) as count 
            FROM operations_log 
            GROUP BY operation_type
        ''')
        ops_by_type = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        return {
            "total_operations": total_ops,
            "total_threats": total_threats,
            "unacknowledged_alerts": unacknowledged_alerts,
            "operations_by_type": ops_by_type
        }
    
    def backup_database(self, backup_path: str = None):
        """Backup database"""
        if backup_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = f"backup_threat_intelligence_{timestamp}.db"
        
        import shutil
        shutil.copy2(self.db_path, backup_path)
        return backup_path


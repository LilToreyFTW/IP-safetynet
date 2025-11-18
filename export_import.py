"""
Export/Import Functionality for Data
"""
import json
import csv
import os
from datetime import datetime
from typing import List, Dict
from threat_database import ThreatDatabase

class ExportImport:
    def __init__(self, db: ThreatDatabase):
        self.db = db
    
    def export_to_json(self, output_file: str = None) -> str:
        """Export all data to JSON"""
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"export_threat_intelligence_{timestamp}.json"
        
        data = {
            "export_date": datetime.now().isoformat(),
            "threat_ips": self.db.get_all_threats(),
            "statistics": self.db.get_operations_stats()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False, default=str)
        
        return output_file
    
    def export_to_csv(self, output_file: str = None) -> str:
        """Export threat IPs to CSV"""
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"export_threats_{timestamp}.csv"
        
        threats = self.db.get_all_threats()
        
        if not threats:
            return None
        
        fieldnames = threats[0].keys()
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(threats)
        
        return output_file
    
    def export_operations_log(self, output_file: str = None) -> str:
        """Export operations log to CSV"""
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"export_operations_{timestamp}.csv"
        
        conn = self.db.db_path
        import sqlite3
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM operations_log ORDER BY timestamp DESC')
        operations = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        if not operations:
            return None
        
        fieldnames = operations[0].keys()
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(operations)
        
        return output_file
    
    def import_from_json(self, input_file: str) -> Dict:
        """Import data from JSON"""
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        imported = {
            "threats": 0,
            "errors": []
        }
        
        if "threat_ips" in data:
            for threat in data["threat_ips"]:
                try:
                    self.db.add_threat_ip(
                        threat.get("ip_address"),
                        threat.get("threat_level", "MEDIUM"),
                        threat.get("threat_type", "UNKNOWN"),
                        threat.get("hostname"),
                        threat.get("notes")
                    )
                    imported["threats"] += 1
                except Exception as e:
                    imported["errors"].append(f"Error importing {threat.get('ip_address')}: {e}")
        
        return imported


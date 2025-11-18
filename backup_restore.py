"""
Backup and Restore Functionality
"""
import os
import shutil
import zipfile
import json
from datetime import datetime
from typing import List, Dict
from threat_database import ThreatDatabase

class BackupRestore:
    def __init__(self, db: ThreatDatabase, logger=None):
        self.db = db
        self.logger = logger
        self.backup_dir = "backups"
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def create_backup(self, include_files=True) -> str:
        """Create complete backup"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"backup_{timestamp}"
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.zip")
        
        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Backup database
                if os.path.exists(self.db.db_path):
                    zipf.write(self.db.db_path, f"{backup_name}/database.db")
                
                # Backup config
                if os.path.exists("config.json"):
                    zipf.write("config.json", f"{backup_name}/config.json")
                
                # Backup logs
                if include_files and os.path.exists("Logs"):
                    for root, dirs, files in os.walk("Logs"):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.join(backup_name, "Logs", os.path.relpath(file_path, "Logs"))
                            zipf.write(file_path, arcname)
                
                # Backup caught IPs
                if include_files and os.path.exists("Caught"):
                    for root, dirs, files in os.walk("Caught"):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.join(backup_name, "Caught", os.path.relpath(file_path, "Caught"))
                            zipf.write(file_path, arcname)
                
                # Create backup manifest
                manifest = {
                    "backup_date": datetime.now().isoformat(),
                    "backup_name": backup_name,
                    "database": os.path.exists(self.db.db_path),
                    "includes_files": include_files
                }
                zipf.writestr(f"{backup_name}/manifest.json", json.dumps(manifest, indent=2))
            
            if self.logger:
                self.logger.info(f"Backup created: {backup_path}")
            
            return backup_path
        except Exception as e:
            if self.logger:
                self.logger.error(f"Backup failed: {e}")
            raise
    
    def restore_backup(self, backup_path: str) -> bool:
        """Restore from backup"""
        try:
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                # Extract manifest
                manifest_data = zipf.read([f for f in zipf.namelist() if f.endswith('manifest.json')][0])
                manifest = json.loads(manifest_data.decode('utf-8'))
                
                # Restore database
                db_files = [f for f in zipf.namelist() if f.endswith('database.db')]
                if db_files:
                    zipf.extract(db_files[0], ".")
                    # Rename if needed
                    extracted = db_files[0].split('/')[-1]
                    if extracted != os.path.basename(self.db.db_path):
                        shutil.move(extracted, self.db.db_path)
                
                # Restore config
                config_files = [f for f in zipf.namelist() if f.endswith('config.json')]
                if config_files:
                    zipf.extract(config_files[0], ".")
                
                # Restore other files
                for file_info in zipf.infolist():
                    if 'Logs' in file_info.filename or 'Caught' in file_info.filename:
                        zipf.extract(file_info, ".")
            
            if self.logger:
                self.logger.info(f"Backup restored from: {backup_path}")
            
            return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Restore failed: {e}")
            return False
    
    def list_backups(self) -> List[Dict]:
        """List all available backups"""
        backups = []
        if not os.path.exists(self.backup_dir):
            return backups
        
        for file in os.listdir(self.backup_dir):
            if file.endswith('.zip'):
                file_path = os.path.join(self.backup_dir, file)
                file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                file_size = os.path.getsize(file_path)
                
                backups.append({
                    "name": file,
                    "path": file_path,
                    "date": file_time.isoformat(),
                    "size": file_size
                })
        
        return sorted(backups, key=lambda x: x["date"], reverse=True)


"""
Configuration Manager for Application Settings
"""
import json
import os
from typing import Any, Dict

class ConfigManager:
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading config: {e}")
                return self.get_default_config()
        else:
            # Create default config file
            default_config = self.get_default_config()
            self.save_config(default_config)
            return default_config
    
    def save_config(self, config: Dict = None):
        """Save configuration to file"""
        if config is None:
            config = self.config
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'logging.level')"""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key_path.split('.')
        config = self.config
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value
        self.save_config()
    
    def get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            "application": {
                "name": "IP Operations Control Panel",
                "version": "2.0.0",
                "author": "Cybersecurity Operations",
                "default_window_size": {
                    "width": 1920,
                    "height": 1080
                }
            },
            "threat_intelligence": {
                "default_threat_ip": "185.196.8.92",
                "threat_ips": ["185.196.8.92"],
                "auto_block_threats": False,
                "threat_level_threshold": "HIGH"
            },
            "networking": {
                "timeout": 5,
                "max_retries": 3,
                "port_scan_timeout": 1,
                "traceroute_max_hops": 30,
                "enable_packet_capture": False
            },
            "logging": {
                "level": "INFO",
                "max_file_size_mb": 10,
                "backup_count": 5,
                "log_to_file": True,
                "log_to_console": True
            },
            "database": {
                "enabled": True,
                "path": "threat_intelligence.db",
                "backup_interval_hours": 24
            },
            "ui": {
                "theme": "dark",
                "font_size": 12,
                "auto_save": True,
                "show_tooltips": True
            },
            "security": {
                "require_confirmation": True,
                "encrypt_logs": False,
                "secure_delete": False
            },
            "monitoring": {
                "enabled": True,
                "check_interval_seconds": 60,
                "alert_on_threat": True
            }
        }


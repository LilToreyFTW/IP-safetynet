"""
Automated Threat Response System
"""
import threading
import time
from datetime import datetime
from threat_database import ThreatDatabase

class AutomatedResponse:
    def __init__(self, db: ThreatDatabase, logger=None, config=None):
        self.db = db
        self.logger = logger
        self.config = config or {}
        self.running = False
        self.response_thread = None
        self.response_rules = []
    
    def add_response_rule(self, condition, action, priority=1):
        """Add automated response rule"""
        self.response_rules.append({
            "condition": condition,
            "action": action,
            "priority": priority
        })
        self.response_rules.sort(key=lambda x: x["priority"], reverse=True)
    
    def start(self):
        """Start automated response system"""
        if self.running:
            return
        
        self.running = True
        self.response_thread = threading.Thread(target=self.response_loop, daemon=True)
        self.response_thread.start()
        
        if self.logger:
            self.logger.info("Automated response system started")
    
    def stop(self):
        """Stop automated response system"""
        self.running = False
        if self.logger:
            self.logger.info("Automated response system stopped")
    
    def response_loop(self):
        """Main response loop"""
        while self.running:
            try:
                # Check for new threats
                threats = self.db.get_all_threats()
                
                for threat in threats:
                    if threat.get("threat_level") == "CRITICAL":
                        # Execute response rules
                        for rule in self.response_rules:
                            if rule["condition"](threat):
                                rule["action"](threat)
                                break
                
                # Sleep before next check
                interval = self.config.get("monitoring", {}).get("check_interval_seconds", 60)
                time.sleep(interval)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Automated response error: {e}")
                time.sleep(10)


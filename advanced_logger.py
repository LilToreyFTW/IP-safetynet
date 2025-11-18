"""
Advanced Logging System with Rotation and Multiple Levels
"""
import logging
import logging.handlers
import os
from datetime import datetime
import json

class AdvancedLogger:
    def __init__(self, name="IPOperations", log_dir="Logs", config=None):
        self.name = name
        self.log_dir = log_dir
        self.config = config or {}
        
        # Create log directory
        os.makedirs(log_dir, exist_ok=True)
        
        # Setup logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self._get_log_level())
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            return
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        simple_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # File handler with rotation
        if self.config.get("logging", {}).get("log_to_file", True):
            max_bytes = self.config.get("logging", {}).get("max_file_size_mb", 10) * 1024 * 1024
            backup_count = self.config.get("logging", {}).get("backup_count", 5)
            
            file_handler = logging.handlers.RotatingFileHandler(
                os.path.join(log_dir, f"{name}.log"),
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(detailed_formatter)
            self.logger.addHandler(file_handler)
        
        # Console handler
        if self.config.get("logging", {}).get("log_to_console", True):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(simple_formatter)
            self.logger.addHandler(console_handler)
        
        # Error file handler
        error_handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, f"{name}_errors.log"),
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        self.logger.addHandler(error_handler)
    
    def _get_log_level(self):
        level_str = self.config.get("logging", {}).get("level", "INFO").upper()
        levels = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }
        return levels.get(level_str, logging.INFO)
    
    def debug(self, message, **kwargs):
        self.logger.debug(self._format_message(message, **kwargs))
    
    def info(self, message, **kwargs):
        self.logger.info(self._format_message(message, **kwargs))
    
    def warning(self, message, **kwargs):
        self.logger.warning(self._format_message(message, **kwargs))
    
    def error(self, message, **kwargs):
        self.logger.error(self._format_message(message, **kwargs))
    
    def critical(self, message, **kwargs):
        self.logger.critical(self._format_message(message, **kwargs))
    
    def _format_message(self, message, **kwargs):
        if kwargs:
            extra = " | " + " | ".join(f"{k}={v}" for k, v in kwargs.items())
            return f"{message}{extra}"
        return message
    
    def log_operation(self, operation, ip, details="", status="SUCCESS"):
        """Log an operation with structured data"""
        self.info(
            f"Operation: {operation} | IP: {ip} | Details: {details} | Status: {status}",
            operation=operation,
            ip=ip,
            details=details,
            status=status
        )
    
    def log_threat(self, ip, threat_type, severity, details=""):
        """Log threat intelligence"""
        self.warning(
            f"THREAT DETECTED | IP: {ip} | Type: {threat_type} | Severity: {severity} | Details: {details}",
            threat_ip=ip,
            threat_type=threat_type,
            severity=severity,
            details=details
        )


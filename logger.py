"""
Logging Module
Provides structured logging for the Network Anomaly Detector
"""

import logging
import logging.handlers
from pathlib import Path
from datetime import datetime
import config

class NetworkLogger:
    """
    Centralized logging system for network anomaly detection
    """
    
    def __init__(self, name='NetworkDetector'):
        """
        Initialize logger with file and console handlers
        
        Args:
            name: Logger name
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, config.LOGGING_CONFIG['level']))
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            return
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            config.LOGGING_CONFIG['file'],
            maxBytes=config.LOGGING_CONFIG['max_bytes'],
            backupCount=config.LOGGING_CONFIG['backup_count']
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(config.LOGGING_CONFIG['format'])
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def debug(self, message):
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message):
        """Log critical message"""
        self.logger.critical(message)
    
    def log_packet_capture(self, packet_count, interface):
        """Log packet capture event"""
        self.info(f"Captured packet #{packet_count} on interface {interface}")
    
    def log_flow_created(self, flow_key):
        """Log new flow creation"""
        self.debug(f"Created new flow: {flow_key}")
    
    def log_flow_expired(self, flow_key, duration):
        """Log flow expiration"""
        self.debug(f"Flow expired: {flow_key} (duration: {duration:.2f}s)")
    
    def log_anomaly_detected(self, flow_key, score, reason):
        """Log anomaly detection"""
        self.warning(f"ANOMALY DETECTED: {flow_key} | Score: {score:.3f} | Reason: {reason}")
    
    def log_attack_detected(self, attack_type, source_ip, details):
        """Log attack detection"""
        self.critical(f"ATTACK DETECTED: {attack_type} from {source_ip} | Details: {details}")
    
    def log_model_trained(self, sample_count, accuracy=None):
        """Log model training event"""
        msg = f"ML model trained on {sample_count} samples"
        if accuracy:
            msg += f" | Accuracy: {accuracy:.2f}%"
        self.info(msg)
    
    def log_database_operation(self, operation, table, count=None):
        """Log database operation"""
        msg = f"Database {operation}: {table}"
        if count:
            msg += f" ({count} records)"
        self.debug(msg)
    
    def log_system_event(self, event, details=""):
        """Log general system event"""
        self.info(f"System Event: {event} | {details}")

# Global logger instance
logger = NetworkLogger()

if __name__ == "__main__":
    # Test logging
    logger.info("Logger initialized successfully")
    logger.debug("This is a debug message")
    logger.warning("This is a warning")
    logger.error("This is an error")
    logger.log_anomaly_detected("192.168.1.1:80->10.0.0.5:443", -0.8, "Unusual packet size")
    logger.log_attack_detected("Port Scan", "192.168.1.100", "20 unique ports in 30s")
